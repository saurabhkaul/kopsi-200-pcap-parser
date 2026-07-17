use memchr::memmem;
use memmap2::{Advice, MmapOptions};
use std::{
    fs::File,
    io::{self, Write},
    mem,
    path::Path,
    sync::mpsc,
    thread,
};

// Packet layout constants:
// 16 bytes pcap per-packet record header
// 14 bytes Ethernet header
// 20 bytes IPv4 header
//  8 bytes UDP header
const HDR_TO_PAYLOAD: usize = 16 + 14 + 20 + 8;
const PAYLOAD_LEN: usize = 215;
const RECORD_DATA_LEN: u32 = (14 + 20 + 8 + PAYLOAD_LEN) as u32;

/// Each boundary between worker slices is extended by this many bytes so a
/// pattern straddling the split is still visible to the owning thread.
const OVERLAP: usize = 4; // len("B6034") - 1

/// Flush a chunk to the printer thread once it reaches this size.
const CHUNK_BYTES: usize = 16 * 1024;

pub const PCAP_FILE_PATH: &str = "fixtures/mdf-kospi200.20110216-0.pcap 2";

#[derive(Copy, Clone)]
pub enum PacketOrdering {
    Default,
    QuoteAcceptTime,
}

#[derive(Clone, Copy)]
struct QuoteAcceptIndex {
    accept_time_cs: u32,
    global_pos: u32,
    local_start: u32,
    local_len: u32,
}

#[derive(Clone, Copy)]
struct MergedQuoteAcceptIndex {
    accept_time_cs: u32,
    global_pos: u32,
    worker_id: usize,
    local_start: u32,
    local_len: u32,
}

#[inline]
fn accept_time_cs(data: &[u8]) -> u32 {
    let hh = aa(&data[206..208]);
    let mm = aa(&data[208..210]);
    let ss = aa(&data[210..212]);
    let cc = aa(&data[212..214]);
    hh * 360_000 + mm * 6_000 + ss * 100 + cc // centiseconds since midnight
}

/// Manually parse exactly two ASCII digits, used for HH, MM, SS, etc.
/// Assumes both bytes are valid digits in 0..9.
#[inline]
fn aa(b: &[u8]) -> u32 {
    (b[0] - b'0') as u32 * 10 + (b[1] - b'0') as u32
}

// Write a 2-digit number into the output buffer.
#[inline]
fn push_2d(out: &mut Vec<u8>, n: u64) {
    out.push(b'0' + (n / 10) as u8);
    out.push(b'0' + (n % 10) as u8);
}

// Write a 3-digit number into the output buffer.
#[inline]
fn push_3d(out: &mut Vec<u8>, n: u64) {
    out.push(b'0' + (n / 100 % 10) as u8);
    out.push(b'0' + (n / 10 % 10) as u8);
    out.push(b'0' + (n % 10) as u8);
}

/// Formats one B6034 quote line into `out` and returns the accept-time
/// in centiseconds-of-day (heap/sort key).
#[inline]
fn write_quote(out: &mut Vec<u8>, ts_sec: u32, ts_usec: u32, data: &[u8]) -> u32 {
    // Packet time.
    let secs = ts_sec as u64 + 9 * 3600;
    push_2d(out, (secs / 3600) % 24);
    out.push(b':');
    push_2d(out, (secs / 60) % 60);
    out.push(b':');
    push_2d(out, secs % 60);
    out.push(b'.');
    push_3d(out, ts_usec as u64 / 1000);
    out.push(b' ');

    // Quote accept time.
    out.extend_from_slice(&data[206..208]);
    out.push(b':');
    out.extend_from_slice(&data[208..210]);
    out.push(b':');
    out.extend_from_slice(&data[210..212]);
    out.push(b'.');
    out.extend_from_slice(&data[212..214]);
    out.push(b'0');
    out.push(b' ');

    // Issue code.
    let code_end = data[5..17]
        .iter()
        .rposition(|&b| b != b' ')
        .map_or(0, |i| i + 1);
    out.extend_from_slice(&data[5..5 + code_end]);

    // Bids.
    for i in (0..5usize).rev() {
        out.push(b' ');
        out.extend_from_slice(&data[34 + i * 12..41 + i * 12]);
        out.push(b'@');
        out.extend_from_slice(&data[29 + i * 12..34 + i * 12]);
    }

    // Asks.
    for i in 0..5usize {
        out.push(b' ');
        out.extend_from_slice(&data[101 + i * 12..108 + i * 12]);
        out.push(b'@');
        out.extend_from_slice(&data[96 + i * 12..101 + i * 12]);
    }
    out.push(b'\n');

    accept_time_cs(data)
}

/// Send `chunk` over `tx`, replacing it with a fresh pre-allocated buffer.
#[inline]
fn flush_chunk(tx: &mpsc::SyncSender<Vec<u8>>, chunk: &mut Vec<u8>) -> io::Result<()> {
    let full = mem::replace(chunk, Vec::with_capacity(CHUNK_BYTES + 256));
    tx.send(full)
        .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "printer thread exited"))
}

pub fn read_pcap_file<W: Write + Send + 'static>(
    path: impl AsRef<Path>,
    ordering: PacketOrdering,
    writer: W,
) -> io::Result<()> {
    let file = File::open(path)?;
    let mmap = unsafe { MmapOptions::new().populate().map(&file)? };
    let _ = mmap.advise(Advice::Sequential);

    if mmap.len() < 24 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "pcap too small"));
    }

    let le = match &mmap[0..4] {
        [0xd4, 0xc3, 0xb2, 0xa1] | [0x4d, 0x3c, 0xb2, 0xa1] => true,
        [0xa1, 0xb2, 0xc3, 0xd4] | [0xa1, 0xb2, 0x3c, 0x4d] => false,
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "not a pcap file",
            ))
        }
    };

    let file_len = mmap.len();

    // ── Core pinning ─────────────────────────────────────────────────────────
    // Main thread → core 0.  Printer thread → core 1.
    // Workers inside thread::scope share cores[0..] with the idle main thread.
    let cores = core_affinity::get_core_ids().unwrap_or_default();
    if let Some(&c) = cores.first() {
        core_affinity::set_for_current(c);
    }
    let printer_core = cores.get(1).copied();

    // ── Printer thread ───────────────────────────────────────────────────────
    // Bounded channel (cap 16): parser blocks if printer falls behind.
    let (tx, rx) = mpsc::sync_channel::<Vec<u8>>(16);

    let printer = thread::spawn(move || -> io::Result<()> {
        if let Some(c) = printer_core {
            core_affinity::set_for_current(c);
        }
        let mut w = writer;
        for chunk in rx {
            w.write_all(&chunk)?;
        }
        Ok(())
    });

    // ── Worker chunk descriptors ─────────────────────────────────────────────
    // Each worker owns [base, own_end) and scans [base, scan_end) where the
    // extra OVERLAP bytes allow patterns straddling the split to be found.
    // A match at global position gpos is claimed by the worker that owns it:
    //   gpos ∈ [base, own_end) (gpos = global byte position of a found B6034)
    // The next worker starts at own_end, so no match is double-counted.
    let nworkers = thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    let chunk_own = (file_len + nworkers - 1) / nworkers; // ceil(file_len / nworkers): bytes owned per worker
    let cap_per_work = (16_004 * 180 / nworkers).max(1024); // ~16k rows * ~180 bytes, split per worker

    match ordering {
        //Print packets on packet time
        PacketOrdering::Default => {
            let results: Vec<Vec<u8>> = thread::scope(|s| {
                let mmap = &mmap;
                let handles: Vec<_> = (0..nworkers)
                    .map(|i| {
                        s.spawn(move || {
                            let base = i * chunk_own;
                            if base >= file_len {
                                return Vec::new();
                            }
                            let own_end = (base + chunk_own).min(file_len);
                            let scan_end = (own_end + OVERLAP).min(file_len);

                            let u32_at = |j: usize| -> u32 {
                                let b: [u8; 4] = mmap[j..j + 4].try_into().unwrap();
                                if le {
                                    u32::from_le_bytes(b)
                                } else {
                                    u32::from_be_bytes(b)
                                }
                            };

                            let finder = memmem::Finder::new(b"B6034");
                            let mut buf = Vec::with_capacity(cap_per_work);

                            for local_pos in finder.find_iter(&mmap[base..scan_end]) {
                                let gpos = base + local_pos;
                                if gpos >= own_end {
                                    break;
                                }

                                //The worker scans slightly past its owned range because of overlap,
                                // but it only owns matches before `own_end`.
                                // If the match is beyond that, stop.
                                if gpos < HDR_TO_PAYLOAD {
                                    continue;
                                }
                                //Avoid underflow.
                                //To validate the pcap record, we later subtract `HDR_TO_PAYLOAD`,
                                //so this match must be far enough into the file
                                let rec = gpos - HDR_TO_PAYLOAD;

                                //Compute the start offset of the pcap packet record.
                                if u32_at(rec + 8) != RECORD_DATA_LEN {
                                    continue;
                                }
                                if gpos + PAYLOAD_LEN > file_len {
                                    continue;
                                }
                                write_quote(
                                    &mut buf,
                                    u32_at(rec),
                                    u32_at(rec + 4),
                                    &mmap[gpos..gpos + PAYLOAD_LEN],
                                );
                            }
                            buf
                        })
                    })
                    .collect();
                handles.into_iter().map(|h| h.join().unwrap()).collect()
            });

            //Send the Packets in main thread buffer onto the printing thread buffer
            for buf in results {
                if !buf.is_empty() {
                    tx.send(buf).map_err(|_| {
                        io::Error::new(io::ErrorKind::BrokenPipe, "printer thread exited")
                    })?;
                }
            }
        }

        // ── QuoteAcceptTime: parallel scan + sort by accept-time ─────────────
        //Each worker scans one slice of the mmap, formats any valid quote packets it owns into a local byte buffer,
        // and records where each row landed so the rows can later be sorted.
        // Each worker also builds an index:
        //   QuoteAcceptIndex { accept_time_cs, global_pos, local_start, local_len }
        //
        // After the scope, all index entries are merged and sorted by
        // (accept_time_cs, global_pos).  global_pos is unique across workers
        // and equals byte arrival-order, giving a deterministic tiebreaker.
        //
        PacketOrdering::QuoteAcceptTime => {
            type WorkerOut = (Vec<u8>, Vec<QuoteAcceptIndex>);

            let results: Vec<WorkerOut> = thread::scope(|s| {
                let mmap = &mmap;
                let handles: Vec<_> = (0..nworkers)
                    .map(|i| {
                        s.spawn(move || -> WorkerOut {
                            //Multiplying so that we can get the ith chunk for the ith worker
                            let base = i * chunk_own;
                            if base >= file_len {
                                return (Vec::new(), Vec::new());
                            }
                            //If there is no file data for this worker, return empty output and empty index.
                            let own_end = (base + chunk_own).min(file_len);
                            //scan_end` extends slightly past that by `OVERLAP`,
                            // so the worker can still see a `B6034` marker crossing a chunk boundary.
                            let scan_end = (own_end + OVERLAP).min(file_len);

                            //Helper to read a 4-byte integer from the mmap using the pcap file’s endianness.
                            let u32_at = |j: usize| -> u32 {
                                let b: [u8; 4] = mmap[j..j + 4].try_into().unwrap();
                                if le {
                                    u32::from_le_bytes(b)
                                } else {
                                    u32::from_be_bytes(b)
                                }
                            };

                            let finder = memmem::Finder::new(b"B6034");
                            let mut buf = Vec::with_capacity(cap_per_work);
                            //preallocate index for roughly
                            //(number of output bytes / average row size) + small headroom
                            let mut index = Vec::with_capacity(cap_per_work / 180 + 16);

                            //Find every `B6034` in this worker’s scan range.
                            for local_pos in finder.find_iter(&mmap[base..scan_end]) {
                                let gpos = base + local_pos;
                                if gpos >= own_end {
                                    break;
                                }
                                //Ignore overlap matches owned by the next worker.
                                if gpos < HDR_TO_PAYLOAD {
                                    continue;
                                }
                                //Avoid underflow before subtracting header size.
                                let rec = gpos - HDR_TO_PAYLOAD;
                                //Compute start of the pcap packet record.
                                if u32_at(rec + 8) != RECORD_DATA_LEN {
                                    continue;
                                }
                                //Validate captured packet length, filtering false `B6034` matches.
                                if gpos + PAYLOAD_LEN > file_len {
                                    continue;
                                }
                                let start = buf.len() as u32;
                                //Remember where this row starts inside the worker buffer.
                                let key = write_quote(
                                    &mut buf,
                                    u32_at(rec),
                                    u32_at(rec + 4),
                                    &mmap[gpos..gpos + PAYLOAD_LEN],
                                );
                                let len = buf.len() as u32 - start;
                                index.push(QuoteAcceptIndex {
                                    accept_time_cs: key,
                                    global_pos: gpos as u32,
                                    local_start: start,
                                    local_len: len,
                                });
                            }
                            (buf, index)
                        })
                    })
                    .collect();
                handles.into_iter().map(|h| h.join().unwrap()).collect()
            });

            //At this point, each worker has returned: (Vec<u8>, Vec<QuoteAcceptIndex>)
            //`Vec<u8>` = that worker’s formatted rows
            //`Vec<QuoteAcceptIndex>` = row metadata pointing into that worker’s buffer

            //Collect all indexes of each worker
            let total_idx: usize = results.iter().map(|(_, idx)| idx.len()).sum();
            let mut all_idx: Vec<MergedQuoteAcceptIndex> = Vec::with_capacity(total_idx);
            for (tid, (_, idx)) in results.iter().enumerate() {
                for item in idx {
                    all_idx.push(MergedQuoteAcceptIndex {
                        accept_time_cs: item.accept_time_cs,
                        global_pos: item.global_pos,
                        worker_id: tid,
                        local_start: item.local_start,
                        local_len: item.local_len,
                    });
                }
            }
            //Sort everything by index
            all_idx.sort_unstable_by_key(|item| (item.accept_time_cs, item.global_pos));

            // Gather sorted lines from per-worker bufs and send in chunks.
            let mut flush_buf: Vec<u8> = Vec::with_capacity(CHUNK_BYTES + 256);
            for item in &all_idx {
                let src = &results[item.worker_id].0;
                let start = item.local_start as usize;
                let end = start + item.local_len as usize;
                flush_buf.extend_from_slice(&src[start..end]);
                if flush_buf.len() >= CHUNK_BYTES {
                    flush_chunk(&tx, &mut flush_buf)?;
                }
            }

            //Final chunk
            if !flush_buf.is_empty() {
                tx.send(flush_buf).map_err(|_| {
                    io::Error::new(io::ErrorKind::BrokenPipe, "printer thread exited")
                })?;
            }
        }
    }

    // Closing tx signals the printer thread to exit after draining.
    drop(tx);
    printer.join().expect("printer thread panicked")
}
