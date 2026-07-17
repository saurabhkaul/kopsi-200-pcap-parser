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

#[inline]
fn accept_time_cs(data: &[u8]) -> u32 {
    let hh = aa(&data[206..208]);
    let mm = aa(&data[208..210]);
    let ss = aa(&data[210..212]);
    let cc = aa(&data[212..214]);
    hh * 360_000 + mm * 6_000 + ss * 100 + cc
}

#[inline]
fn aa(b: &[u8]) -> u32 {
    (b[0] - b'0') as u32 * 10 + (b[1] - b'0') as u32
}

#[inline]
fn push_2d(out: &mut Vec<u8>, n: u64) {
    out.push(b'0' + (n / 10) as u8);
    out.push(b'0' + (n % 10) as u8);
}

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
    let secs = ts_sec as u64 + 9 * 3600;
    push_2d(out, (secs / 3600) % 24);
    out.push(b':');
    push_2d(out, (secs / 60) % 60);
    out.push(b':');
    push_2d(out, secs % 60);
    out.push(b'.');
    push_3d(out, ts_usec as u64 / 1000);
    out.push(b' ');

    out.extend_from_slice(&data[206..208]);
    out.push(b':');
    out.extend_from_slice(&data[208..210]);
    out.push(b':');
    out.extend_from_slice(&data[210..212]);
    out.push(b'.');
    out.extend_from_slice(&data[212..214]);
    out.push(b'0');
    out.push(b' ');

    let code_end = data[5..17]
        .iter()
        .rposition(|&b| b != b' ')
        .map_or(0, |i| i + 1);
    out.extend_from_slice(&data[5..5 + code_end]);

    for i in (0..5usize).rev() {
        out.push(b' ');
        out.extend_from_slice(&data[34 + i * 12..41 + i * 12]);
        out.push(b'@');
        out.extend_from_slice(&data[29 + i * 12..34 + i * 12]);
    }
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
    //   gpos ∈ [base, own_end)
    // The next worker starts at own_end, so no match is double-counted.
    let nworkers = thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    let chunk_own = (file_len + nworkers - 1) / nworkers; // bytes owned per worker
    let cap_per_work = (16_004 * 180 / nworkers).max(1024); // pre-alloc per worker buf

    match ordering {
        // ── Default: emit in pcap arrival order ──────────────────────────────
        //
        // Each worker scans its slice and formats into a local buf.
        // Collecting bufs in worker order == collecting in file order == arrival order.
        // No sort, no merge: just concatenate and send each buf as a channel chunk.
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
                                } // past ownership
                                if gpos < HDR_TO_PAYLOAD {
                                    continue;
                                }
                                let rec = gpos - HDR_TO_PAYLOAD;
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

            for buf in results {
                if !buf.is_empty() {
                    tx.send(buf).map_err(|_| {
                        io::Error::new(io::ErrorKind::BrokenPipe, "printer thread exited")
                    })?;
                }
            }
        }

        // ── QuoteAcceptTime: parallel scan + sort by accept-time ─────────────
        //
        // Each worker also builds an index:
        //   (accept_time_cs, global_pos, local_start, local_len)
        //
        // After the scope, all index entries are merged and sorted by
        // (accept_time_cs, global_pos).  global_pos is unique across workers
        // and equals byte arrival-order, giving a deterministic tiebreaker.
        //
        // Lines are then gathered directly from per-worker bufs into flush_buf
        // and sent to the printer — no extra flat copy of the full output needed.
        PacketOrdering::QuoteAcceptTime => {
            type WorkerOut = (Vec<u8>, Vec<(u32, u32, u32, u32)>);

            let results: Vec<WorkerOut> = thread::scope(|s| {
                let mmap = &mmap;
                let handles: Vec<_> = (0..nworkers)
                    .map(|i| {
                        s.spawn(move || -> WorkerOut {
                            let base = i * chunk_own;
                            if base >= file_len {
                                return (Vec::new(), Vec::new());
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
                            let mut index = Vec::with_capacity(cap_per_work / 180 + 16);

                            for local_pos in finder.find_iter(&mmap[base..scan_end]) {
                                let gpos = base + local_pos;
                                if gpos >= own_end {
                                    break;
                                }
                                if gpos < HDR_TO_PAYLOAD {
                                    continue;
                                }
                                let rec = gpos - HDR_TO_PAYLOAD;
                                if u32_at(rec + 8) != RECORD_DATA_LEN {
                                    continue;
                                }
                                if gpos + PAYLOAD_LEN > file_len {
                                    continue;
                                }
                                let start = buf.len() as u32;
                                let key = write_quote(
                                    &mut buf,
                                    u32_at(rec),
                                    u32_at(rec + 4),
                                    &mmap[gpos..gpos + PAYLOAD_LEN],
                                );
                                let len = buf.len() as u32 - start;
                                index.push((key, gpos as u32, start, len));
                            }
                            (buf, index)
                        })
                    })
                    .collect();
                handles.into_iter().map(|h| h.join().unwrap()).collect()
            });

            // Collect all index entries and sort by (accept_time_cs, global_pos).
            let total_idx: usize = results.iter().map(|(_, idx)| idx.len()).sum();
            // (accept_time_cs, global_pos, worker_id, local_start, local_len)
            let mut all_idx: Vec<(u32, u32, usize, u32, u32)> = Vec::with_capacity(total_idx);
            for (tid, (_, idx)) in results.iter().enumerate() {
                for &(key, gpos, s, l) in idx {
                    all_idx.push((key, gpos, tid, s, l));
                }
            }
            all_idx.sort_unstable_by_key(|&(key, gpos, _, _, _)| (key, gpos));

            // Gather sorted lines from per-worker bufs and send in chunks.
            let mut flush_buf: Vec<u8> = Vec::with_capacity(CHUNK_BYTES + 256);
            for &(_, _, tid, s, l) in &all_idx {
                let src = &results[tid].0;
                flush_buf.extend_from_slice(&src[s as usize..s as usize + l as usize]);
                if flush_buf.len() >= CHUNK_BYTES {
                    flush_chunk(&tx, &mut flush_buf)?;
                }
            }
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
