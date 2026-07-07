use memchr::memmem;
use memmap2::{Advice, MmapOptions};
use std::{
    cmp::Reverse,
    collections::BinaryHeap,
    fs::File,
    io::{self, Write},
    mem,
    path::Path,
    sync::mpsc,
    thread,
};

const HDR_TO_PAYLOAD:  usize = 16 + 14 + 20 + 8;
const PAYLOAD_LEN:     usize = 215;
const RECORD_DATA_LEN: u32   = (14 + 20 + 8 + PAYLOAD_LEN) as u32;

/// Flush a chunk to the printer thread once it reaches this size.
/// ~16 KB ≈ 88 lines per send; the full dataset needs ~180 channel messages.
const CHUNK_BYTES: usize = 16 * 1024;

pub const PCAP_FILE_PATH: &str = "fixtures/mdf-kospi200.20110216-0.pcap 2";

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
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
    out.push(b'0' + (n / 10  % 10) as u8);
    out.push(b'0' + (n       % 10) as u8);
}

/// Formats one B6034 quote line into `out` and returns the accept-time
/// in centiseconds-of-day (used as the heap sort key).
#[inline]
fn write_quote(out: &mut Vec<u8>, ts_sec: u32, ts_usec: u32, data: &[u8]) -> u32 {
    let secs = ts_sec as u64 + 9 * 3600;
    push_2d(out, (secs / 3600) % 24); out.push(b':');
    push_2d(out, (secs / 60)   % 60); out.push(b':');
    push_2d(out, secs          % 60); out.push(b'.');
    push_3d(out, ts_usec as u64 / 1000); out.push(b' ');

    out.extend_from_slice(&data[206..208]); out.push(b':');
    out.extend_from_slice(&data[208..210]); out.push(b':');
    out.extend_from_slice(&data[210..212]); out.push(b'.');
    out.extend_from_slice(&data[212..214]); out.push(b'0');
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
        out.extend_from_slice(&data[96  + i * 12..101 + i * 12]);
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

    let little_endian = match &mmap[0..4] {
        [0xd4, 0xc3, 0xb2, 0xa1] | [0x4d, 0x3c, 0xb2, 0xa1] => true,
        [0xa1, 0xb2, 0xc3, 0xd4] | [0xa1, 0xb2, 0x3c, 0x4d] => false,
        _ => return Err(io::Error::new(io::ErrorKind::InvalidData, "not a pcap file")),
    };

    let u32_at = |i: usize| -> u32 {
        let b: [u8; 4] = mmap[i..i + 4].try_into().unwrap();
        if little_endian { u32::from_le_bytes(b) } else { u32::from_be_bytes(b) }
    };

    // ── Core pinning ─────────────────────────────────────────────────────────
    // Pin parser (this thread) to core 0, printer thread to core 1.
    // Best-effort: if fewer cores are available, pinning is skipped silently.
    let cores = core_affinity::get_core_ids().unwrap_or_default();
    if let Some(&c) = cores.first() {
        core_affinity::set_for_current(c);
    }
    let printer_core = cores.get(1).copied();

    // ── Printer thread ───────────────────────────────────────────────────────
    // Bounded channel (capacity 16): parser blocks if printer falls behind,
    // preventing unbounded memory growth under slow I/O.
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

    // ── Parse + send ─────────────────────────────────────────────────────────
    let finder = memmem::Finder::new(b"B6034");

    match ordering {
        // ── Default: emit lines in pcap arrival order ─────────────────────
        PacketOrdering::Default => {
            let mut chunk: Vec<u8> = Vec::with_capacity(CHUNK_BYTES + 256);

            for pos in finder.find_iter(&mmap) {
                if pos < HDR_TO_PAYLOAD { continue; }
                let rec = pos - HDR_TO_PAYLOAD;
                if u32_at(rec + 8) != RECORD_DATA_LEN { continue; }
                if pos + PAYLOAD_LEN > mmap.len()      { continue; }

                write_quote(&mut chunk, u32_at(rec), u32_at(rec + 4),
                            &mmap[pos..pos + PAYLOAD_LEN]);

                if chunk.len() >= CHUNK_BYTES {
                    flush_chunk(&tx, &mut chunk)?;
                }
            }
            if !chunk.is_empty() {
                tx.send(chunk)
                  .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "printer thread exited"))?;
            }
        }

        // ── QuoteAcceptTime: streaming min-heap with 3-second window ──────
        //
        // `out`       — backing store; formatted lines are appended here and
        //               referenced by (start, len) offsets stored in the heap.
        // `flush_buf` — lines popped from the heap (now in accept-time order)
        //               accumulate here until they fill a chunk, then are sent.
        //
        // Heap entry: Reverse<(accept_time_cs, seq, start, len)>
        //   • Reverse  — turns BinaryHeap (max-heap) into a min-heap
        //   • seq      — arrival-order tiebreaker for equal accept-times
        PacketOrdering::QuoteAcceptTime => {
            let mut out  = Vec::with_capacity(16_004 * 180);
            let mut heap: BinaryHeap<Reverse<(u32, u32, u32, u32)>> = BinaryHeap::new();
            let mut flush_buf: Vec<u8> = Vec::with_capacity(CHUNK_BYTES + 256);
            let mut seq = 0u32;

            for pos in finder.find_iter(&mmap) {
                if pos < HDR_TO_PAYLOAD { continue; }
                let rec = pos - HDR_TO_PAYLOAD;
                if u32_at(rec + 8) != RECORD_DATA_LEN { continue; }
                if pos + PAYLOAD_LEN > mmap.len()      { continue; }

                let ts_sec  = u32_at(rec);
                let ts_usec = u32_at(rec + 4);

                let start = out.len() as u32;
                let key = write_quote(&mut out, ts_sec, ts_usec,
                                      &mmap[pos..pos + PAYLOAD_LEN]);
                let len = out.len() as u32 - start;

                heap.push(Reverse((key, seq, start, len)));
                seq += 1;

                // Convert pcap timestamp to centiseconds-of-day in KST so it
                // is comparable to accept_time_cs (which is also KST wall-clock).
                let pcap_cs = ((ts_sec as u64 + 9 * 3600) % 86400) as u32 * 100
                            + ts_usec / 10_000;

                // Flush every heap entry whose accept-time is more than 3 s
                // behind the current pcap time — its final rank is now settled.
                let threshold = pcap_cs.saturating_sub(300); // 300 cs = 3 s
                while let Some(&Reverse((a_min, _, _, _))) = heap.peek() {
                    if a_min < threshold {
                        let Reverse((_, _, s, l)) = heap.pop().unwrap();
                        flush_buf.extend_from_slice(
                            &out[s as usize..s as usize + l as usize]);

                        if flush_buf.len() >= CHUNK_BYTES {
                            flush_chunk(&tx, &mut flush_buf)?;
                        }
                    } else {
                        break;
                    }
                }
            }

            // EOF: drain the remaining heap in sorted order.
            while let Some(Reverse((_, _, s, l))) = heap.pop() {
                flush_buf.extend_from_slice(&out[s as usize..s as usize + l as usize]);

                if flush_buf.len() >= CHUNK_BYTES {
                    flush_chunk(&tx, &mut flush_buf)?;
                }
            }
            if !flush_buf.is_empty() {
                tx.send(flush_buf)
                  .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "printer thread exited"))?;
            }
        }
    }

    // Drop tx → channel closes → printer thread exits its for-loop.
    drop(tx);
    printer.join().expect("printer thread panicked")
}
