use anyhow::Result;
use chrono::{Duration, TimeZone, Utc};
use chrono_tz::Asia::Seoul;
use pcap_parser::data::get_packetdata;
use pcap_parser::{create_reader, PcapBlockOwned, PcapError, PcapHeader};
use std::fs::File;
use std::io::{BufReader, BufWriter, Write};
use std::mem::MaybeUninit;
use std::path::PathBuf;
use std::sync::mpsc;
use std::thread;
mod models;
pub use models::{PacketDataWithTime, PacketOrdering, QuotePacket};

fn print_worker_default_ordering<W: Write>(rx: mpsc::Receiver<QuotePacket>, out: W) -> W {
    let mut out = BufWriter::with_capacity(65536, out);
    while let Ok(qp) = rx.recv() {
        qp.write_to(&mut out).expect("should be able to print");
    }
    out.flush().expect("should flush at last");
    out.into_inner().unwrap_or_else(|_| panic!("BufWriter into_inner failed"))
}

// Upper bound on packets within any 3-second window of packet_time.
// The challenge guarantees |quote_accept_time - packet_time| <= 3s, so this
// bounds how many packets can ever be in-flight at once.
const WINDOW_CAPACITY: usize = 3500;

// Total physical slots. The extra WINDOW_CAPACITY of headroom means compaction
// (one bulk memmove back to slot 0) happens at most once per WINDOW_CAPACITY
// inserts — amortised O(1) per push.
const TOTAL_CAPACITY: usize = WINDOW_CAPACITY * 2;

/// Stack-allocated sliding-window buffer that is always kept sorted by
/// `quote_accept_time`.
///
/// Inserting maintains sorted order via binary search + shift. Because packets
/// arrive roughly in packet_time order and `qat ≈ packet_time`, the insertion
/// point is almost always at the tail — the shift is zero elements, so each
/// push is effectively O(log n) with no data movement.
///
/// Flushing is O(1): just advance the `head` integer. No `rotate_left` needed.
struct SlidingWindowBuffer {
    // SAFETY invariant: data[head .. head+len] are fully initialised QuotePackets,
    // sorted in ascending order by quote_accept_time.
    data: [MaybeUninit<QuotePacket>; TOTAL_CAPACITY],
    head: usize,
    len: usize,
}

impl SlidingWindowBuffer {
    fn new() -> Self {
        // SAFETY: MaybeUninit<T> does not require T to be initialised.
        unsafe {
            Self {
                data: MaybeUninit::uninit().assume_init(),
                head: 0,
                len: 0,
            }
        }
    }

    /// Insert `item` while maintaining sorted order by `quote_accept_time`.
    /// For mostly-in-order data the binary search finds `pos == len` and no
    /// shifting occurs, so the common case is O(log n) with no data movement.
    fn push_sorted(&mut self, item: QuotePacket) {
        debug_assert!(self.len < WINDOW_CAPACITY, "window buffer full — increase WINDOW_CAPACITY");
        if self.head + self.len == TOTAL_CAPACITY {
            self.compact();
        }

        // Binary search in the live (sorted) slice.
        let pos = {
            // SAFETY: data[head..head+len] are initialised.
            let live = unsafe {
                let ptr = self.data.as_ptr().add(self.head) as *const QuotePacket;
                std::slice::from_raw_parts(ptr, self.len)
            };
            live.partition_point(|p| p.quote_accept_time() < item.quote_accept_time())
        };

        let insert_at = self.head + pos;

        // Shift data[insert_at .. head+len] right by one to open a slot.
        // SAFETY: src and dst are within the allocated array; ptr::copy handles overlap.
        if pos < self.len {
            unsafe {
                std::ptr::copy(
                    self.data.as_ptr().add(insert_at) as *const QuotePacket,
                    self.data.as_mut_ptr().add(insert_at + 1) as *mut QuotePacket,
                    self.len - pos,
                );
            }
        }

        // Write the new element into the opened slot.
        // SAFETY: insert_at is within allocated range; slot is now logically uninit.
        unsafe {
            (self.data.as_mut_ptr().add(insert_at) as *mut QuotePacket).write(item);
        }
        self.len += 1;
    }

    /// Mutable view of the live (sorted) elements.
    fn live_slice_mut(&mut self) -> &mut [QuotePacket] {
        // SAFETY: data[head..head+len] are all initialised.
        unsafe {
            let ptr = self.data.as_mut_ptr().add(self.head) as *mut QuotePacket;
            std::slice::from_raw_parts_mut(ptr, self.len)
        }
    }

    /// Drop the first `n` live elements by advancing the head — O(1), no memmove.
    fn advance_head(&mut self, n: usize) {
        debug_assert!(n <= self.len);
        for i in self.head..self.head + n {
            // SAFETY: data[head..head+n] are initialised.
            unsafe { self.data[i].assume_init_drop() };
        }
        self.head += n;
        self.len -= n;
    }

    /// Move live data to slot 0. Called at most once per WINDOW_CAPACITY pushes.
    fn compact(&mut self) {
        if self.head == 0 {
            return;
        }
        // SAFETY: ptr::copy (memmove) handles overlapping ranges correctly.
        unsafe {
            std::ptr::copy(
                self.data.as_ptr().add(self.head),
                self.data.as_mut_ptr(),
                self.len,
            );
        }
        self.head = 0;
    }
}

impl Drop for SlidingWindowBuffer {
    fn drop(&mut self) {
        for i in self.head..self.head + self.len {
            // SAFETY: data[head..head+len] are initialised.
            unsafe { self.data[i].assume_init_drop() };
        }
    }
}

fn print_worker_quote_accept_time_ordering<W: Write>(rx: mpsc::Receiver<QuotePacket>, out: W) -> W {
    let mut out = BufWriter::with_capacity(65_536, out);
    let mut buf = SlidingWindowBuffer::new();

    for item in rx {
        let pt = item.packet_time();

        // Insert maintaining sorted order — typically O(log n), O(1) shift.
        buf.push_sorted(item);

        // Any buffered packet with quote_accept_time < (current_packet_time - 3s)
        // is guaranteed to precede all future packets in quote_accept_time order.
        let flush_threshold = pt - Duration::seconds(3);

        // buf is sorted: only flush if the minimum (first element) is below threshold.
        let should_flush = buf
            .live_slice_mut()
            .first()
            .is_some_and(|p| p.quote_accept_time() < flush_threshold);

        if should_flush {
            let flush_count = {
                let live = buf.live_slice_mut();
                // Buffer is sorted; elements < threshold form a contiguous prefix.
                let fc = live.partition_point(|p| p.quote_accept_time() < flush_threshold);
                for p in &live[..fc] {
                    p.write_to(&mut out).expect("stdout write failed");
                }
                fc
            }; // live borrow ends here
            // O(1): advance head integer, no data movement.
            buf.advance_head(flush_count);
        }
    }

    // Flush remaining packets (already sorted).
    for p in buf.live_slice_mut().iter() {
        p.write_to(&mut out).expect("stdout write failed");
    }

    out.flush().expect("final flush failed");
    out.into_inner().unwrap_or_else(|_| panic!("BufWriter into_inner failed"))
}

#[allow(unused_assignments, unused_variables)]
pub fn read_pcap_file<W: Write + Send + 'static>(
    path_buf: PathBuf,
    ordering: PacketOrdering,
    out: W,
) -> Result<W> {
    let (tx, rx) = mpsc::channel::<QuotePacket>();
    const PRINT_WORKER_STACK_SIZE: usize = 8 * 1024 * 1024;
    let handle = thread::Builder::new()
        .stack_size(PRINT_WORKER_STACK_SIZE)
        .spawn(move || match ordering {
            PacketOrdering::Default => print_worker_default_ordering(rx, out),
            PacketOrdering::QuoteAcceptTime => print_worker_quote_accept_time_ordering(rx, out),
        })
        .expect("failed to spawn print worker thread");
    let mut num_blocks = 0;
    let file = File::open(path_buf)?;
    let reader = BufReader::new(file);
    let mut pcap_reader = create_reader(65536, reader)?;

    loop {
        match pcap_reader.next() {
            Ok((offset, block)) => {
                num_blocks += 1;
                let mut packet_header = PcapHeader::new();

                match block {
                    PcapBlockOwned::LegacyHeader(header) => {
                        packet_header = header;
                    }
                    PcapBlockOwned::Legacy(packet) => {
                        let (ts_sec, ts_usec, caplen, data) =
                            (packet.ts_sec, packet.ts_usec, packet.caplen, packet.data);

                        let utc_timestamp = Utc.timestamp_opt(ts_sec as i64, ts_usec * 1000);
                        let ktc_time = utc_timestamp.single().unwrap().with_timezone(&Seoul).time();

                        if let Some(data) =
                            get_packetdata(data, packet_header.network, caplen as usize)
                        {
                            let packet_data_with_time = PacketDataWithTime {
                                packet_timestamp: ktc_time,
                                data,
                                ordering,
                            };

                            if let Ok(quote_packet) = QuotePacket::try_from(&packet_data_with_time)
                            {
                                let _ = tx.send(quote_packet);
                            }
                        }
                    }
                    PcapBlockOwned::NG(_) => unreachable!(),
                }
                pcap_reader.consume(offset);
            }
            Err(PcapError::Eof) => break,
            Err(PcapError::Incomplete(_)) => {
                pcap_reader.refill().unwrap();
            }
            Err(e) => panic!("Error {:?} while reading file", e),
        }
    }
    drop(tx);
    let out = handle.join().expect("print worker panicked");
    Ok(out)
}
