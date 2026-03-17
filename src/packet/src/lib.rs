use anyhow::Result;
use chrono::{Duration, TimeZone, Utc};
use chrono_tz::Asia::Seoul;
use heapless::Vec as HeaplessVec;
use pcap_parser::data::get_packetdata;
use pcap_parser::{create_reader, PcapBlockOwned, PcapError, PcapHeader};
use std::fs::File;
use std::io::{BufReader, BufWriter, Write};
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

fn print_worker_quote_accept_time_ordering<W: Write>(rx: mpsc::Receiver<QuotePacket>, out: W) -> W {
    let mut out = BufWriter::with_capacity(65_536, out);
    let mut buffer: HeaplessVec<QuotePacket, WINDOW_CAPACITY> = HeaplessVec::new();
    // Track the minimum quote_accept_time in the buffer so we can decide
    // whether a flush is needed in O(1) without scanning.
    let mut min_qat: Option<chrono::NaiveTime> = None;

    for item in rx {
        let pt = item.packet_time();
        let qat = item.quote_accept_time();
        min_qat = Some(min_qat.map_or(qat, |m: chrono::NaiveTime| m.min(qat)));
        buffer.push(item).expect("window buffer full — increase WINDOW_CAPACITY");

        // Any buffered packet with quote_accept_time < (current_packet_time - 3s)
        // is guaranteed to precede all future packets in quote_accept_time order,
        // because future packets have packet_time >= pt and therefore
        // quote_accept_time >= pt - 3s.
        let flush_threshold = pt - Duration::seconds(3);
        if min_qat.is_some_and(|m| m < flush_threshold) {
            buffer.sort();
            let flush_count = buffer.partition_point(|p| p.quote_accept_time() < flush_threshold);
            for i in 0..flush_count {
                buffer[i].write_to(&mut out).expect("stdout write failed");
            }
            let new_len = buffer.len() - flush_count;
            buffer.rotate_left(flush_count);
            buffer.truncate(new_len);
            min_qat = buffer.iter().map(|p| p.quote_accept_time()).min();
        }
    }

    // Flush all remaining packets in sorted order.
    buffer.sort();
    for item in buffer.drain(..) {
        item.write_to(&mut out).expect("stdout write failed");
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
    // 16 MB stack for the print worker — needed for large HeaplessVec<QuotePacket, CHUNK_SIZE>
    // allocations in the quote-accept-time ordering path.
    const PRINT_WORKER_STACK_SIZE: usize = 16 * 1024 * 1024;
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
