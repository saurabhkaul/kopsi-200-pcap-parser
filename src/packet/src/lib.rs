use anyhow::Result;
use std::sync::mpsc;
use std::thread;
use chrono::{TimeZone, Utc};
use chrono_tz::Asia::Seoul;
use pcap_parser::data::get_packetdata;
use pcap_parser::{create_reader, PcapBlockOwned, PcapError, PcapHeader};
use std::fs::File;
use std::io::{BufReader, BufWriter, Stdout, Write, stdout};
use heapless::Vec as HeaplessVec;
use std::path::PathBuf;
mod models;
pub use models::{PacketDataWithTime, PacketOrdering, QuotePacket};



fn print_worker_default_ordering(rx: mpsc::Receiver<QuotePacket>) {
    let stdout = stdout();
    let mut out = stdout.lock();
    while let Ok(qp) = rx.recv() {
        writeln!(out, "{}", qp).expect("should be able to print");
    }
    out.flush().expect("should flush at last");
}


fn print_worker_quote_accept_time_ordering(rx: mpsc::Receiver<QuotePacket>) {
    let stdout = stdout();
    let mut out = stdout.lock();
    let mut buffer_that_sorts:HeaplessVec<QuotePacket,100> = HeaplessVec::new();
    
    loop {
            match rx.recv() {
                Ok(item) => {
                    // Push until full
                    if buffer_that_sorts.push(item.clone()).is_err() {
                        // buffer full → sort + drain
                        buffer_that_sorts.sort();
    
                        for item in buffer_that_sorts.drain(..) {
                            writeln!(out, "{}", item)
                                .expect("stdout write failed");
                        }
    
                        // retry push (now guaranteed to succeed)
                        buffer_that_sorts.push(item).unwrap();
                    }
                }
    
                // Channel closed → flush remaining items
                Err(_) => {
                    if !buffer_that_sorts.is_empty() {
                        buffer_that_sorts.sort();
                        for item in buffer_that_sorts.drain(..) {
                            writeln!(out, "{}", item)
                                .expect("stdout write failed");
                        }
                    }
                    break;
                }
            }
        }
    
        out.flush().expect("final flush failed");
    
    // while let Ok(qp) = rx.recv() {
    //     buffer_that_sorts.push(qp)
    //     // writeln!(buffer_that_sorts, "{}", qp).expect("should be able to print");
    // }
    // out.flush().expect("should flush at last");
}


#[allow(unused_assignments, unused_variables)]
pub fn read_pcap_file(path_buf: PathBuf, ordering: PacketOrdering) -> Result<()> {
    let (tx, rx) = mpsc::channel::<QuotePacket>();
    let handle = thread::spawn(move || {
        match ordering {
            PacketOrdering::Default => print_worker_default_ordering(rx),
            PacketOrdering::QuoteAcceptTime => print_worker_quote_accept_time_ordering(rx),
        }
    });
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

                            
                            if let Ok(quote_packet) =
                                QuotePacket::try_from(&packet_data_with_time){
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
    let _ = handle.join();
    Ok(())
}
