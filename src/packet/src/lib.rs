use anyhow::{Result};
use std::path::PathBuf;
use std::fs::File;
use std::io::{stdout, BufReader, BufWriter, Stdout, Write};
use pcap_parser::data::{get_packetdata};
use pcap_parser::{create_reader,PcapBlockOwned, PcapError};
use chrono::{TimeZone, Utc};
use chrono_tz::Asia::Seoul;
mod models;
pub use models::{QuotePacket, PacketOrdering,PacketDataWithTime};

const DEFAULT_CAPACITY: usize = 65536;


//This controls the buffer of sorted packets, tweak this based on how much memory we can use
const BUFFER_SIZE:usize = 1024*1024;




pub struct Stream {
    packets: Vec<QuotePacket>,
    writer:BufWriter<Stdout>,
}

impl Stream {
    fn new() -> Self {
        Self {
            packets: Vec::with_capacity(BUFFER_SIZE),
            writer:  BufWriter::with_capacity(BUFFER_SIZE*2, stdout())
        }
    }
    fn push(&mut self, packet: QuotePacket) {
        match self.packets.capacity() == self.packets.len() {
            true => {
                self.packets.sort();
                self.packets.drain(..).for_each(|packet|self.writer.write_all(format!("{}\n", packet).as_bytes()).unwrap());
                self.packets.push(packet);
            }
            false =>{
                self.writer.flush().unwrap();
                self.packets.push(packet);
            },
        }
        
    }
}



#[allow(unused_assignments,unused_variables)]
pub fn read_pcap_file(path_buf: PathBuf,ordering: PacketOrdering) -> Result<()>{
    let mut num_blocks = 0;
    let mut stream = Stream::new();

    let file = File::open(path_buf)?;
    let reader = BufReader::new(file);

    let mut pcap_reader = create_reader(DEFAULT_CAPACITY,reader)?;
    loop {
        match pcap_reader.next() {
            Ok((offset,block)) => {
                num_blocks += 1;
                let mut packet_header = Default::default();
                match block {
                    PcapBlockOwned::LegacyHeader(header) => {
                        packet_header = header;

                    }
                    PcapBlockOwned::Legacy(packet) => {
                        let (ts_sec,ts_usec,caplen,data) = (packet.ts_sec,packet.ts_usec,packet.caplen,packet.data);

                        let utc_timestamp = Utc.timestamp_opt(
                            ts_sec as i64,
                            ts_usec * 1000  // Convert microseconds to nanoseconds
                        );

                        let ktc_time = utc_timestamp.single().unwrap().with_timezone(&Seoul).time();

                        if let Some(data) = get_packetdata(data, packet_header.network, caplen as usize){
                         let packet_data_with_time = PacketDataWithTime{
                             packet_timestamp: ktc_time,
                             data,
                             ordering,
                         };

                         match QuotePacket::try_from(packet_data_with_time) {
                             Ok(quote_packet) => stream.push(quote_packet),
                             Err(_e) => ()
                         }

                        }
                    }
                    PcapBlockOwned::NG(_) => {
                        unreachable!()
                    }
                }
                pcap_reader.consume(offset);
            }
            Err(PcapError::Eof) => break,
            Err(PcapError::Incomplete(_)) => {
                pcap_reader.refill().unwrap();

            },
            Err(e) => panic!("Error {:?} while reading file", e),
        }
    }
    Ok(())
}