use anyhow::Result;

use chrono::{TimeZone, Utc};
use chrono_tz::Asia::Seoul;
use pcap_parser::data::get_packetdata;
use pcap_parser::{create_reader, PcapBlockOwned, PcapError, PcapHeader};
use std::fs::File;
use std::io::{stdout, BufReader, BufWriter, Write};
use std::path::PathBuf;
mod models;
pub use models::{PacketDataWithTime, PacketOrdering, QuotePacket};

const DEFAULT_CAPACITY: usize = 65536;
const WRITER_BUFFER_SIZE: usize = 1024 * 1024;
const VEC_BUFFER_SIZE:usize = 64 * 1024;

pub struct SortedPacketsBufWriter<W, const N: usize> 
where
    W: Write,
{
    writer: BufWriter<W>,
    buffer: Vec<QuotePacket<'static, N>>,
    capacity: usize,
}

impl<W, const N: usize> SortedPacketsBufWriter<W, N>
where
    W: Write,
{
    pub fn new(writer: W, capacity: usize) -> Self {
        Self {
            writer: BufWriter::with_capacity(WRITER_BUFFER_SIZE, writer),
            buffer: Vec::with_capacity(capacity),
            capacity,
        }
    }


    pub fn with_default_capacity(writer: W) -> Self {
        Self::new(writer, VEC_BUFFER_SIZE)
    }

    pub fn push(&mut self, packet: QuotePacket<'static, N>) -> Result<()> {
        if self.buffer.len() >= self.capacity {
            self.flush_buffer()?;
        }
        
        
        self.buffer.push(packet);
        Ok(())
    }

    fn flush_buffer(&mut self) -> Result<()> {
        if self.buffer.is_empty() {
            return Ok(());
        }

        self.buffer.sort_unstable();

        for packet in self.buffer.drain(..) {
            write!(self.writer, "{}\n", packet)?;
        }
        
        self.writer.flush()?;
        Ok(())
    }

    pub fn finish(&mut self) -> Result<()> {
        self.flush_buffer()?;
        Ok(())
    }
}
impl<W,const N:usize> Drop for SortedPacketsBufWriter<W,N>
where
    W: Write
{
    fn drop(&mut self) {
        let _ = self.finish();
    }
}


unsafe fn make_static_packet<const N: usize>(packet: QuotePacket<'_, N>) -> QuotePacket<'static, N> {
    std::mem::transmute(packet)
}


#[allow(unused_assignments, unused_variables)]
pub fn read_pcap_file(path_buf: PathBuf, ordering: PacketOrdering) -> Result<()> {
    let mut num_blocks = 0;
    let file = File::open(path_buf)?;
    let reader = BufReader::new(file);
    let mut pcap_reader = create_reader(DEFAULT_CAPACITY, reader)?;

    let mut sorted_writer = SortedPacketsBufWriter::<_, 5>::with_default_capacity(stdout());

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
                                QuotePacket::<5>::try_from(&packet_data_with_time)
                            {
                                let static_packet = unsafe { make_static_packet(quote_packet) };
                                sorted_writer.push(static_packet)?;
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
    Ok(())
}
