use std::cmp::Ordering;
use anyhow::{Error, Result};
use std::{fmt, str};
use nom::error::ErrorKind;
use std::path::PathBuf;
use std::fs::File;
use std::io::BufReader;
use pcap_parser::data::{get_packetdata, PacketData};
use pcap_parser::{create_reader,PcapBlockOwned, PcapError};
use chrono::{NaiveTime, TimeZone, Utc};
use chrono_tz::Asia::Seoul;


const DEFAULT_CAPACITY: usize = 65536;



/* Example packet
0000   01 00 5e 25 36 3e 00 12 44 c8 38 0a 08 00 45 00
0010   00 f3 e1 81 00 00 3b 11 ba f6 c0 a6 02 78 e9 25
0020   36 3e 8d ce 3c 9c 00 df 78 83 42 36 30 33 34 4b
0030   52 34 33 30 31 46 36 32 35 35 31 30 39 32 31 31
0040   30 30 30 31 30 34 32 30 30 34 35 35 30 30 30 30
0050   30 30 31 30 30 34 35 30 30 30 30 30 30 31 30 30
0060   30 34 34 35 30 30 30 30 30 31 30 30 30 34 34 30
0070   30 30 30 30 30 30 30 30 30 34 33 35 30 30 30 30
0080   30 31 30 30 30 30 31 30 34 30 30 30 38 33 35 30
0090   30 30 30 30 31 30 30 30 38 34 30 30 30 30 30 30
00a0   31 30 30 30 38 34 35 30 30 30 30 30 30 30 30 30
00b0   38 35 30 30 30 30 30 30 31 30 30 30 38 35 35 30
00c0   30 30 30 30 31 30 30 30 31 30 36 30 30 30 31 30
00d0   30 30 31 30 30 30 31 30 30 30 30 30 30 30 31 30
00e0   30 31 30 34 30 30 30 31 30 30 30 31 30 30 30 30
00f0   30 30 30 31 30 30 30 31 30 39 30 30 30 30 30 30
0100   ff

16 full lines * 16 bytes per line = 256 bytes
Plus 1 byte on the last line
Total: 256 + 1 = 257 bytes
*/

const PACKET_IDENTIFIER:&str = "B6034";


#[derive(Debug,Eq)]
#[allow(dead_code)]
pub struct QuotePacket {
    packet_time:NaiveTime,
    data_type: String,
    information_type: String,
    market_type: char,
    issue_code: String,
    issue_seq_no: String,
    market_status_type: String,
    total_bid_quote_volume: String,
    bid_prices: Vec<String>,
    bid_quantities: Vec<String>,
    total_ask_quote_volume: String,
    ask_prices: Vec<String>,
    ask_quantities: Vec<String>,
    best_bid_valid_quote_total: String,
    best_bid_quotes: Vec<String>,
    best_ask_valid_quote_total: String,
    best_ask_quotes: Vec<String>,
    quote_accept_time: NaiveTime,
}

impl fmt::Display for QuotePacket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {} {}",
               self.packet_time.format("%H:%M:%S%.3f"),
               self.quote_accept_time,
               self.issue_code
        )?;

        for i in (0..5).rev() {
            write!(f, " {}@{}",
                   self.bid_quantities.get(i).unwrap(),
                   self.bid_prices.get(i).unwrap()
            )?;
        }

        for i in 0..5 {
            write!(f, " {}@{}",
                   self.ask_quantities.get(i).unwrap(),
                   self.ask_prices.get(i).unwrap()
            )?;
        }

        Ok(())
    }
}

impl PartialEq<Self> for QuotePacket {
    fn eq(&self, other: &Self) -> bool {
        self.quote_accept_time == other.quote_accept_time
    }
}

impl Ord for QuotePacket {
    fn cmp(&self, other: &Self) -> Ordering {
        other.quote_accept_time.cmp(&self.quote_accept_time)
    }
}

impl PartialOrd<Self> for QuotePacket {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}



fn parse_str_in_packet(slice: &[u8]) -> Result<&str, PcapError<&[u8]>> {
    str::from_utf8(slice).map_err(|_e| {
        PcapError::NomError(slice, ErrorKind::Verify)
    })
}

impl <'a>TryFrom<PacketDataWithTime<'a>> for QuotePacket {
    type Error = PcapError<&'a [u8]>;
    fn try_from(data:PacketDataWithTime<'a>) -> Result<Self, Self::Error> {
        let (packet_time,data) = (data.packet_timestamp,data.data);
        let data_slice = match data {
            PacketData::L2(d) => d,
            _ => return Err(PcapError::HeaderNotRecognized)
        };
        let mut offset = 42; //Packet data starts from the 42nd byte.

        let data_type = parse_str_in_packet(&data_slice[offset..offset+2])?.to_string();
        offset += 2;

        let information_type = parse_str_in_packet(&data_slice[offset..offset+2])?.to_string();
        offset += 2;

        let market_type = data_slice[offset] as char;
        offset += 1;

        let packet_identifier = format!("{}{}{}",data_type,information_type,market_type);

        if packet_identifier != PACKET_IDENTIFIER {
             return Err(Self::Error::from_data(
                 &data_slice[..offset],
                 ErrorKind::IsNot
             ))
        }else {
            let issue_code = parse_str_in_packet(&data_slice[offset..offset+12])?.to_string();
            offset += 12;

            let issue_seq_no = parse_str_in_packet(&data_slice[offset..offset+3])?.to_string();
            offset += 3;

            let market_status_type = parse_str_in_packet(&data_slice[offset..offset+2])?.to_string();
            offset += 2;

            let total_bid_quote_volume = parse_str_in_packet(&data_slice[offset..offset+7])?.to_string();
            offset += 7;

            let mut bid_prices = Vec::new();
            let mut bid_quantities = Vec::new();
            let mut ask_prices = Vec::new();
            let mut ask_quantities = Vec::new();

            for _ in 0..5 {

                bid_prices.push(parse_str_in_packet(&data_slice[offset..offset + 5])?.to_string());
                offset += 5;

                bid_quantities.push(parse_str_in_packet(&data_slice[offset..offset + 5])?.to_string());
                offset += 7;
            }

            let total_ask_quote_volume = parse_str_in_packet(&data_slice[offset..offset+7])?.to_string();
            offset += 7;

            for _ in 0..5 {
                ask_prices.push(parse_str_in_packet(&data_slice[offset..offset+5])?.to_string());


                offset += 5;
                ask_quantities.push(parse_str_in_packet(&data_slice[offset..offset+7])?.to_string());


                offset += 7;
            }

            let best_bid_valid_quote_total = parse_str_in_packet(&data_slice[offset..offset+5])?.to_string();
            offset += 5;

            let mut best_bid_quotes = Vec::new();
            for _ in 0..5 {
                best_bid_quotes.push(parse_str_in_packet(&data_slice[offset..offset+4])?.to_string());
                offset += 4;
            }

            let best_ask_valid_quote_total = parse_str_in_packet(&data_slice[offset..offset+5])?.to_string();
            offset += 5;

            let mut best_ask_quotes = Vec::new();
            for _ in 0..5 {
                best_ask_quotes.push(parse_str_in_packet(&data_slice[offset..offset+4])?.to_string());
                offset += 4;
            }

            let quote_accept_time_string = parse_str_in_packet(&data_slice[offset..offset+8])?.to_string();

            let hours = u32::from_str_radix(&quote_accept_time_string[0..2], 10).unwrap();
            let minutes = u32::from_str_radix(&quote_accept_time_string[2..4], 10).unwrap();
            let seconds = u32::from_str_radix(&quote_accept_time_string[4..6], 10).unwrap();
            let centisecs = u32::from_str_radix(&quote_accept_time_string[6..8], 10).unwrap();
            let microseconds = centisecs * 10000;

            let quote_accept_time = NaiveTime::from_hms_micro_opt(hours, minutes, seconds, microseconds).unwrap();

            Ok(QuotePacket {
                packet_time,
                data_type,
                information_type,
                market_type,
                issue_code,
                issue_seq_no,
                market_status_type,
                total_bid_quote_volume,
                bid_prices,
                bid_quantities,
                total_ask_quote_volume,
                ask_prices,
                ask_quantities,
                best_bid_valid_quote_total,
                best_bid_quotes,
                best_ask_valid_quote_total,
                best_ask_quotes,
                quote_accept_time,
            })
        }


    }
}

struct PacketDataWithTime<'a>{
    data:PacketData<'a>,
    packet_timestamp:NaiveTime
}

#[allow(unused_assignments,unused_variables)]
pub async fn read_pcap_file(path_buf: PathBuf) ->Result<Vec<QuotePacket>,Error>{
    let mut num_blocks = 0;
    let mut quote_packets = vec![];

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
                         }  ;

                         match QuotePacket::try_from(packet_data_with_time) {
                             Ok(quote_packet) => quote_packets.push(quote_packet),
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
    Ok(quote_packets)
}
