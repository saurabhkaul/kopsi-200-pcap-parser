use anyhow::{Result};
use std::cmp::Ordering;
use std:: {fmt, str};
use pcap_parser::data::{PacketData};
use pcap_parser::{PcapError};
use chrono::{NaiveTime};
use nom::error::ErrorKind;

const PACKET_IDENTIFIER:&str = "B6034";



pub struct PacketDataWithTime<'a>{
    pub data:PacketData<'a>,
    pub packet_timestamp:NaiveTime,
    pub ordering: PacketOrdering,
}

#[derive(Copy,Clone,Debug,Eq,PartialEq)]
pub enum PacketOrdering {
    Default,
    QuoteAcceptTime,
}


#[derive(Debug,Eq,Clone,Copy)]
pub struct QuotePacket<'a,const N:usize> {
    packet_time:NaiveTime,
    issue_code: &'a str,
    bid_prices: [&'a str;N],
    bid_quantities: [&'a str;N],
    ask_prices: [&'a str;N],
    ask_quantities: [&'a str;N],
    quote_accept_time: NaiveTime,
    ordering: PacketOrdering,
    
}



impl<'a,const N:usize> fmt::Display for QuotePacket<'a,N> {
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

impl <'a,const N:usize> PartialEq<Self> for QuotePacket<'a,N> {
    fn eq(&self, other: &Self) -> bool {
        self.quote_accept_time == other.quote_accept_time
    }
}

impl<'a,const N:usize> Ord for QuotePacket<'a,N> {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.ordering {
            PacketOrdering::Default => self.packet_time.cmp(&other.packet_time),
            PacketOrdering::QuoteAcceptTime => self.quote_accept_time.cmp(&other.quote_accept_time),
        }
        
    }
}

impl <'a,const N:usize> PartialOrd<Self> for QuotePacket<'a,N> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}



fn parse_ascii_str_in_packet(slice: &[u8]) -> Result<&str, PcapError<&[u8]>> {
    str::from_utf8(slice).map_err(|_e| {
        PcapError::NomError(slice, ErrorKind::Verify)
    })
    // if slice.iter().all(|&b| b.is_ascii()) {
    //        Ok(unsafe { str::from_utf8_unchecked(slice) })
    //    } else {
    //        Err(PcapError::NomError(slice, ErrorKind::Verify))
    //    }
    // Not checking for ascii or utf8 since this is in the hot path
    // Ok(unsafe { str::from_utf8_unchecked(slice)})
}

impl <'a,const N:usize>TryFrom<&PacketDataWithTime<'a>> for QuotePacket<'a,N> {
    type Error = PcapError<&'a [u8]>;
    
    // fn try_from(data:&PacketDataWithTime<'a>) -> Result<Self, Self::Error> {
       
    //     let (packet_time,data,ordering) = (data.packet_timestamp,&data.data,data.ordering);
    //             let data_slice = match data {
    //                 PacketData::L2(d) => d,
    //                 _ => return Err(PcapError::HeaderNotRecognized)
    //             };
    //             let mut offset = 42;
        
    //             if data_slice.len() < offset + 5 {
    //                 return Err(PcapError::NomError(&data_slice[offset..], ErrorKind::Eof));
    //             }
                
    //             if &data_slice[offset..offset+5] != b"B6034" {
    //                 return Err(PcapError::NomError(&data_slice[offset..offset+5], ErrorKind::IsNot));
    //             }
    //             offset += 5;
        
    //             let issue_code = parse_ascii_str_in_packet(&data_slice[offset..offset+12])?;
    //             offset += 24;
        
    //             let mut bid_prices = ["";N];
    //             let mut bid_quantities = ["";N];
    //             let mut ask_prices = ["";N];
    //             let mut ask_quantities = ["";N];
        
    //             // Batch boundary check to avoid repeated bounds checking
    //             let required_len = offset + (5 * (5 + 7)) + 7 + (5 * (5 + 7)) + 50 + 8;
    //             if data_slice.len() < required_len {
    //                 return Err(PcapError::NomError(&data_slice[offset..], ErrorKind::Eof));
    //             }
        
    //             for i in 0..5 {
    //                 bid_prices[i] = parse_ascii_str_in_packet(&data_slice[offset..offset + 5])?;
    //                 offset += 5;
    //                 bid_quantities[i] = parse_ascii_str_in_packet(&data_slice[offset..offset + 7])?;
    //                 offset += 7;
    //             }
                
    //             offset += 7;
        
    //             for i in 0..5 {
    //                 ask_prices[i] = parse_ascii_str_in_packet(&data_slice[offset..offset + 5])?;
    //                 offset += 5;
    //                 ask_quantities[i] = parse_ascii_str_in_packet(&data_slice[offset..offset + 7])?;
    //                 offset += 7;
    //             }
        
    //             offset += 50;
        
    //             // Direct byte parsing for time
    //             let time_bytes = &data_slice[offset..offset+8];
    //             if !time_bytes.iter().all(|&b| b.is_ascii_digit()) {
    //                 return Err(PcapError::NomError(time_bytes, ErrorKind::Verify));
    //             }
        
    //             let hours = (time_bytes[0] - b'0') as u32 * 10 + (time_bytes[1] - b'0') as u32;
    //             let minutes = (time_bytes[2] - b'0') as u32 * 10 + (time_bytes[3] - b'0') as u32;
    //             let seconds = (time_bytes[4] - b'0') as u32 * 10 + (time_bytes[5] - b'0') as u32;
    //             let centisecs = (time_bytes[6] - b'0') as u32 * 10 + (time_bytes[7] - b'0') as u32;
    //             let microseconds = centisecs * 10000;
        
    //             let quote_accept_time = NaiveTime::from_hms_micro_opt(hours, minutes, seconds, microseconds)
    //                 .ok_or(PcapError::NomError(time_bytes, ErrorKind::Verify))?;
        
    //             Ok(QuotePacket {
    //                 packet_time,
    //                 issue_code,
    //                 bid_prices,
    //                 bid_quantities,
    //                 ask_prices,
    //                 ask_quantities,
    //                 quote_accept_time,
    //                 ordering,
    //             })

    // }
    fn try_from(data:&PacketDataWithTime<'a>) -> Result<Self, Self::Error> {
            let (packet_time,data,ordering) = (data.packet_timestamp,&data.data,data.ordering);
            let data_slice = match data {
                PacketData::L2(d) => d,
                _ => return Err(PcapError::HeaderNotRecognized)
            };
            let mut offset = 42; //Packet data starts from the 42nd byte.
    
            let data_type = parse_ascii_str_in_packet(&data_slice[offset..offset+2])?;
            offset += 2;
    
            let information_type = parse_ascii_str_in_packet(&data_slice[offset..offset+2])?;
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
                let issue_code = parse_ascii_str_in_packet(&data_slice[offset..offset+12])?;
            
                offset += 24;
                
    
                let mut bid_prices = ["";N];
                let mut bid_quantities = ["";N];
                let mut ask_prices = ["";N];
                let mut ask_quantities = ["";N];
    
                for i in 0..5 {
    
                    // bid_prices.push(parse_ascii_str_in_packet(&data_slice[offset..offset + 5])?);
                    bid_prices[i] = parse_ascii_str_in_packet(&data_slice[offset..offset + 5])?;
                    offset += 5;
    
                    // bid_quantities.push(parse_ascii_str_in_packet(&data_slice[offset..offset + 5])?);
                    bid_quantities[i] = parse_ascii_str_in_packet(&data_slice[offset..offset + 7])?;
                    offset += 7;
                }
                
                offset += 7;
    
                for i in 0..5 {
                    // ask_prices.push(parse_ascii_str_in_packet(&data_slice[offset..offset+5])?.to_string());
                    ask_prices[i] = parse_ascii_str_in_packet(&data_slice[offset..offset + 5])?;
                    offset += 5;
                    // ask_quantities.push(parse_ascii_str_in_packet(&data_slice[offset..offset+7])?.to_string());
                    ask_quantities[i] = parse_ascii_str_in_packet(&data_slice[offset..offset + 7])?;
                    offset += 7;
                }
    
                offset += 50;
    
                
                let quote_accept_time_string = parse_ascii_str_in_packet(&data_slice[offset..offset+8])?.to_string();
    
                let hours = u32::from_str_radix(&quote_accept_time_string[0..2], 10).unwrap();
                let minutes = u32::from_str_radix(&quote_accept_time_string[2..4], 10).unwrap();
                let seconds = u32::from_str_radix(&quote_accept_time_string[4..6], 10).unwrap();
                let centisecs = u32::from_str_radix(&quote_accept_time_string[6..8], 10).unwrap();
                let microseconds = centisecs * 10000;
    
                let quote_accept_time = NaiveTime::from_hms_micro_opt(hours, minutes, seconds, microseconds).unwrap();
    
                Ok(QuotePacket {
                    packet_time,
                    issue_code,
                    bid_prices,
                    bid_quantities,
                    ask_prices,
                    ask_quantities,
                    quote_accept_time,
                    ordering,
                })
            }
        }
}


