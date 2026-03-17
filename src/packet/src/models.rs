use anyhow::Result;
use chrono::{NaiveTime, Timelike};
use core::fmt::Write as FmtWrite;
use heapless::String as HeaplessString;
use nom::error::ErrorKind;
use pcap_parser::data::PacketData;
use pcap_parser::PcapError;
use std::cmp::Ordering;
use std::io::Write;
use std::{fmt, str};

const PACKET_IDENTIFIER: &str = "B6034";

pub struct PacketDataWithTime<'a> {
    pub data: PacketData<'a>,
    pub packet_timestamp: NaiveTime,
    pub ordering: PacketOrdering,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum PacketOrdering {
    Default,
    QuoteAcceptTime,
}

#[derive(Debug, Eq, Clone)]
pub struct QuotePacket {
    packet_time: NaiveTime,
    issue_code: HeaplessString<12>,
    bid_prices: [HeaplessString<5>; 5],
    bid_quantities: [HeaplessString<7>; 5],
    ask_prices: [HeaplessString<5>; 5],
    ask_quantities: [HeaplessString<7>; 5],
    quote_accept_time: NaiveTime,
    ordering: PacketOrdering,
}

//Old formatting machinery that I'm keeping around
// impl fmt::Display for QuotePacket {
//     fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
//         write!(
//             f,
//             "{} {} {}",
//             self.packet_time.format("%H:%M:%S%.3f"),
//             self.quote_accept_time,
//             self.issue_code
//         )?;

//         for i in (0..5).rev() {
//             write!(
//                 f,
//                 " {}@{}",
//                 self.bid_quantities.get(i).unwrap(),
//                 self.bid_prices.get(i).unwrap()
//             )?;
//         }

//         for i in 0..5 {
//             write!(
//                 f,
//                 " {}@{}",
//                 self.ask_quantities.get(i).unwrap(),
//                 self.ask_prices.get(i).unwrap()
//             )?;
//         }
//         Ok(())
//     }
// }

impl QuotePacket {
    pub fn packet_time(&self) -> NaiveTime { self.packet_time }
    pub fn quote_accept_time(&self) -> NaiveTime { self.quote_accept_time }

    /// Fast direct write to a byte buffer, bypassing fmt machinery.
    #[inline]
    pub fn write_to<W: Write>(&self, w: &mut W) -> std::io::Result<()> {
        let mut buf = [0u8; 256]; // Stack buffer for the entire line
        let mut pos = 0;

        // Write packet_time as HH:MM:SS.mmm
        pos += write_time_millis(&mut buf[pos..], self.packet_time);
        buf[pos] = b' ';
        pos += 1;

        // Write quote_accept_time as HH:MM:SS.mmmmmm
        pos += write_time_millis(&mut buf[pos..], self.quote_accept_time);
        buf[pos] = b' ';
        pos += 1;

        // Write issue_code
        let issue_bytes = self.issue_code.as_bytes();
        buf[pos..pos + issue_bytes.len()].copy_from_slice(issue_bytes);
        pos += issue_bytes.len();

        // Write bid quantities and prices (reverse order)
        for i in (0..5).rev() {
            buf[pos] = b' ';
            pos += 1;
            let qty = self.bid_quantities[i].as_bytes();
            buf[pos..pos + qty.len()].copy_from_slice(qty);
            pos += qty.len();
            buf[pos] = b'@';
            pos += 1;
            let price = self.bid_prices[i].as_bytes();
            buf[pos..pos + price.len()].copy_from_slice(price);
            pos += price.len();
        }

        // Write ask quantities and prices
        for i in 0..5 {
            buf[pos] = b' ';
            pos += 1;
            let qty = self.ask_quantities[i].as_bytes();
            buf[pos..pos + qty.len()].copy_from_slice(qty);
            pos += qty.len();
            buf[pos] = b'@';
            pos += 1;
            let price = self.ask_prices[i].as_bytes();
            buf[pos..pos + price.len()].copy_from_slice(price);
            pos += price.len();
        }

        buf[pos] = b'\n';
        pos += 1;

        w.write_all(&buf[..pos])
    }
}

/// Write time as HH:MM:SS.mmm (milliseconds) - 12 bytes
#[inline(always)]
fn write_time_millis(buf: &mut [u8], time: NaiveTime) -> usize {
    let h = time.hour();
    let m = time.minute();
    let s = time.second();
    let ms = time.nanosecond() / 1_000_000;

    buf[0] = b'0' + (h / 10) as u8;
    buf[1] = b'0' + (h % 10) as u8;
    buf[2] = b':';
    buf[3] = b'0' + (m / 10) as u8;
    buf[4] = b'0' + (m % 10) as u8;
    buf[5] = b':';
    buf[6] = b'0' + (s / 10) as u8;
    buf[7] = b'0' + (s % 10) as u8;
    buf[8] = b'.';
    buf[9] = b'0' + (ms / 100) as u8;
    buf[10] = b'0' + ((ms / 10) % 10) as u8;
    buf[11] = b'0' + (ms % 10) as u8;
    12
}

/// Write time as HH:MM:SS.mmmmmm (microseconds) - 15 bytes
#[inline(always)]
fn write_time_micros(buf: &mut [u8], time: NaiveTime) -> usize {
    let h = time.hour();
    let m = time.minute();
    let s = time.second();
    let us = time.nanosecond() / 1_000;

    buf[0] = b'0' + (h / 10) as u8;
    buf[1] = b'0' + (h % 10) as u8;
    buf[2] = b':';
    buf[3] = b'0' + (m / 10) as u8;
    buf[4] = b'0' + (m % 10) as u8;
    buf[5] = b':';
    buf[6] = b'0' + (s / 10) as u8;
    buf[7] = b'0' + (s % 10) as u8;
    buf[8] = b'.';
    // 6 digits for microseconds
    buf[9] = b'0' + (us / 100000) as u8;
    buf[10] = b'0' + ((us / 10000) % 10) as u8;
    buf[11] = b'0' + ((us / 1000) % 10) as u8;
    buf[12] = b'0' + ((us / 100) % 10) as u8;
    buf[13] = b'0' + ((us / 10) % 10) as u8;
    buf[14] = b'0' + (us % 10) as u8;
    15
}

impl PartialEq<Self> for QuotePacket {
    fn eq(&self, other: &Self) -> bool {
        self.quote_accept_time == other.quote_accept_time
    }
}

impl Ord for QuotePacket {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.ordering {
            PacketOrdering::Default => self.packet_time.cmp(&other.packet_time),
            PacketOrdering::QuoteAcceptTime => self.quote_accept_time.cmp(&other.quote_accept_time),
        }
    }
}

impl PartialOrd<Self> for QuotePacket {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[inline(always)]
fn parse_ascii_str_in_packet(slice: &[u8]) -> Result<&str, PcapError<&[u8]>> {
    // ASCII check is faster than full UTF-8 validation, and ASCII is valid UTF-8
    if slice.is_ascii() {
        // SAFETY: ASCII bytes are always valid UTF-8
        Ok(unsafe { std::str::from_utf8_unchecked(slice) })
    } else {
        Err(PcapError::NomError(slice, ErrorKind::Verify))
    }
}

impl<'a> TryFrom<&'a PacketDataWithTime<'a>> for QuotePacket {
    type Error = PcapError<&'a [u8]>;

    fn try_from(data: &'a PacketDataWithTime<'a>) -> Result<Self, Self::Error> {
        let (packet_time, data, ordering) = (data.packet_timestamp, &data.data, data.ordering);
        let data_slice = match data {
            PacketData::L2(d) => d,
            _ => return Err(PcapError::HeaderNotRecognized),
        };
        let mut offset = 42; //Packet data starts from the 42nd byte.

        let data_type = parse_ascii_str_in_packet(&data_slice[offset..offset + 2])?;
        offset += 2;

        let information_type = parse_ascii_str_in_packet(&data_slice[offset..offset + 2])?;
        offset += 2;

        let market_type = data_slice[offset] as char;
        offset += 1;

        let mut packet_identifier = HeaplessString::<32>::new();
        let _ = write!(
            &mut packet_identifier,
            "{}{}{}",
            data_type, information_type, market_type
        )
        .map_err(|_| PcapError::NomError(data_slice, ErrorKind::TooLarge));

        if packet_identifier != PACKET_IDENTIFIER {
            return Err(PcapError::NomError(&data_slice[..offset], ErrorKind::IsNot));
        } else {
            let issue_code: HeaplessString<12> = HeaplessString::try_from(
                parse_ascii_str_in_packet(&data_slice[offset..offset + 12])?,
            )
            .map_err(|_| {
                PcapError::NomError(&data_slice[offset..offset + 12], ErrorKind::Verify)
            })?;
            offset += 24;

            let mut bid_prices: [HeaplessString<5>; 5] = Default::default();
            let mut bid_quantities: [HeaplessString<7>; 5] = Default::default();
            let mut ask_prices: [HeaplessString<5>; 5] = Default::default();
            let mut ask_quantities: [HeaplessString<7>; 5] = Default::default();

            for i in 0..5 {
                let bid_price_str = parse_ascii_str_in_packet(&data_slice[offset..offset + 5])?;
                bid_prices[i] = HeaplessString::try_from(bid_price_str).map_err(|_| {
                    PcapError::NomError(&data_slice[offset..offset + 5], ErrorKind::Verify)
                })?;
                offset += 5;

                let bid_quantity_str = parse_ascii_str_in_packet(&data_slice[offset..offset + 7])?;
                bid_quantities[i] = HeaplessString::try_from(bid_quantity_str).map_err(|_| {
                    PcapError::NomError(&data_slice[offset..offset + 7], ErrorKind::Verify)
                })?;
                offset += 7;
            }

            offset += 7;

            for i in 0..5 {
                let ask_price_str = parse_ascii_str_in_packet(&data_slice[offset..offset + 5])?;
                ask_prices[i] = HeaplessString::try_from(ask_price_str).map_err(|_| {
                    PcapError::NomError(&data_slice[offset..offset + 5], ErrorKind::Verify)
                })?;
                offset += 5;

                let ask_quantity_str = parse_ascii_str_in_packet(&data_slice[offset..offset + 7])?;
                ask_quantities[i] = HeaplessString::try_from(ask_quantity_str).map_err(|_| {
                    PcapError::NomError(&data_slice[offset..offset + 7], ErrorKind::Verify)
                })?;
                offset += 7;
            }

            offset += 50;

            let quote_accept_time_string =
                parse_ascii_str_in_packet(&data_slice[offset..offset + 8])?;

            let hours = u32::from_str_radix(&quote_accept_time_string[0..2], 10).unwrap();
            let minutes = u32::from_str_radix(&quote_accept_time_string[2..4], 10).unwrap();
            let seconds = u32::from_str_radix(&quote_accept_time_string[4..6], 10).unwrap();
            let centiseconds = u32::from_str_radix(&quote_accept_time_string[6..8], 10).unwrap();
            let microseconds = centiseconds * 10000;

            let quote_accept_time =
                NaiveTime::from_hms_micro_opt(hours, minutes, seconds, microseconds).unwrap();

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
