mod common;

use chrono::{DateTime, Duration, NaiveTime};
use kopsi_200_pcap_parser::{read_pcap_file, PacketOrdering, PCAP_FILE_PATH};
use pcap_parser::data::{get_packetdata, PacketData};
use pcap_parser::{create_reader, PcapBlockOwned, PcapError};
use std::cmp::Ordering;
use std::fs::File;
use std::io::BufReader;

#[test]
fn test_read_pcap_default_ordering_is_correct() {
    let buf = common::parser_output(&[]);
    let output = String::from_utf8(buf).expect("output should be valid UTF-8");

    let packet_times: Vec<&str> = output
        .lines()
        .map(|line| {
            line.split_ascii_whitespace()
                .next()
                .expect("each line should have a packet_time field")
        })
        .collect();

    assert!(
        !packet_times.is_empty(),
        "should have parsed at least one packet"
    );

    for window in packet_times.windows(2) {
        assert!(
            window[0] <= window[1],
            "packet times out of order: {} > {}",
            window[0],
            window[1]
        );
    }
}

#[test]
fn test_read_pcap_quote_accept_time_ordering_is_correct() {
    let buf = common::parser_output(&["-r"]);
    let output = String::from_utf8(buf).expect("output should be valid UTF-8");

    let quote_accept_times: Vec<&str> = output
        .lines()
        .map(|line| {
            let mut fields = line.split_ascii_whitespace();
            fields.next(); // skip packet_time
            fields
                .next()
                .expect("each line should have a quote_accept_time field")
        })
        .collect();

    assert!(
        !quote_accept_times.is_empty(),
        "should have parsed at least one packet"
    );

    for window in quote_accept_times.windows(2) {
        assert!(
            window[0] <= window[1],
            "quote accept times out of order: {} > {}",
            window[0],
            window[1]
        );
    }
}

#[test]
fn test_read_pcap_nonexistent_file_returns_error() {
    let result = read_pcap_file(
        std::path::PathBuf::from("nonexistent.pcap"),
        PacketOrdering::Default,
        Vec::new(),
    );
    assert!(result.is_err());
}

#[derive(Debug, Eq, PartialEq)]
struct QuotePacket {
    packet_time: NaiveTime,
    quote_accept_time: NaiveTime,
    /// counter used as a tie breaker
    packet_sequence: usize,
    issue_code: String,
    bid_prices: Vec<String>,
    bid_quantities: Vec<String>,
    ask_prices: Vec<String>,
    ask_quantities: Vec<String>,
}

impl Ord for QuotePacket {
    fn cmp(&self, other: &Self) -> Ordering {
        (self.quote_accept_time, self.packet_sequence)
            .cmp(&(other.quote_accept_time, other.packet_sequence))
    }
}

impl PartialOrd for QuotePacket {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

fn two_digits(b: &[u8]) -> u32 {
    assert!(b.len() == 2);
    assert!(b[0].is_ascii_digit() && b[1].is_ascii_digit());
    (b[0] - b'0') as u32 * 10 + (b[1] - b'0') as u32
}

fn ascii_field(data: &[u8], range: std::ops::Range<usize>) -> String {
    std::str::from_utf8(&data[range])
        .expect("quote field should be ASCII")
        .to_owned()
}

fn packet_time_kst(ts_sec: u32, ts_usec: u32) -> NaiveTime {
    let utc = DateTime::from_timestamp(ts_sec as i64, ts_usec * 1000)
        .expect("pcap timestamp should be valid");
    (utc.naive_utc() + Duration::hours(9)).time()
}

fn quote_accept_time(data: &[u8]) -> NaiveTime {
    let hh = two_digits(&data[206..208]);
    let mm = two_digits(&data[208..210]);
    let ss = two_digits(&data[210..212]);
    let cc = two_digits(&data[212..214]);
    NaiveTime::from_hms_micro_opt(hh, mm, ss, cc * 10_000)
        .expect("quote accept time should be valid")
}

fn quote_packet_from_payload(
    ts_sec: u32,
    ts_usec: u32,
    packet_sequence: usize,
    data: &[u8],
) -> Option<QuotePacket> {
    if data.len() < 215 || &data[..5] != b"B6034" {
        return None;
    }

    let mut bid_prices = Vec::with_capacity(5);
    let mut bid_quantities = Vec::with_capacity(5);
    for i in 0..5usize {
        bid_prices.push(ascii_field(data, 29 + i * 12..34 + i * 12));
        bid_quantities.push(ascii_field(data, 34 + i * 12..41 + i * 12));
    }

    let mut ask_prices = Vec::with_capacity(5);
    let mut ask_quantities = Vec::with_capacity(5);
    for i in 0..5usize {
        ask_prices.push(ascii_field(data, 96 + i * 12..101 + i * 12));
        ask_quantities.push(ascii_field(data, 101 + i * 12..108 + i * 12));
    }

    Some(QuotePacket {
        packet_time: packet_time_kst(ts_sec, ts_usec),
        quote_accept_time: quote_accept_time(data),
        packet_sequence,
        issue_code: ascii_field(data, 5..17).trim_end().to_owned(),
        bid_prices,
        bid_quantities,
        ask_prices,
        ask_quantities,
    })
}

impl QuotePacket {
    fn output_line(&self) -> String {
        let mut line = format!(
            "{} {} {}",
            self.packet_time.format("%H:%M:%S%.3f"),
            self.quote_accept_time.format("%H:%M:%S%.3f"),
            self.issue_code
        );

        for i in (0..5usize).rev() {
            line.push_str(&format!(
                " {}@{}",
                self.bid_quantities[i], self.bid_prices[i]
            ));
        }

        for i in 0..5usize {
            line.push_str(&format!(
                " {}@{}",
                self.ask_quantities[i], self.ask_prices[i]
            ));
        }

        line
    }
}

fn reference_quote_accept_time_output() -> Vec<String> {
    let file = File::open(PCAP_FILE_PATH).expect("fixture should open");
    let reader = BufReader::new(file);
    let mut pcap_reader = create_reader(64 * 1024, reader).expect("pcap reader should initialize");
    let mut linktype = None;
    let mut packet_sequence = 0usize;
    let mut packets = Vec::new();

    loop {
        match pcap_reader.next() {
            Ok((offset, block)) => {
                match block {
                    PcapBlockOwned::LegacyHeader(header) => {
                        linktype = Some(header.network);
                    }
                    PcapBlockOwned::Legacy(packet) => {
                        let network = linktype.expect("legacy pcap header should appear first");
                        if let Some(PacketData::L2(frame)) =
                            get_packetdata(packet.data, network, packet.caplen as usize)
                        {
                            if frame.len() >= 42 {
                                let payload = &frame[42..];
                                if let Some(packet) = quote_packet_from_payload(
                                    packet.ts_sec,
                                    packet.ts_usec,
                                    packet_sequence,
                                    payload,
                                ) {
                                    packets.push(packet);
                                }
                            }
                        }
                        packet_sequence += 1;
                    }
                    PcapBlockOwned::NG(_) => panic!("fixture should be a legacy pcap"),
                }
                pcap_reader.consume(offset);
            }
            Err(PcapError::Eof) => break,
            Err(PcapError::Incomplete(_)) => pcap_reader.refill().expect("pcap refill should work"),
            Err(err) => panic!("pcap parse error: {err:?}"),
        }
    }

    packets.sort();

    packets
        .into_iter()
        .map(|packet| packet.output_line())
        .collect()
}

//Test our performance parser against a simple parser and compare outputs
#[test]
fn test_has_file_been_parsed_and_sorted_correctly() {
    let actual = String::from_utf8(common::parser_output(&["-r"]))
        .expect("optimized output should be valid UTF-8");
    let actual_lines: Vec<&str> = actual.lines().collect();
    let expected = reference_quote_accept_time_output();

    assert_eq!(actual_lines.len(), expected.len());

    for (line_number, (actual, expected)) in actual_lines.iter().zip(expected.iter()).enumerate() {
        assert_eq!(
            *actual,
            expected,
            "parsed quote output differs at line {}",
            line_number + 1
        );
    }
}
