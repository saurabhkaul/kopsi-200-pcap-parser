mod common;

use kopsi_200_pcap_parser::{read_pcap_file, PacketOrdering};

#[test]
fn test_read_pcap_default_ordering_is_correct() {
    let buf = read_pcap_file(common::fixture_path(), PacketOrdering::Default, Vec::new())
        .expect("should parse without error");
    let output = String::from_utf8(buf).expect("output should be valid UTF-8");

    let packet_times: Vec<&str> = output
        .lines()
        .map(|line| {
            line.split_ascii_whitespace()
                .next()
                .expect("each line should have a packet_time field")
        })
        .collect();

    assert!(!packet_times.is_empty(), "should have parsed at least one packet");

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
    let buf = read_pcap_file(
        common::fixture_path(),
        PacketOrdering::QuoteAcceptTime,
        Vec::new(),
    )
    .expect("should parse without error");
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
