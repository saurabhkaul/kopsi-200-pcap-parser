mod common;

use kopsi_200_pcap_parser::{read_pcap_file, PacketOrdering};

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


//Writing a simple non performant parser that we are sure is correct and we match it with current implementation's results
#[test]
fn test_has_file_been_parsed_and_sorted_correctly(){
    let buf = common::parser_output(&["-r"]);
    struct Packet{
        
    }
    
    
}
