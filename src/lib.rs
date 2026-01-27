pub use packet::{read_pcap_file, PacketOrdering};
use std::path::PathBuf;

pub const PCAP_FILE_PATH: &str = "test/fixtures/mdf-kospi200.20110216-0.pcap 2";

pub fn runner() -> Result<(), Box<dyn std::error::Error>> {
    let is_quote_time_ordering = std::env::args().any(|arg| arg == "-r");
    let ordering = match is_quote_time_ordering {
        true => PacketOrdering::QuoteAcceptTime,
        false => PacketOrdering::Default,
    };
    read_pcap_file(PathBuf::from(PCAP_FILE_PATH), ordering)?;

    Ok(())
}
