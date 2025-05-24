pub use packet::{read_pcap_file, PacketOrdering};
use std::path::PathBuf;

pub const PCAP_FILE_PATH: &str = "test/fixtures/mdf-kospi200.20110216-0.pcap 2";

pub fn runner() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let is_quote_time_ordering = args.contains(&"-r".to_string());

    let ordering = match is_quote_time_ordering {
        true => PacketOrdering::QuoteAcceptTime,
        false => PacketOrdering::Default,
    };
    read_pcap_file(PathBuf::from(PCAP_FILE_PATH), ordering)?;

    // let quote_packets = packet::read_pcap_file(PathBuf::from(PCAP_FILE_PATH))?;

    // let mut writer = BufWriter::with_capacity(buffer_size, stdout);

    // match is_quote_time_ordering {
    //     true => {
    //         let mut min_heap = BinaryHeap::from(quote_packets);
    //         while let Some(packet) = min_heap.pop() {
    //             writer.write_all(format!("{}\n", packet).as_bytes())?;
    //         }
    //     }
    //     false => {
    //         for packet in quote_packets {
    //             writer.write_all(format!("{}\n", packet).as_bytes())?;
    //         }
    //     }
    // }

    // writer.flush()?;
    Ok(())
}
