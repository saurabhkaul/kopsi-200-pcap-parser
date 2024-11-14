use std::collections::BinaryHeap;
use std::path::PathBuf;
use tokio::io::stdout;
use tokio::io::AsyncWriteExt;
use tokio::io::BufWriter;


pub const PCAP_FILE_PATH: &str = "test/fixtures/mdf-kospi200.20110216-0.pcap 2";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let stdout = stdout();
    let buffer_size = 128 * 1024; //128kb buffer size

    let is_quote_time_ordering =  args.contains(&"-r".to_string());

    let quote_packets = packet::read_pcap_file(PathBuf::from(PCAP_FILE_PATH)).await?;

    let mut writer = BufWriter::with_capacity(buffer_size, stdout);


    match is_quote_time_ordering {
        true => {
            let mut min_heap = BinaryHeap::from(quote_packets);
            while let Some(packet) = min_heap.pop() {
                writer.write_all(format!("{}\n", packet).as_bytes()).await?;
            }
        }
        false => {
            for packet in quote_packets {
                writer.write_all(format!("{}\n", packet).as_bytes()).await?;
            }
        }
    }

    writer.flush().await?;
    Ok(())
}