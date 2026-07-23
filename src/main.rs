use kopsi_200_pcap_parser::{read_pcap_file, PacketOrdering, PCAP_FILE_PATH};
use std::{
    env,
    io::{self, BufWriter},
};

fn main() -> io::Result<()> {
    let ordering = if env::args().any(|arg| arg == "-r") {
        PacketOrdering::QuoteAcceptTime
    } else {
        PacketOrdering::Default
    };

    read_pcap_file(
        PCAP_FILE_PATH,
        ordering,
        BufWriter::with_capacity(3 * 1024 * 1024, io::stdout()),
    )
    .map(|_| ())
}
