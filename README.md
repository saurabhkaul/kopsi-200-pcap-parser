# kopsi-200-pcap-parser
A pcap parser that extracts market data from kopsi 200 packets, in rust 🦀

To run this program, simply cd into dir and run

`cargo run --release` for default ordering of packets.

or

`cargo run --release --  -r`

to order by quote accept time

The kopsi 200 pcap file is in `test/fixtures`  
