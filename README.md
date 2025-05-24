# kopsi-200-pcap-parser
A pcap parser that extracts market data from kopsi 200 packets, in rust 🦀

To run this program, simply cd into dir and run

`cargo run --release` for default ordering of packets.

or pass the flag "-r" like

`cargo run --release --  -r`

_to order by quote accept time_

The kopsi 200 pcap file is in `test/fixtures`

This project was made as a submission for the coding challenege here https://www.tsurucapital.com/en/code-sample.html

To bench the code for both kinds of ordering, run
`sudo cargo bench --bench benchmark -- --verbose`

