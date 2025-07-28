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

On my 2019 16' Intel Macbook Pro, I'm achieving 16.719ms mean and 17.344ms median benchmark time on parsing the packet file with quote time ordering. Previous benches and their commits are mentioned below.


|commit                                  | mean bench | median bench |
| :-----------------------------------:  | :------:  | :----: |
|[7e473cf05132de90681f66b4c8103def01e95ac2](https://github.com/saurabhkaul/kopsi-200-pcap-parser/commit/7e473cf05132de90681f66b4c8103def01e95ac2)| 30.775 ms | 30.354 ms |
|[9bdbf7547a878509770a7a23141744b88bb93936](https://github.com/saurabhkaul/kopsi-200-pcap-parser/commit/9bdbf7547a878509770a7a23141744b88bb93936)| 79.885 ms | 80.197 ms |
|[f01ae1ec9caa8fe091c0ce2a2827095d97b535ca](https://github.com/saurabhkaul/kopsi-200-pcap-parser/commit/f01ae1ec9caa8fe091c0ce2a2827095d97b535ca)| 120.08 ms | 118.96 ms |


