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

Following are current benchmarks, where I am directly benching the binary using hyperfine.

1) Without outputting to terminal
```bash
hyperfine --warmup 3 --cleanup 'sleep 0.1' \
  -n 'no-output' './target/release/kopsi-200-pcap-parser > /dev/null' \
  -n 'no-output-quote-time-order' './target/release/kopsi-200-pcap-parser -r > /dev/null'
```

Benchmark 1: no-output
  Time (mean ± σ):      43.5 ms ±   3.0 ms    [User: 42.0 ms, System: 12.1 ms]
  Range (min … max):    37.7 ms …  50.5 ms    52 runs

Benchmark 2: no-output-quote-time-order
  Time (mean ± σ):      48.6 ms ±   2.9 ms    [User: 46.7 ms, System: 12.4 ms]
  Range (min … max):    44.5 ms …  57.1 ms    54 runs

Summary
  no-output ran
    1.12 ± 0.10 times faster than no-output-quote-time-order
    
2) With outputting to terminal (adds terminal printing overhead)
```bash
hyperfine --warmup 3 --cleanup 'sleep 0.1' --show-output \
  -n 'with-output' './target/release/kopsi-200-pcap-parser' \
  -n 'with-output-quote-time-ordering' './target/release/kopsi-200-pcap-parser -r'
```
Benchmark 1: with-output 
Time (mean ± σ):     159.2 ms ±  28.4 ms    [User: 45.0 ms, System: 27.8 ms]
  Range (min … max):    98.4 ms … 188.3 ms    21 runs
  
Benchmark 2: with-output-quote-time-ordering
Time (mean ± σ):     158.1 ms ±  28.1 ms    [User: 53.4 ms, System: 29.3 ms]
  Range (min … max):   107.6 ms … 196.8 ms    15 runs

Summary (Generated for both)
  with-output-quote-time-ordering ran
    1.04 ± 0.24 times faster than with-output
    
    
Basically without outputting to terminal (least overhead) we are getting 37.7ms and 44.5ms for both workloads.