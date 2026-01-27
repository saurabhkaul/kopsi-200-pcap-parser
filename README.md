# kopsi-200-pcap-parser

A pcap parser that extracts market data from KOSPI 200 packets, written in Rust.

This is a submission for a hiring challenge by Tsuru Capital. Challenge details: https://www.tsurucapital.com/en/code-sample.html

## Running the Program

The KOSPI 200 pcap file is located in `test/fixtures`.

**Default ordering (by packet time):**
```bash
cargo run --release
```

**Order by quote accept time:**
```bash
cargo run --release -- -r
```

## Benchmarking

### Using Criterion
```bash
sudo cargo bench --bench benchmark -- --verbose
```

### Using Hyperfine

The following benchmarks compare both ordering modes using hyperfine to measure the binary directly.

#### 1. Without Terminal Output (No Terminal Printing Overhead)
```bash
hyperfine --warmup 3 --cleanup 'sleep 0.1' \
  -n 'no-output' './target/release/kopsi-200-pcap-parser > /dev/null' \
  -n 'no-output-quote-time-order' './target/release/kopsi-200-pcap-parser -r > /dev/null'
```

**Results:**
```
Benchmark 1: no-output
  Time (mean ± σ):      21.4 ms ±   2.7 ms    [User: 19.5 ms, System: 8.6 ms]
  Range (min … max):    15.7 ms …  27.8 ms    117 runs

Benchmark 2: no-output-quote-time-order
  Time (mean ± σ):      19.8 ms ±   2.7 ms    [User: 21.8 ms, System: 6.0 ms]
  Range (min … max):    14.5 ms …  28.2 ms    133 runs

Summary
  no-output-quote-time-order ran
    1.08 ± 0.20 times faster than no-output
```

#### 2. With Terminal Output (Terminal Printing Overhead)
```bash
hyperfine --warmup 3 --cleanup 'sleep 0.1' --show-output \
  -n 'with-output' './target/release/kopsi-200-pcap-parser' \
  -n 'with-output-quote-time-ordering' './target/release/kopsi-200-pcap-parser -r'
```

**Results:**
```
Benchmark 1: with-output
Time (mean ± σ):      93.4 ms ±  16.4 ms    [User: 18.2 ms, System: 22.1 ms]
  Range (min … max):    75.6 ms … 123.6 ms    34 runs

Benchmark 2: with-output-quote-time-ordering
Time (mean ± σ):      98.4 ms ±  17.4 ms    [User: 24.5 ms, System: 21.1 ms]
  Range (min … max):    73.6 ms … 124.9 ms    25 runs

Summary
with-output ran
  1.14 ± 0.26 times faster than with-output-quote-time-ordering
```

### Performance Summary

**Best-case performance (minimum times, no Terminal I/O overhead):**
- Packet time ordering: 15.7 ms
- Quote accept time ordering: 14.5 ms

**Worst-case performance (minimum times, Terminal I/O overhead):**
- Packet time ordering: 75.6 ms
- Quote accept time ordering: 73.6 ms

