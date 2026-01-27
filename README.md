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
  Time (mean ± σ):      43.5 ms ±   3.0 ms    [User: 42.0 ms, System: 12.1 ms]
  Range (min … max):    37.7 ms …  50.5 ms    52 runs

Benchmark 2: no-output-quote-time-order
  Time (mean ± σ):      48.6 ms ±   2.9 ms    [User: 46.7 ms, System: 12.4 ms]
  Range (min … max):    44.5 ms …  57.1 ms    54 runs

Summary
  no-output ran 1.12 ± 0.10 times faster than no-output-quote-time-order
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
  Time (mean ± σ):     159.2 ms ±  28.4 ms    [User: 45.0 ms, System: 27.8 ms]
  Range (min … max):    98.4 ms … 188.3 ms    21 runs

Benchmark 2: with-output-quote-time-ordering
  Time (mean ± σ):     158.1 ms ±  28.1 ms    [User: 53.4 ms, System: 29.3 ms]
  Range (min … max):   107.6 ms … 196.8 ms    15 runs

Summary
  with-output-quote-time-ordering ran 1.04 ± 0.24 times faster than with-output
```

### Performance Summary

**Best-case performance (minimum times, no I/O overhead):**
- Packet time ordering: 37.7 ms
- Quote accept time ordering: 44.5 ms