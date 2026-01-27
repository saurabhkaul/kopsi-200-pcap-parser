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
  Time (mean ± σ):      13.8 ms ±   2.3 ms    [User: 11.4 ms, System: 5.1 ms]
  Range (min … max):     9.0 ms …  20.5 ms    146 runs

Benchmark 2: no-output-quote-time-order
  Time (mean ± σ):      18.1 ms ±   2.4 ms    [User: 16.7 ms, System: 5.6 ms]
  Range (min … max):    13.3 ms …  25.2 ms    124 runs

Summary
  no-output ran
    1.31 ± 0.28 times faster than no-output-quote-time-order
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
Time (mean ± σ):      85.1 ms ±  15.1 ms    [User: 13.3 ms, System: 21.3 ms]
  Range (min … max):    69.7 ms … 118.5 ms    39 runs

Benchmark 2: with-output-quote-time-ordering
Time (mean ± σ):     107.0 ms ±  21.6 ms    [User: 21.9 ms, System: 25.4 ms]
  Range (min … max):    75.8 ms … 143.4 ms    24 runs

Summary
  with-output ran
    1.11 ± 0.27 times faster than with-output-quote-time-ordering
```

### Performance Summary

**Best-case performance (minimum times, no Terminal I/O overhead):**
- Packet time ordering: 9.0 ms
- Quote accept time ordering: 13.3 ms

**Worst-case performance (minimum times, Terminal I/O overhead):**
- Packet time ordering: 69.7 ms
- Quote accept time ordering: 75.8 ms

### Architecture Summary + Perf Techniques Discussion. 
The architecture is very simple. We parse the file -> Collect packets -> Sort them by Quote Accept Time (if the optional flag is passed) -> Print them.

The parsing and printing logic has been separated into 2 threads to avoid blocking parsing & printing syscalls.

The other main objective was to remove all heap allocations, for this the heapless crate was used.

```
┌─────────────────────────────────────────────────────────────────────┐
│                           Main Thread                                │
│  ┌─────────────┐    ┌──────────────┐    ┌───────────────────────┐   │
│  │ File I/O    │───▶│ PCAP Parser  │───▶│ Packet Filter (B6034) │   │
│  │ BufReader   │    │ 64KB buffer  │    │ QuotePacket::try_from │   │
│  │ 64KB buffer │    │              │    │                       │   │
│  └─────────────┘    └──────────────┘    └───────────┬───────────┘   │
│                                                      │               │
│                                          mpsc::channel (unbounded)   │
│                                                      │               │
└──────────────────────────────────────────────────────┼───────────────┘
                                                       ▼
┌─────────────────────────────────────────────────────────────────────┐
│                          Print Thread                                │
│  ┌───────────────────┐    ┌─────────────┐    ┌─────────────────┐    │
│  │ HeaplessVec<512>  │───▶│ Sort Buffer │───▶│ BufWriter 64KB  │    │
│  │ (for -r flag)     │    │ (batch)     │    │ stdout          │    │
│  └───────────────────┘    └─────────────┘    └─────────────────┘    │
└─────────────────────────────────────────────────────────────────────┘
```

Two-thread pipeline:**
- **Parser thread**: Reads pcap, filters quote packets, sends via channel
- **Print thread**: Receives packets, optionally sorts by quote accept time, writes to stdout

**Zero-heap data structures:**
- `HeaplessString<N>` for fixed-size fields (issue code, prices, quantities)
- `HeaplessVec<QuotePacket, 512>` for sort buffer (stack-allocated)


Performance Techniques Discussion
1. Using direct byte writing instead of Display trait for QuotePackets, since fmt was taking more time.
2. Skipping utf8 validation but checking for ascii, which gives correct output and is faster. Not checking for ascii resulted in incorrect output.
3. Batch printing instead of printing every line, reducing as many print syscalls as possible.
4. Benching the full program with hyperfine and cargo flamegraph, analyzing the flamegraph, ideating fixes, validating with hyperfine - repeat.