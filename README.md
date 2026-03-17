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
  Time (mean ± σ):      22.6 ms ±   3.9 ms    [User: 16.3 ms, System: 10.6 ms]
  Range (min … max):    11.7 ms …  31.9 ms    157 runs

Benchmark 2: no-output-quote-time-order
  Time (mean ± σ):      28.8 ms ±   4.2 ms    [User: 23.2 ms, System: 11.4 ms]
  Range (min … max):    19.2 ms …  36.2 ms    82 runs

Summary
  no-output ran
    1.27 ± 0.28 times faster than no-output-quote-time-order
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
Time (mean ± σ):     124.6 ms ±   2.5 ms    [User: 20.7 ms, System: 35.5 ms]
  Range (min … max):   120.2 ms … 128.3 ms    23 runs

Benchmark 2: with-output-quote-time-ordering
Time (mean ± σ):     133.0 ms ±   3.2 ms    [User: 30.9 ms, System: 35.1 ms]
  Range (min … max):   129.4 ms … 139.3 ms    21 runs

Summary
  with-output ran
    1.11 ± 0.27 times faster than with-output-quote-time-ordering
```

### Performance Summary

**Best-case performance (minimum times, no Terminal I/O overhead):**
- Packet time ordering: 11.7 ms
- Quote accept time ordering: 19.2 ms

**Worst-case performance (minimum times, Terminal I/O overhead):**
- Packet time ordering: 120.2 ms
- Quote accept time ordering: 129.4 ms

### Architecture Summary + Perf Techniques Discussion.
The architecture is very simple. We parse the file -> filter B6034 packets -> optionally sort by quote accept time -> print.

Parsing and printing are on separate threads so file I/O and stdout writes don't block each other.

The goal was to avoid heap allocations. `HeaplessString<N>` covers the fixed-width fields. The sort buffer is a custom stack-allocated sliding window described below.

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
│  ┌──────────────────────────┐    ┌─────────────────┐                │
│  │ SlidingWindowBuffer      │───▶│ BufWriter 64KB  │                │
│  │ (stack, insertion-sorted │    │ stdout          │                │
│  │  for -r flag)            │    │                 │                │
│  └──────────────────────────┘    └─────────────────┘                │
└─────────────────────────────────────────────────────────────────────┘
```

**Two-thread pipeline:**
- **Parser thread**: Reads pcap, filters quote packets, sends via channel
- **Print thread**: Receives packets, optionally sorts by quote accept time, writes to stdout

**Stack-based data structures:**
- `HeaplessString<N>` for fixed-size fields (issue code, prices, quantities)
- `SlidingWindowBuffer` — a custom stack-allocated array (`[MaybeUninit<QuotePacket>; 7000]`) with `head` and `len` tracking. New packets are inserted in sorted order via binary search. Flushing advances the `head` integer — no data is ever moved. Compaction (one `memmove` back to slot 0) happens at most once per 3500 inserts.

**Quote accept time sorting:**

The challenge guarantees `|quote_accept_time - packet_time| <= 3s`. Since the pcap is in packet_time order, any packet arriving with `packet_time = T` means all future packets have `quote_accept_time >= T - 3s`. So buffered packets with `quote_accept_time < T - 3s` are safe to flush — no future packet can sort before them.

Each incoming packet is inserted into the buffer via binary search to maintain sorted order. Because `quote_accept_time ≈ packet_time` and packets arrive in packet_time order, the insertion point is almost always at the tail. The binary search finds it in O(log n) with zero elements to shift. When the flush threshold is crossed, the already-sorted prefix is written out and `head` is advanced.


Performance Techniques Discussion
1. Using direct byte writing instead of Display trait for QuotePackets, since fmt was taking more time.
2. Skipping utf8 validation but checking for ascii, which gives correct output and is faster. Not checking for ascii resulted in incorrect output.
3. Batch printing instead of printing every line, reducing as many print syscalls as possible.
4. Benching the full program with hyperfine and cargo flamegraph, analyzing the flamegraph, ideating fixes, validating with hyperfine - repeat.