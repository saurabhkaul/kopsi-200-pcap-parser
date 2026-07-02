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
cargo bench --bench benchmark -- --quiet
```

Criterion measures the library path in-process, so it excludes binary startup and shell/process scheduling overhead.

**Latest results:**

```text
read_pcap_file/default_to_vec
  9.43-9.60 ms

read_pcap_file/quote_accept_time_to_vec
  12.40-12.70 ms

read_pcap_file/default_to_sink
  8.23-8.47 ms

read_pcap_file/quote_accept_time_to_sink
  9.24-9.52 ms
```

The benchmark also includes phase-level timings for the current parser:

```text
open_mmap
  28.9-29.8 us

find_validate_packets
  1.46-1.54 ms

format_rows
  3.42-3.65 ms

sort_and_write_to_vec
  2.12-2.27 ms
```

### Using Hyperfine

Hyperfine measures the full binary, including process startup, dynamic linking, file open/mmap, stdout setup, and OS scheduling. It is useful for end-to-end wall time, but it is not a clean parser-only measurement.

#### Without Terminal Output
```bash
cargo build --release

hyperfine --warmup 10 --runs 50 \
  --prepare 'cat target/release/kopsi-200-pcap-parser "test/fixtures/mdf-kospi200.20110216-0.pcap 2" > /dev/null' \
  './target/release/kopsi-200-pcap-parser > /dev/null' \
  './target/release/kopsi-200-pcap-parser -r > /dev/null'
```

**Latest results:**
```
Benchmark 1: ./target/release/kopsi-200-pcap-parser > /dev/null
  Time (mean ± σ):      21.7 ms ±   9.3 ms    [User: 10.0 ms, System: 9.2 ms]
  Range (min … max):     5.0 ms …  40.4 ms    50 runs

Benchmark 2: ./target/release/kopsi-200-pcap-parser -r > /dev/null
  Time (mean ± σ):      27.5 ms ±   2.5 ms    [User: 13.4 ms, System: 11.2 ms]
  Range (min … max):    22.2 ms …  33.9 ms    50 runs

Summary
  ./target/release/kopsi-200-pcap-parser > /dev/null ran
    1.27 ± 0.56 times faster than ./target/release/kopsi-200-pcap-parser -r > /dev/null
```

#### With Terminal Output
```bash
hyperfine --warmup 3 --runs 10 --show-output \
  -n default './target/release/kopsi-200-pcap-parser' \
  -n quote-time './target/release/kopsi-200-pcap-parser -r'
```

Terminal rendering is much slower than redirecting to `/dev/null`, so these numbers are mostly terminal I/O behavior rather than parser behavior.

**Latest Ghostty results:**

```text
Benchmark 1: default
  Time (mean +/- sigma):      70.2 ms +/- 8.5 ms    [User: 5.9 ms, System: 5.2 ms]
  Range (min ... max):        60.3 ms ... 86.2 ms    10 runs

Benchmark 2: quote-time
  Time (mean +/- sigma):      76.5 ms +/- 6.4 ms    [User: 8.5 ms, System: 5.8 ms]
  Range (min ... max):        64.8 ms ... 88.3 ms    10 runs

Summary
  default ran
    1.09 +/- 0.16 times faster than quote-time
```

### Performance Summary

**In-process parser performance:**
- Packet time ordering: about 8-10 ms
- Quote accept time ordering: about 9-10 ms when writing to a sink, about 12-13 ms when collecting reordered output into a `Vec<u8>`

**End-to-end binary wall time:**
- Packet time ordering: highly variable, about 21.7 ms mean in the latest hyperfine run
- Quote accept time ordering: about 27.5 ms mean in the latest hyperfine run

**Ghostty terminal-rendering wall time:**
- Packet time ordering: about 70.2 ms mean
- Quote accept time ordering: about 76.5 ms mean

### Architecture Summary + Perf Techniques Discussion.

1. Memory-map the fixture pcap with `memmap2`.
2. Use `memchr::memmem::Finder` to locate quote packets beginning with `B6034`.
3. Validate the surrounding pcap record length.
4. Format rows into one byte buffer using direct byte writes and fixed-width payload slices.
5. For `-r`, sort row offsets by quote accept time and write the corresponding row slices through a buffered writer.

```
┌─────────────────────────────────────────────────────────────────────┐
│ mmap pcap -> memmem B6034 scan -> record validation -> row format    │
│                                      │                              │
│ default ordering                     └── write full output buffer    │
│ quote accept ordering (-r)           └── sort row offsets, write rows│
└─────────────────────────────────────────────────────────────────────┘
```

Performance techniques currently used:

1. `memmap2` avoids reading the whole file through buffered `read` calls.
2. `memchr::memmem` provides a SIMD-capable substring search for `B6034`.
3. Output is written as bytes, not through `format!` or `Display`.
4. Fixed-width price and quantity fields are copied directly from the payload instead of parsed and re-formatted.
5. Packet timestamps are written as KST milliseconds directly.
6. Quote accept time is copied from the payload and padded to milliseconds.
7. The `-r` path sorts compact row offsets instead of sorting row data.
8. The CLI wraps stdout in `BufWriter` to avoid excessive write syscalls.

Current likely remaining bottlenecks:

1. `find_validate_packets` still scans the mmap for `B6034`; walking pcap records directly could be faster and stricter.
2. `format_rows` is still the largest isolated formatting phase.
3. End-to-end wall time is dominated by process startup, OS scheduling, and stdout/file-descriptor setup once the parser itself is in the 4-9 ms range.
