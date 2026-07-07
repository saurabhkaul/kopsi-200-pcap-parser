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
  4.4059-4.5300 ms
  1.2056-1.2396 GiB/s

read_pcap_file/quote_accept_time_to_vec
  5.9749-5.9960 ms
  932.71-936.00 MiB/s

read_pcap_file/default_to_sink
  4.0378-4.0528 ms
  1.3476-1.3526 GiB/s

read_pcap_file/quote_accept_time_to_sink
  5.8076-5.8253 ms
  960.05-962.97 MiB/s
```

### Using Hyperfine

Hyperfine measures the full binary, including process startup, dynamic linking, file open/mmap, stdout setup, and OS scheduling. It is useful for end-to-end wall time, but it is not a clean parser-only measurement.

#### Without Terminal Output
```bash
cargo build --release

hyperfine --warmup 10 --runs 50 \
  --prepare 'cat target/release/kopsi-200-pcap-parser "fixtures/mdf-kospi200.20110216-0.pcap 2" > /dev/null' \
  './target/release/kopsi-200-pcap-parser > /dev/null' \
  './target/release/kopsi-200-pcap-parser -r > /dev/null'
```

**Latest results:**
```
Benchmark 1: ./target/release/kopsi-200-pcap-parser > /dev/null
  Time (mean ± σ):      12.2 ms ±   1.2 ms    [User: 7.2 ms, System: 5.7 ms]
  Range (min … max):     9.8 ms …  13.8 ms    50 runs

Benchmark 2: ./target/release/kopsi-200-pcap-parser -r > /dev/null
  Time (mean ± σ):      15.3 ms ±   1.7 ms    [User: 9.5 ms, System: 6.6 ms]
  Range (min … max):    12.4 ms …  17.5 ms    50 runs

Summary
  ./target/release/kopsi-200-pcap-parser > /dev/null ran
    1.25 ± 0.18 times faster than ./target/release/kopsi-200-pcap-parser -r > /dev/null
```

#### With File Output
```bash
hyperfine --warmup 10 --runs 50 \
  --prepare 'cat target/release/kopsi-200-pcap-parser "fixtures/mdf-kospi200.20110216-0.pcap 2" > /dev/null' \
  './target/release/kopsi-200-pcap-parser > /tmp/kopsi_hyperfine_default.out' \
  './target/release/kopsi-200-pcap-parser -r > /tmp/kopsi_hyperfine_quote.out'
```

This writes the full `2,864,716` byte / `16,004` row output to a real file.

**Latest results:**
```text
Benchmark 1: ./target/release/kopsi-200-pcap-parser > /tmp/kopsi_hyperfine_default.out
  Time (mean ± σ):      14.8 ms ±   0.9 ms    [User: 7.6 ms, System: 7.6 ms]
  Range (min … max):    11.5 ms …  16.3 ms    50 runs

Benchmark 2: ./target/release/kopsi-200-pcap-parser -r > /tmp/kopsi_hyperfine_quote.out
  Time (mean ± σ):      18.1 ms ±   1.2 ms    [User: 10.1 ms, System: 8.4 ms]
  Range (min … max):    14.4 ms …  19.9 ms    50 runs

Summary
  ./target/release/kopsi-200-pcap-parser > /tmp/kopsi_hyperfine_default.out ran
    1.23 ± 0.11 times faster than ./target/release/kopsi-200-pcap-parser -r > /tmp/kopsi_hyperfine_quote.out
```

#### With Terminal Output
```bash
hyperfine --warmup 3 --runs 10 --show-output \
  -n default './target/release/kopsi-200-pcap-parser' \
  -n quote-time './target/release/kopsi-200-pcap-parser -r'
```

Terminal rendering is much slower than redirecting to `/dev/null`, so these numbers are mostly terminal I/O behavior rather than parser behavior.

**Latest Alacritty results:**

```text
Benchmark 1: default
  Time (mean ± σ):      57.0 ms ±   0.9 ms    [User: 5.3 ms, System: 4.5 ms]
  Range (min … max):    55.7 ms …  58.3 ms    10 runs

Benchmark 2: quote-time
  Time (mean ± σ):      60.9 ms ±   0.9 ms    [User: 7.6 ms, System: 5.6 ms]
  Range (min … max):    59.5 ms …  62.3 ms    10 runs

Summary
  default ran
    1.07 ± 0.02 times faster than quote-time
```

### Performance Summary

**In-process parser performance:**
- Packet time ordering: about 4.0-4.5 ms
- Quote accept time ordering: about 5.8-6.0 ms

**End-to-end binary wall time:**
- Packet time ordering: about 12.2 ms to `/dev/null`, about 14.8 ms to a file
- Quote accept time ordering: about 15.3 ms to `/dev/null`, about 18.1 ms to a file

**Alacritty terminal-rendering wall time:**
- Packet time ordering: about 57.0 ms mean
- Quote accept time ordering: about 60.9 ms mean

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

1. Packet discovery still scans the mmap for `B6034`; walking pcap records directly could be faster and stricter.
2. Row formatting remains a likely hot path because every quote row is copied into the output buffer.
3. End-to-end wall time is dominated by process startup, OS scheduling, and stdout/file-descriptor setup once the parser itself is in the 4-9 ms range.
