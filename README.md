# kopsi-200-pcap-parser

A pcap parser that extracts market data from KOSPI 200 packets, written in Rust.

This is a submission for a hiring challenge by Tsuru Capital. Challenge details: https://www.tsurucapital.com/en/code-sample.html

## Running the Program

The KOSPI 200 pcap file is located in `fixtures`.

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
  3.8767-3.9661 ms
  1.3771-1.4088 GiB/s

read_pcap_file/quote_accept_time_to_vec
  5.5030-5.5339 ms
  1010.6-1016.3 MiB/s

read_pcap_file/default_to_sink
  1.5969-1.6121 ms
  3.3878-3.4200 GiB/s

read_pcap_file/quote_accept_time_to_sink
  3.1535-3.1802 ms
  1.7173-1.7319 GiB/s
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
  Time (mean ± σ):      11.5 ms ±   0.7 ms    [User: 12.1 ms, System: 13.1 ms]
  Range (min … max):    10.6 ms …  13.0 ms    50 runs

Benchmark 2: ./target/release/kopsi-200-pcap-parser -r > /dev/null
  Time (mean ± σ):      12.5 ms ±   0.5 ms    [User: 14.1 ms, System: 14.7 ms]
  Range (min … max):    11.7 ms …  13.9 ms    50 runs

Summary
  ./target/release/kopsi-200-pcap-parser > /dev/null ran
    1.09 ± 0.08 times faster than ./target/release/kopsi-200-pcap-parser -r > /dev/null
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
  Time (mean ± σ):      13.7 ms ±   0.9 ms    [User: 12.3 ms, System: 15.1 ms]
  Range (min … max):    12.0 ms …  16.2 ms    50 runs

Benchmark 2: ./target/release/kopsi-200-pcap-parser -r > /tmp/kopsi_hyperfine_quote.out
  Time (mean ± σ):      15.0 ms ±   0.8 ms    [User: 14.1 ms, System: 16.5 ms]
  Range (min … max):    13.4 ms …  16.8 ms    50 runs

Summary
  ./target/release/kopsi-200-pcap-parser > /tmp/kopsi_hyperfine_default.out ran
    1.09 ± 0.09 times faster than ./target/release/kopsi-200-pcap-parser -r > /tmp/kopsi_hyperfine_quote.out
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
  Time (mean ± σ):      66.3 ms ±   6.9 ms    [User: 10.2 ms, System: 12.1 ms]
  Range (min … max):    58.5 ms …  77.8 ms    10 runs

Benchmark 2: quote-time
  Time (mean ± σ):      64.4 ms ±   4.4 ms    [User: 12.3 ms, System: 13.5 ms]
  Range (min … max):    59.7 ms …  71.1 ms    10 runs

Summary
  quote-time ran
    1.03 ± 0.13 times faster than default
```

### Performance Summary

**In-process parser performance:**
- Packet time ordering: about 1.6 ms to `io::sink()`, about 3.9 ms when collecting bytes
- Quote accept time ordering: about 3.2 ms to `io::sink()`, about 5.5 ms when collecting bytes

**End-to-end binary wall time:**
- Packet time ordering: about 11.5 ms to `/dev/null`, about 13.7 ms to a file in the latest run
- Quote accept time ordering: about 12.5 ms to `/dev/null`, about 15.0 ms to a file in the latest run

**Alacritty terminal-rendering wall time:**
- Packet time ordering: about 66.3 ms mean
- Quote accept time ordering: about 64.4 ms mean

### Architecture

The parser maps the pcap once, splits the mapped bytes across worker threads, and searches each slice for `B6034` with a small overlap at the boundary so a marker is not missed. Each hit is still validated against the surrounding pcap record length before it is formatted.

Rows are formatted as bytes directly into per-worker buffers. The code copies fixed-width fields from the payload instead of parsing and re-formatting prices and quantities.

Default mode keeps packet arrival order by collecting worker buffers in file order. Quote-time mode builds a compact index per worker, merges those indexes, sorts by `(quote_accept_time, packet_position)`, and gathers the corresponding row bytes from the worker buffers.

Output is handed to a printer thread through a bounded channel. The main binary also wraps stdout in a large `BufWriter`, so the parser does not do a syscall per row.

```
mmap pcap
  -> split into worker-owned byte ranges
  -> memmem scan for B6034
  -> validate pcap record length
  -> format rows into per-worker buffers
  -> default: emit worker buffers in file order
  -> -r: merge/sort row indexes, gather sorted rows
  -> printer thread
```

The main remaining cost depends on how output is measured. Parser-only work is now in the low single-digit milliseconds. Full binary runs include process startup, mmap setup, thread scheduling, and stdout/file setup. Terminal runs are mostly terminal rendering; they are not a good proxy for parser speed.
