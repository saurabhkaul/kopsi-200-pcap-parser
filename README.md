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
  3.9095-3.9339 ms
  1.3883-1.3970 GiB/s

read_pcap_file/quote_accept_time_to_vec
  4.7699-5.0921 ms
  1.0725-1.1450 GiB/s

read_pcap_file/default_to_sink
  1.1511-1.1730 ms
  4.6561-4.7445 GiB/s

read_pcap_file/quote_accept_time_to_sink
  2.3099-2.4555 ms
  2.2242-2.3644 GiB/s
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
  Time (mean ± σ):      10.6 ms ±   2.5 ms    [User: 10.3 ms, System: 12.0 ms]
  Range (min … max):     7.4 ms …  14.6 ms    50 runs

Benchmark 2: ./target/release/kopsi-200-pcap-parser -r > /dev/null
  Time (mean ± σ):       9.7 ms ±   0.4 ms    [User: 10.9 ms, System: 11.9 ms]
  Range (min … max):     9.0 ms …  10.8 ms    50 runs

Summary
  ./target/release/kopsi-200-pcap-parser -r > /dev/null ran
    1.09 ± 0.26 times faster than ./target/release/kopsi-200-pcap-parser > /dev/null
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
  Time (mean ± σ):      13.4 ms ±   6.7 ms    [User: 10.3 ms, System: 13.2 ms]
  Range (min … max):     8.4 ms …  55.4 ms    50 runs

Benchmark 2: ./target/release/kopsi-200-pcap-parser -r > /tmp/kopsi_hyperfine_quote.out
  Time (mean ± σ):      11.5 ms ±   1.4 ms    [User: 10.6 ms, System: 13.1 ms]
  Range (min … max):     8.8 ms …  14.5 ms    50 runs

Summary
  ./target/release/kopsi-200-pcap-parser -r > /tmp/kopsi_hyperfine_quote.out ran
    1.17 ± 0.60 times faster than ./target/release/kopsi-200-pcap-parser > /tmp/kopsi_hyperfine_default.out
```

The default file-output run had one large outlier, so the range is more useful than the mean for that line.

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
  Time (mean ± σ):      53.5 ms ±   1.9 ms    [User: 7.8 ms, System: 9.2 ms]
  Range (min … max):    51.1 ms …  55.9 ms    10 runs

Benchmark 2: quote-time
  Time (mean ± σ):      52.1 ms ±   0.8 ms    [User: 9.2 ms, System: 10.4 ms]
  Range (min … max):    51.4 ms …  53.6 ms    10 runs

Summary
  quote-time ran
    1.03 ± 0.04 times faster than default
```

### Performance Summary

**In-process parser performance:**
- Packet time ordering: about 1.2 ms to `io::sink()`, about 3.9 ms when collecting bytes
- Quote accept time ordering: about 2.3-2.5 ms to `io::sink()`, about 4.8-5.1 ms when collecting bytes

**End-to-end binary wall time:**
- Packet time ordering: about 10.6 ms to `/dev/null`, about 13.4 ms to a file in the latest run
- Quote accept time ordering: about 9.7 ms to `/dev/null`, about 11.5 ms to a file in the latest run

**Alacritty terminal-rendering wall time:**
- Packet time ordering: about 53.5 ms mean
- Quote accept time ordering: about 52.1 ms mean

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
