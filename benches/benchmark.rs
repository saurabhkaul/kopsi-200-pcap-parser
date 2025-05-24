use criterion::{criterion_group, criterion_main, Criterion};
use kopsi_200_pcap_parser::{read_pcap_file, PacketOrdering, PCAP_FILE_PATH};
use std::hint::black_box;
use std::path::PathBuf;

fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("runner default ordering", |b| {
        b.iter(|| {
            black_box(read_pcap_file(
                PathBuf::from(PCAP_FILE_PATH),
                PacketOrdering::Default,
            ))
        })
    });

    c.bench_function("runner quote time ordering", |b| {
        b.iter(|| {
            black_box(read_pcap_file(
                PathBuf::from(PCAP_FILE_PATH),
                PacketOrdering::QuoteAcceptTime,
            ))
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);

//Original bench pre rewrite
//runner                  time:   [123.29 ms 128.15 ms 133.94 ms]

//By increasing buffer size 1024*1024 vs 1024 only
//mean   [30.775 ms 31.400 ms] std. dev.      [1.2402 ms 1.9140 ms]
//median [30.354 ms 30.770 ms] med. abs. dev. [697.66 µs 1.1753 ms]
