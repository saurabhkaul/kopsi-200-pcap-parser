use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use kopsi_200_pcap_parser::{read_pcap_file, PacketOrdering, PCAP_FILE_PATH};
use std::io;
use std::path::PathBuf;

fn criterion_benchmark(c: &mut Criterion) {
    let fixture = PathBuf::from(PCAP_FILE_PATH);
    let fixture_bytes = std::fs::metadata(&fixture).expect("fixture metadata").len();

    let mut group = c.benchmark_group("read_pcap_file");
    group.throughput(Throughput::Bytes(fixture_bytes));

    group.bench_function("default_to_vec", |b| {
        b.iter(|| {
            black_box(read_pcap_file(
                black_box(&fixture),
                PacketOrdering::Default,
                Vec::new(),
            ))
        })
    });

    group.bench_function("quote_accept_time_to_vec", |b| {
        b.iter(|| {
            black_box(read_pcap_file(
                black_box(&fixture),
                PacketOrdering::QuoteAcceptTime,
                Vec::new(),
            ))
        })
    });

    group.bench_function("default_to_sink", |b| {
        b.iter(|| {
            black_box(read_pcap_file(
                black_box(&fixture),
                PacketOrdering::Default,
                io::sink(),
            ))
        })
    });

    group.bench_function("quote_accept_time_to_sink", |b| {
        b.iter(|| {
            black_box(read_pcap_file(
                black_box(&fixture),
                PacketOrdering::QuoteAcceptTime,
                io::sink(),
            ))
        })
    });

    group.finish();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
