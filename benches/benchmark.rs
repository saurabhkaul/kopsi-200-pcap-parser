use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion, Throughput};
use kopsi_200_pcap_parser::{read_pcap_file, PacketOrdering, PCAP_FILE_PATH};
use memchr::memmem;
use memmap2::Mmap;
use std::fs::File;
use std::io;
use std::path::PathBuf;

const HDR_TO_PAYLOAD: usize = 16 + 14 + 20 + 8;
const PAYLOAD_LEN: usize = 215;
const RECORD_DATA_LEN: u32 = (14 + 20 + 8 + PAYLOAD_LEN) as u32;

#[derive(Clone, Copy)]
struct PacketRef {
    rec: usize,
    pos: usize,
}

#[inline]
// Parses exactly two ASCII digit bytes into a u32, e.g. b"07" -> 7.
fn aa(b: &[u8]) -> u32 {
    (b[0] - b'0') as u32 * 10 + (b[1] - b'0') as u32
}

#[inline]
fn accept_time_cs(data: &[u8]) -> u32 {
    let hh = aa(&data[206..208]);
    let mm = aa(&data[208..210]);
    let ss = aa(&data[210..212]);
    let cc = aa(&data[212..214]);
    hh * 360_000 + mm * 6_000 + ss * 100 + cc
}

#[inline]
fn push_2d(out: &mut Vec<u8>, n: u64) {
    out.push(b'0' + (n / 10) as u8);
    out.push(b'0' + (n % 10) as u8);
}

#[inline]
fn push_3d(out: &mut Vec<u8>, n: u64) {
    out.push(b'0' + (n / 100 % 10) as u8);
    out.push(b'0' + (n / 10 % 10) as u8);
    out.push(b'0' + (n % 10) as u8);
}

#[inline]
fn write_quote(out: &mut Vec<u8>, ts_sec: u32, ts_usec: u32, data: &[u8]) -> u32 {
    let secs = ts_sec as u64 + 9 * 3600;
    push_2d(out, (secs / 3600) % 24);
    out.push(b':');
    push_2d(out, (secs / 60) % 60);
    out.push(b':');
    push_2d(out, secs % 60);
    out.push(b'.');
    push_3d(out, ts_usec as u64 / 1000);
    out.push(b' ');

    out.extend_from_slice(&data[206..208]);
    out.push(b':');
    out.extend_from_slice(&data[208..210]);
    out.push(b':');
    out.extend_from_slice(&data[210..212]);
    out.push(b'.');
    out.extend_from_slice(&data[212..214]);
    out.push(b'0');
    out.push(b' ');

    let code_end = data[5..17]
        .iter()
        .rposition(|&b| b != b' ')
        .map_or(0, |i| i + 1);
    out.extend_from_slice(&data[5..5 + code_end]);

    for i in (0..5usize).rev() {
        out.push(b' ');
        out.extend_from_slice(&data[34 + i * 12..41 + i * 12]);
        out.push(b'@');
        out.extend_from_slice(&data[29 + i * 12..34 + i * 12]);
    }
    for i in 0..5usize {
        out.push(b' ');
        out.extend_from_slice(&data[101 + i * 12..108 + i * 12]);
        out.push(b'@');
        out.extend_from_slice(&data[96 + i * 12..101 + i * 12]);
    }
    out.push(b'\n');

    accept_time_cs(data)
}

fn little_endian(mmap: &[u8]) -> bool {
    match &mmap[0..4] {
        [0xd4, 0xc3, 0xb2, 0xa1] | [0x4d, 0x3c, 0xb2, 0xa1] => true,
        [0xa1, 0xb2, 0xc3, 0xd4] | [0xa1, 0xb2, 0x3c, 0x4d] => false,
        _ => panic!("not a pcap file"),
    }
}

#[inline]
fn u32_at(mmap: &[u8], little_endian: bool, i: usize) -> u32 {
    let b: [u8; 4] = mmap[i..i + 4].try_into().unwrap();
    if little_endian {
        u32::from_le_bytes(b)
    } else {
        u32::from_be_bytes(b)
    }
}

fn find_valid_packets(mmap: &[u8]) -> Vec<PacketRef> {
    let little_endian = little_endian(mmap);
    let finder = memmem::Finder::new(b"B6034");
    let mut packets = Vec::with_capacity(16_004);

    for pos in finder.find_iter(mmap) {
        if pos < HDR_TO_PAYLOAD {
            continue;
        }
        let rec = pos - HDR_TO_PAYLOAD;
        if u32_at(mmap, little_endian, rec + 8) != RECORD_DATA_LEN {
            continue;
        }
        if pos + PAYLOAD_LEN > mmap.len() {
            continue;
        }

        packets.push(PacketRef { rec, pos });
    }

    packets
}

fn format_rows(mmap: &[u8], packets: &[PacketRef]) -> (Vec<u8>, Vec<(u32, u32, u32)>) {
    let little_endian = little_endian(mmap);
    let mut out = Vec::with_capacity(16_004 * 120);
    let mut index = Vec::with_capacity(16_004);

    for packet in packets {
        let start = out.len() as u32;
        let key = write_quote(
            &mut out,
            u32_at(mmap, little_endian, packet.rec),
            u32_at(mmap, little_endian, packet.rec + 4),
            &mmap[packet.pos..packet.pos + PAYLOAD_LEN],
        );
        index.push((key, start, out.len() as u32 - start));
    }

    (out, index)
}

fn sort_and_write(out: &[u8], mut index: Vec<(u32, u32, u32)>) -> Vec<u8> {
    index.sort_unstable_by_key(|&(key, off, _)| (key, off));
    let mut sorted = Vec::with_capacity(out.len());
    for (_, off, len) in &index {
        sorted.extend_from_slice(&out[*off as usize..*off as usize + *len as usize]);
    }
    sorted
}

fn criterion_benchmark(c: &mut Criterion) {
    let fixture = PathBuf::from(PCAP_FILE_PATH);
    let fixture_bytes = std::fs::metadata(&fixture).expect("fixture metadata").len();
    let mmap = std::fs::read(&fixture).expect("fixture read");
    let packets = find_valid_packets(&mmap);
    let (formatted, index) = format_rows(&mmap, &packets);

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

    let mut phases = c.benchmark_group("phases");
    phases.throughput(Throughput::Bytes(fixture_bytes));

    phases.bench_function("open_mmap", |b| {
        b.iter(|| {
            let file = File::open(black_box(&fixture)).expect("fixture open");
            let mmap = unsafe { Mmap::map(&file).expect("fixture mmap") };
            black_box(mmap.len())
        })
    });

    phases.bench_function("find_validate_packets", |b| {
        b.iter(|| black_box(find_valid_packets(black_box(&mmap))))
    });

    phases.bench_function("format_rows", |b| {
        b.iter(|| black_box(format_rows(black_box(&mmap), black_box(&packets))))
    });

    phases.bench_function("sort_and_write_to_vec", |b| {
        b.iter_batched(
            || index.clone(),
            |index| black_box(sort_and_write(black_box(&formatted), index)),
            BatchSize::SmallInput,
        )
    });

    phases.finish();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
