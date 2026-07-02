use memchr::memmem;
use memmap2::Mmap;
use std::{
    fs::File,
    io::{self, Write},
    path::Path,
};

const HDR_TO_PAYLOAD: usize = 16 + 14 + 20 + 8;
const PAYLOAD_LEN: usize = 215;
const RECORD_DATA_LEN: u32 = (14 + 20 + 8 + PAYLOAD_LEN) as u32;

pub const PCAP_FILE_PATH: &str = "test/fixtures/mdf-kospi200.20110216-0.pcap 2";

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum PacketOrdering {
    Default,
    QuoteAcceptTime,
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
// Parses exactly two ASCII digit bytes into a u32, e.g. b"07" -> 7.
fn aa(b: &[u8]) -> u32 {
    (b[0] - b'0') as u32 * 10 + (b[1] - b'0') as u32
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
    // Packet timestamp: pcap stores UTC seconds + microseconds; output is KST milliseconds.
    let secs = ts_sec as u64 + 9 * 3600;
    push_2d(out, (secs / 3600) % 24);
    out.push(b':');
    push_2d(out, (secs / 60) % 60);
    out.push(b':');
    push_2d(out, secs % 60);
    out.push(b'.');
    push_3d(out, ts_usec as u64 / 1000);
    out.push(b' ');

    // Quote accept time: payload stores HHMMSScc, where cc is centiseconds.
    out.extend_from_slice(&data[206..208]);
    out.push(b':');
    out.extend_from_slice(&data[208..210]);
    out.push(b':');
    out.extend_from_slice(&data[210..212]);
    out.push(b'.');
    out.extend_from_slice(&data[212..214]);
    out.push(b'0');
    out.push(b' ');

    // Issue code is a fixed-width, space-padded 12-byte field.
    let code_end = data[5..17]
        .iter()
        .rposition(|&b| b != b' ')
        .map_or(0, |i| i + 1);
    out.extend_from_slice(&data[5..5 + code_end]);

    // Bids are emitted from 5th best to 1st best as fixed-width quantity@price.
    for i in (0..5usize).rev() {
        out.push(b' ');
        out.extend_from_slice(&data[34 + i * 12..41 + i * 12]);
        out.push(b'@');
        out.extend_from_slice(&data[29 + i * 12..34 + i * 12]);
    }

    // Asks are emitted from 1st best to 5th best as fixed-width quantity@price.
    for i in 0..5usize {
        out.push(b' ');
        out.extend_from_slice(&data[101 + i * 12..108 + i * 12]);
        out.push(b'@');
        out.extend_from_slice(&data[96 + i * 12..101 + i * 12]);
    }
    out.push(b'\n');

    // Return quote accept time as centiseconds since midnight for -r sorting.
    accept_time_cs(data)
}

pub fn read_pcap_file<W: Write>(
    path: impl AsRef<Path>,
    ordering: PacketOrdering,
    mut writer: W,
) -> io::Result<W> {
    let file = File::open(path)?;
    let mmap = unsafe { Mmap::map(&file)? };

    if mmap.len() < 24 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "pcap too small"));
    }

    let little_endian = match &mmap[0..4] {
        [0xd4, 0xc3, 0xb2, 0xa1] | [0x4d, 0x3c, 0xb2, 0xa1] => true,
        [0xa1, 0xb2, 0xc3, 0xd4] | [0xa1, 0xb2, 0x3c, 0x4d] => false,
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "not a pcap file",
            ))
        }
    };

    let u32_at = |i: usize| -> u32 {
        let b: [u8; 4] = mmap[i..i + 4].try_into().unwrap();
        if little_endian {
            u32::from_le_bytes(b)
        } else {
            u32::from_be_bytes(b)
        }
    };

    let reorder = ordering == PacketOrdering::QuoteAcceptTime;
    // Heuristic preallocation: fixture has ~16k quote rows, averaging about 120 bytes per row.
    let mut out = Vec::with_capacity(16_004 * 120);
    // For -r, keep a compact sortable index: (quote_time_key, row_offset, row_len).
    // Full row bytes stay in `out`; only these small tuples are sorted.
    let mut index: Vec<(u32, u32, u32)> = if reorder {
        Vec::with_capacity(16_004)
    } else {
        Vec::new()
    };
    let finder = memmem::Finder::new(b"B6034");

    for pos in finder.find_iter(&mmap) {
        if pos < HDR_TO_PAYLOAD {
            continue;
        }
        let rec = pos - HDR_TO_PAYLOAD;
        if u32_at(rec + 8) != RECORD_DATA_LEN {
            continue;
        }
        if pos + PAYLOAD_LEN > mmap.len() {
            continue;
        }

        let start = out.len() as u32;
        let key = write_quote(
            &mut out,
            u32_at(rec),
            u32_at(rec + 4),
            &mmap[pos..pos + PAYLOAD_LEN],
        );
        if reorder {
            index.push((key, start, out.len() as u32 - start));
        }
    }

    if reorder {
        // Sort by quote accept time, then original row offset to preserve packet order on ties.
        index.sort_unstable_by_key(|&(key, off, _)| (key, off));
        for (_, off, len) in &index {
            //Slicing the sorted row out of the byte buffer "out", based on our sorted index
            writer.write_all(&out[*off as usize..*off as usize + *len as usize])?;
        }
    } else {
        writer.write_all(&out)?;
    }

    Ok(writer)
}
