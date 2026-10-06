//! Classic Darwin BPF records, decoded without casts.
//!
//! The inspected 64-bit macOS SDK uses timeval32: two LE i32 fields, LE u32
//! caplen and datalen, LE u16 hdrlen, and 4-byte record alignment. No casts occur.
//! The fields occupy 18 wire bytes. sizeof(struct bpf_hdr) is 20 because of C
//! trailing padding; Darwin's SIZEOF_BPF_HDR and Ethernet bh_hdrlen can be 18.

use crate::error::DecodeError;

pub const MAX_BUFFER_BYTES: usize = 1024 * 1024;
pub const DARWIN_HEADER_BYTES: usize = 18;

#[derive(Debug, PartialEq, Eq)]
pub struct Record<'a> {
    pub seconds: i32,
    pub microseconds: i32,
    pub frame: &'a [u8],
    pub original_len: u32,
    pub truncated: bool,
}

pub fn decode_darwin_records(buffer: &[u8]) -> Result<Vec<Record<'_>>, DecodeError> {
    if buffer.len() > MAX_BUFFER_BYTES {
        return Err(DecodeError::Malformed("BPF buffer size"));
    }
    let mut records = Vec::new();
    let mut offset = 0usize;
    while offset < buffer.len() {
        let remaining = &buffer[offset..];
        if remaining.len() < DARWIN_HEADER_BYTES {
            return Err(DecodeError::Malformed("short BPF header"));
        }
        let caplen = u32::from_le_bytes(remaining[8..12].try_into().expect("checked header"));
        let datalen = u32::from_le_bytes(remaining[12..16].try_into().expect("checked header"));
        let hdrlen = usize::from(u16::from_le_bytes([remaining[16], remaining[17]]));
        if hdrlen < DARWIN_HEADER_BYTES || caplen > datalen {
            return Err(DecodeError::Malformed(
                "BPF header length or capture length",
            ));
        }
        let end = hdrlen
            .checked_add(caplen as usize)
            .filter(|&end| end <= remaining.len())
            .ok_or(DecodeError::Malformed("BPF record exceeds buffer"))?;
        let seconds = i32::from_le_bytes(remaining[..4].try_into().expect("checked header"));
        let microseconds = i32::from_le_bytes(remaining[4..8].try_into().expect("checked header"));
        if !(0..1_000_000).contains(&microseconds) {
            return Err(DecodeError::Malformed("BPF timestamp microseconds"));
        }
        records.push(Record {
            seconds,
            microseconds,
            frame: &remaining[hdrlen..end],
            original_len: datalen,
            truncated: caplen < datalen,
        });
        // A final record may end exactly at read length, without trailing padding.
        if end == remaining.len() {
            break;
        }
        let aligned = end
            .checked_add(3)
            .map(|value| value & !3)
            .filter(|&value| value <= remaining.len())
            .ok_or(DecodeError::Malformed("BPF alignment exceeds buffer"))?;
        offset = offset
            .checked_add(aligned)
            .ok_or(DecodeError::Malformed("BPF offset overflow"))?;
    }
    Ok(records)
}
