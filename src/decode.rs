use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::dns::{DnsQuery, decode_query};
use crate::error::DecodeError;

pub const DLT_EN10MB: u32 = 1;

#[derive(Debug, PartialEq, Eq)]
pub struct Checksums {
    pub ipv4_header: &'static str,
    pub udp: &'static str,
}

// Internet checksum: network-order words, odd trailing byte padded on the right.
// Fold after each word so the accumulator cannot overflow on bounded inputs.
fn sum(bytes: &[u8], mut acc: u32) -> u32 {
    for chunk in bytes.chunks(2) {
        acc += u32::from(u16::from_be_bytes([chunk[0], *chunk.get(1).unwrap_or(&0)]));
        acc = (acc & 0xffff) + (acc >> 16);
    }
    (acc & 0xffff) + (acc >> 16)
}

/// Offline only. Structural/DNS decoding succeeds before checksum slices are used.
/// IPv4 UDP zero means omitted; direct IPv6 UDP zero is rejected.
pub fn decode_frame_checked(
    dlt: u32,
    frame: &[u8],
) -> Result<(PacketQuery, Option<Checksums>), DecodeError> {
    let packet = decode_frame_offline(dlt, frame)?;
    let ip = &frame[14..];
    let (udp, pseudo_sum, ipv4_header) = if ip[0] >> 4 == 4 {
        let header_len = usize::from(ip[0] & 15) * 4;
        check_ipv4_checksum_options(&ip[20..header_len])?;
        if sum(&ip[..header_len], 0) != 0xffff {
            return Err(DecodeError::Malformed("IPv4 header checksum"));
        }
        let udp = &ip[header_len..usize::from(be16(ip, 2))];
        let acc = sum(&ip[12..20], 0);
        let acc = sum(&[0, 17], acc);
        (udp, sum(&(udp.len() as u16).to_be_bytes(), acc), "valid")
    } else {
        let udp = ipv6_udp(ip, true)?;
        let acc = sum(&ip[8..40], 0);
        let acc = sum(&(udp.len() as u32).to_be_bytes(), acc);
        (udp, sum(&[0, 0, 0, 17], acc), "not-applicable")
    };
    let udp_status = if be16(udp, 6) == 0 {
        if ipv4_header == "not-applicable" {
            return Err(DecodeError::Malformed("IPv6 UDP zero checksum"));
        }
        "omitted"
    } else if sum(udp, pseudo_sum) == 0xffff {
        "valid"
    } else {
        return Err(DecodeError::Malformed("UDP checksum"));
    };
    Ok((
        packet,
        Some(Checksums {
            ipv4_header,
            udp: udp_status,
        }),
    ))
}

// Bounds are already checked by decode_frame_offline; IHL limits this to 40 bytes.
// Source routing changes the UDP pseudo-header destination. Do not claim validity
// without implementing its semantics, even when the UDP checksum is omitted.
fn check_ipv4_checksum_options(options: &[u8]) -> Result<(), DecodeError> {
    let mut offset = 0;
    while offset < options.len() {
        match options[offset] {
            0 => break,       // End of option list; remaining bytes are padding.
            1 => offset += 1, // NOP has no length field.
            kind => {
                if options.len() - offset < 2 {
                    return Err(DecodeError::Malformed("short IPv4 option"));
                }
                let length = usize::from(options[offset + 1]);
                if length < 2 || length > options.len() - offset {
                    return Err(DecodeError::Malformed("IPv4 option length"));
                }
                if matches!(kind, 131 | 137) {
                    return Err(DecodeError::Unsupported("IPv4 source-route checksum"));
                }
                offset += length;
            }
        }
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketQuery {
    pub source_mac: [u8; 6],
    pub destination_mac: [u8; 6],
    pub source_ip: IpAddr,
    pub destination_ip: IpAddr,
    pub source_port: u16,
    pub destination_port: u16,
    pub dns: DnsQuery,
}

fn be16(bytes: &[u8], offset: usize) -> u16 {
    // All callers have checked the enclosing header length.
    u16::from_be_bytes([bytes[offset], bytes[offset + 1]])
}

pub fn decode_frame(dlt: u32, frame: &[u8]) -> Result<PacketQuery, DecodeError> {
    decode_frame_mode(dlt, frame, false)
}

/// Offline replay can walk bounded padding-only IPv6 options headers.
/// Live callers retain the direct-UDP-only decoder.
pub fn decode_frame_offline(dlt: u32, frame: &[u8]) -> Result<PacketQuery, DecodeError> {
    decode_frame_mode(dlt, frame, true)
}

fn decode_frame_mode(dlt: u32, frame: &[u8], extensions: bool) -> Result<PacketQuery, DecodeError> {
    if dlt != DLT_EN10MB {
        return Err(DecodeError::Unsupported("datalink type"));
    }
    if frame.len() < 14 {
        return Err(DecodeError::Malformed("short Ethernet header"));
    }
    match be16(frame, 12) {
        0x0800 => (),
        0x86dd => return decode_ipv6(frame, extensions),
        0x8100 | 0x88a8 => return Err(DecodeError::Unsupported("VLAN")),
        _ => return Err(DecodeError::Unsupported("EtherType is not IPv4 or IPv6")),
    }
    let ip = &frame[14..];
    if ip.len() < 20 {
        return Err(DecodeError::Malformed("short IPv4 header"));
    }
    if ip[0] >> 4 != 4 {
        return Err(DecodeError::Malformed("IPv4 version"));
    }
    let header_len = usize::from(ip[0] & 0x0f) * 4;
    if header_len < 20 || header_len > ip.len() {
        return Err(DecodeError::Malformed("IPv4 IHL"));
    }
    let total_len = usize::from(be16(ip, 2));
    if total_len < header_len || total_len > ip.len() {
        return Err(DecodeError::Malformed("IPv4 total length"));
    }
    let fragmentation = be16(ip, 6);
    if fragmentation & 0x8000 != 0 {
        return Err(DecodeError::Malformed("IPv4 reserved flag"));
    }
    if fragmentation & 0x3fff != 0 {
        return Err(DecodeError::Unsupported("IPv4 fragmentation"));
    }
    if ip[9] != 17 {
        return Err(DecodeError::Unsupported("IP protocol is not UDP"));
    }
    let udp = &ip[header_len..total_len];
    if udp.len() < 8 {
        return Err(DecodeError::Malformed("short UDP header"));
    }
    let dns = decode_udp(udp)?;
    Ok(PacketQuery {
        destination_mac: frame[..6].try_into().expect("checked Ethernet header"),
        source_mac: frame[6..12].try_into().expect("checked Ethernet header"),
        source_ip: Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15]).into(),
        destination_ip: Ipv4Addr::new(ip[16], ip[17], ip[18], ip[19]).into(),
        source_port: be16(udp, 0),
        destination_port: be16(udp, 2),
        dns,
    })
}

fn decode_udp(udp: &[u8]) -> Result<DnsQuery, DecodeError> {
    if udp.len() < 8 {
        return Err(DecodeError::Malformed("short UDP header"));
    }
    let length = usize::from(be16(udp, 4));
    if length < 8 || length != udp.len() {
        return Err(DecodeError::Malformed("UDP length"));
    }
    if be16(udp, 2) != 53 {
        return Err(DecodeError::Unsupported("UDP destination port is not 53"));
    }
    decode_query(&udp[8..length])
}

// Limits bound both header traversal and TLV parsing. Not protocol maxima.
const MAX_EXTENSION_HEADERS: usize = 8;
const MAX_EXTENSION_BYTES: usize = 2048;

fn ipv6_udp(ip: &[u8], extensions: bool) -> Result<&[u8], DecodeError> {
    if ip.len() < 40 {
        return Err(DecodeError::Malformed("short IPv6 header"));
    }
    if ip[0] >> 4 != 6 {
        return Err(DecodeError::Malformed("IPv6 version"));
    }
    let length = usize::from(be16(ip, 4));
    if length == 0 {
        return Err(DecodeError::Unsupported("IPv6 jumbogram or empty payload"));
    }
    let end = 40 + length;
    if end > ip.len() {
        return Err(DecodeError::Malformed("IPv6 payload length"));
    }
    let mut next = ip[6];
    let mut offset = 40;
    let mut count = 0;
    while next != 17 {
        if !extensions {
            return Err(DecodeError::Unsupported(
                "IPv6 next header is not direct UDP",
            ));
        }
        if !matches!(next, 0 | 60) {
            // Routing can change the checksum destination; Home Address options
            // can change its source. Neither is silently skipped.
            return Err(DecodeError::Unsupported("IPv6 extension or transport"));
        }
        if next == 0 && offset != 40 {
            return Err(DecodeError::Malformed("Hop-by-Hop header must be first"));
        }
        if count == MAX_EXTENSION_HEADERS {
            return Err(DecodeError::Unsupported("IPv6 extension header limit"));
        }
        if end - offset < 2 {
            return Err(DecodeError::Malformed("short IPv6 extension header"));
        }
        let size = (usize::from(ip[offset + 1]) + 1) * 8;
        if size > end - offset {
            return Err(DecodeError::Malformed("IPv6 extension length"));
        }
        if offset + size - 40 > MAX_EXTENSION_BYTES {
            return Err(DecodeError::Unsupported("IPv6 extension byte limit"));
        }
        let mut option = offset + 2;
        while option < offset + size {
            if ip[option] == 0 {
                // Pad1
                option += 1;
                continue;
            }
            if offset + size - option < 2 {
                return Err(DecodeError::Malformed("short IPv6 option"));
            }
            let option_size = usize::from(ip[option + 1]) + 2;
            if option_size > offset + size - option {
                return Err(DecodeError::Malformed("IPv6 option length"));
            }
            if ip[option] != 1 {
                return Err(DecodeError::Unsupported("IPv6 option is not padding"));
            }
            if ip[option + 2..option + option_size]
                .iter()
                .any(|byte| *byte != 0)
            {
                return Err(DecodeError::Malformed("IPv6 PadN data"));
            }
            option += option_size;
        }
        next = ip[offset];
        offset += size;
        count += 1;
    }
    Ok(&ip[offset..end])
}

fn decode_ipv6(frame: &[u8], extensions: bool) -> Result<PacketQuery, DecodeError> {
    let ip = &frame[14..];
    let udp = ipv6_udp(ip, extensions)?;
    let dns = decode_udp(udp)?;
    Ok(PacketQuery {
        destination_mac: frame[..6].try_into().expect("checked Ethernet header"),
        source_mac: frame[6..12].try_into().expect("checked Ethernet header"),
        source_ip: Ipv6Addr::from(<[u8; 16]>::try_from(&ip[8..24]).expect("checked IPv6 header"))
            .into(),
        destination_ip: Ipv6Addr::from(
            <[u8; 16]>::try_from(&ip[24..40]).expect("checked IPv6 header"),
        )
        .into(),
        source_port: be16(udp, 0),
        destination_port: be16(udp, 2),
        dns,
    })
}
