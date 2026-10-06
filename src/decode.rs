use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::dns::{DnsQuery, decode_query};
use crate::error::DecodeError;

pub const DLT_EN10MB: u32 = 1;

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
    if dlt != DLT_EN10MB {
        return Err(DecodeError::Unsupported("datalink type"));
    }
    if frame.len() < 14 {
        return Err(DecodeError::Malformed("short Ethernet header"));
    }
    match be16(frame, 12) {
        0x0800 => (),
        0x86dd => return decode_ipv6(frame),
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

fn decode_ipv6(frame: &[u8]) -> Result<PacketQuery, DecodeError> {
    let ip = &frame[14..];
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
    if 40 + length > ip.len() {
        return Err(DecodeError::Malformed("IPv6 payload length"));
    }
    // Deliberately narrow: no extension-chain walking or fragment reassembly.
    if ip[6] != 17 {
        return Err(DecodeError::Unsupported(
            "IPv6 next header is not direct UDP",
        ));
    }
    let udp = &ip[40..40 + length];
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
