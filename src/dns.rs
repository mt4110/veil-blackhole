use hickory_proto::op::{Message, MessageType, OpCode};
use hickory_proto::rr::DNSClass;
use hickory_proto::serialize::binary::{BinDecodable, BinDecoder};

use crate::error::DecodeError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuery {
    pub id: u16,
    pub flags: u16,
    /// Labels are byte strings, not necessarily UTF-8. Root is an empty vector.
    pub labels: Vec<Vec<u8>>,
    pub query_type: u16,
    pub query_class: u16,
}

impl DnsQuery {
    /// Escapes separators and non-printable bytes so input cannot control a terminal.
    pub fn escaped_name(&self) -> String {
        let mut name = String::new();
        for label in &self.labels {
            for &byte in label {
                if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_') {
                    name.push(char::from(byte));
                } else {
                    use std::fmt::Write;
                    // Writing to String cannot fail.
                    let _ = write!(name, "\\{byte:03}");
                }
            }
            name.push('.');
        }
        if name.is_empty() {
            name.push('.');
        }
        name
    }
}

pub fn decode_query(payload: &[u8]) -> Result<DnsQuery, DecodeError> {
    if !(12..=65535).contains(&payload.len()) {
        return Err(DecodeError::Malformed("DNS message length"));
    }
    let flags = u16::from_be_bytes([payload[2], payload[3]]);
    if flags & 0x8000 != 0 {
        return Err(DecodeError::Unsupported("DNS response"));
    }
    if flags & 0x7800 != 0 {
        return Err(DecodeError::Unsupported("DNS opcode"));
    }
    if u16::from_be_bytes([payload[4], payload[5]]) != 1 {
        return Err(DecodeError::Malformed("DNS question count must be one"));
    }
    // Even root-name RRs need 11 bytes. Reject impossible counts before parser allocation.
    let records: usize = [6, 8, 10]
        .into_iter()
        .map(|offset| usize::from(u16::from_be_bytes([payload[offset], payload[offset + 1]])))
        .sum();
    if 17 + records * 11 > payload.len() {
        return Err(DecodeError::Malformed("DNS section counts exceed message"));
    }
    let mut decoder = BinDecoder::new(payload);
    let message = Message::read(&mut decoder)
        .map_err(|_| DecodeError::Malformed("DNS structure or compressed name"))?;
    if decoder.index() != payload.len() {
        return Err(DecodeError::Malformed("trailing DNS bytes"));
    }
    if message.message_type != MessageType::Query || message.op_code != OpCode::Query {
        return Err(DecodeError::Unsupported("DNS message kind"));
    }
    let question = message
        .queries
        .first()
        .ok_or(DecodeError::Malformed("missing DNS question"))?;
    if question.query_class() != DNSClass::IN {
        return Err(DecodeError::Unsupported("DNS class is not IN"));
    }
    Ok(DnsQuery {
        id: message.id,
        flags,
        labels: question.name().iter().map(<[u8]>::to_vec).collect(),
        query_type: question.query_type().into(),
        query_class: question.query_class().into(),
    })
}
