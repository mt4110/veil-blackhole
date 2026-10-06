use crate::error::DecodeError;

pub const MAX_HEX_FILE_BYTES: usize = 1024 * 1024;

/// Parses ASCII hex with whitespace. It does not echo input bytes in errors.
pub fn decode_hex(input: &[u8]) -> Result<Vec<u8>, DecodeError> {
    if input.len() > MAX_HEX_FILE_BYTES {
        return Err(DecodeError::Malformed("fixture file exceeds 1 MiB"));
    }
    let mut bytes = Vec::with_capacity(input.len() / 2);
    let mut high = None;
    for &byte in input {
        if byte.is_ascii_whitespace() {
            continue;
        }
        let nibble = match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            b'A'..=b'F' => byte - b'A' + 10,
            _ => return Err(DecodeError::Malformed("fixture is not ASCII hex")),
        };
        if let Some(first) = high.take() {
            bytes.push(first * 16 + nibble);
        } else {
            high = Some(nibble);
        }
    }
    if high.is_some() || bytes.is_empty() {
        return Err(DecodeError::Malformed("odd or empty fixture hex"));
    }
    Ok(bytes)
}
