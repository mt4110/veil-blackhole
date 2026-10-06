use veil_blackhole::{
    decode::{decode_frame, decode_frame_checked, decode_frame_offline},
    error::DecodeError,
    fixture::decode_hex,
};

fn frame(headers: &[u8], first: u8) -> Vec<u8> {
    let mut bytes = decode_hex(include_bytes!("fixtures/query-v6.hex")).unwrap();
    bytes[20] = first;
    bytes.splice(54..54, headers.iter().copied());
    bytes[18..20].copy_from_slice(&(38 + headers.len() as u16).to_be_bytes());
    bytes
}

#[test]
fn padding_chain_replays_and_checksum_excludes_extensions() {
    for (headers, first) in [
        (vec![17, 0, 0, 0, 0, 0, 0, 0], 0),
        (vec![17, 0, 1, 4, 0, 0, 0, 0], 60),
        (vec![60, 0, 0, 0, 0, 0, 0, 0, 17, 0, 1, 4, 0, 0, 0, 0], 0),
    ] {
        let bytes = frame(&headers, first);
        let query = decode_frame_offline(1, &bytes).unwrap();
        assert_eq!(query.dns.id, 4660);
        assert_eq!(query.source_port, 53000);
        assert_eq!(
            decode_frame_checked(1, &bytes).unwrap().1.unwrap().udp,
            "valid"
        );
        assert!(matches!(
            decode_frame(1, &bytes),
            Err(DecodeError::Unsupported(_))
        ));
        let mut padding = bytes.clone();
        padding.extend([255; 12]);
        assert!(decode_frame_checked(1, &padding).is_ok());
        for n in 0..bytes.len() {
            assert!(decode_frame_offline(1, &bytes[..n]).is_err());
        }
    }
}

#[test]
fn malformed_lengths_options_and_order_are_rejected() {
    for header in [
        vec![17, 255, 0, 0, 0, 0, 0, 0],
        vec![17, 0, 1, 7, 0, 0, 0, 0],
        vec![17, 0, 1, 4, 1, 0, 0, 0],
        vec![17, 0, 0, 0, 0, 0, 0, 1],
    ] {
        assert!(matches!(
            decode_frame_offline(1, &frame(&header, 0)),
            Err(DecodeError::Malformed(_))
        ));
    }
    let late_hop = frame(&[0, 0, 0, 0, 0, 0, 0, 0, 17, 0, 0, 0, 0, 0, 0, 0], 60);
    assert!(matches!(
        decode_frame_offline(1, &late_hop),
        Err(DecodeError::Malformed(_))
    ));
}

#[test]
fn unsupported_options_fragments_and_bounds() {
    for next in [43, 44, 50, 51, 59, 6, 253] {
        assert!(matches!(
            decode_frame_offline(1, &frame(&[], next)),
            Err(DecodeError::Unsupported(_))
        ));
        assert!(matches!(
            decode_frame_offline(1, &frame(&[next, 0, 0, 0, 0, 0, 0, 0], 0)),
            Err(DecodeError::Unsupported(_))
        ));
    }
    assert!(matches!(
        decode_frame_offline(1, &frame(&[17, 0, 201, 4, 0, 0, 0, 0], 60)),
        Err(DecodeError::Unsupported(_))
    ));
    for count in [8, 9] {
        let mut headers = vec![0; count * 8];
        for i in 0..count {
            headers[i * 8] = if i + 1 == count { 17 } else { 60 };
        }
        let result = decode_frame_offline(1, &frame(&headers, 60));
        assert_eq!(result.is_ok(), count == 8);
    }
    let mut max = vec![0; 2048];
    max[0] = 17;
    max[1] = 255;
    assert!(decode_frame_offline(1, &frame(&max, 60)).is_ok());
    max[0] = 60;
    max.extend([17, 0, 0, 0, 0, 0, 0, 0]);
    assert!(matches!(
        decode_frame_offline(1, &frame(&max, 60)),
        Err(DecodeError::Unsupported(_))
    ));
}

#[test]
fn mutation_corpus_does_not_panic_and_udp_checksum_is_still_checked() {
    let original = frame(&[17, 0, 1, 4, 0, 0, 0, 0], 60);
    for offset in 0..original.len() {
        for value in [0, 255, 192] {
            let mut bytes = original.clone();
            bytes[offset] = value;
            let _ = decode_frame_checked(1, &bytes);
        }
    }
    let mut invalid = original;
    invalid[70] ^= 1;
    assert!(decode_frame_offline(1, &invalid).is_ok());
    assert!(decode_frame_checked(1, &invalid).is_err());
}
