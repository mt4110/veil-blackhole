use std::net::{IpAddr, Ipv6Addr};
use veil_blackhole::{decode::decode_frame, error::DecodeError, fixture::decode_hex};

fn frame() -> Vec<u8> {
    decode_hex(include_bytes!("fixtures/query-v6.hex")).unwrap()
}
fn put16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_be_bytes());
}

#[test]
fn fixed_ipv6_frame_and_padding_have_known_fields() {
    let mut bytes = frame();
    bytes.extend([0xff; 20]);
    let query = decode_frame(1, &bytes).unwrap();
    assert_eq!(query.source_ip, "2001:db8::10".parse::<IpAddr>().unwrap());
    assert_eq!(
        query.destination_ip,
        "2001:db8::53".parse::<IpAddr>().unwrap()
    );
    assert_eq!((query.source_port, query.destination_port), (53000, 53));
    assert_eq!(query.dns.id, 0x1234);
    assert_eq!(query.dns.escaped_name(), "tracker.test.");
}

#[test]
fn ipv6_truncation_lengths_version_and_udp_boundaries_are_checked() {
    let bytes = frame();
    for length in 0..bytes.len() {
        assert!(decode_frame(1, &bytes[..length]).is_err());
    }
    for (offset, length) in [(18, 65535), (18, 7), (18, 37), (58, 7), (58, 37), (58, 39)] {
        let mut bytes = frame();
        put16(&mut bytes, offset, length);
        assert!(matches!(
            decode_frame(1, &bytes),
            Err(DecodeError::Malformed(_))
        ));
    }
    let mut bytes = frame();
    bytes[14] = 0x45;
    assert_eq!(
        decode_frame(1, &bytes),
        Err(DecodeError::Malformed("IPv6 version"))
    );
    let mut bytes = frame();
    put16(&mut bytes, 18, 0);
    assert!(matches!(
        decode_frame(1, &bytes),
        Err(DecodeError::Unsupported(_))
    ));
}

#[test]
fn extension_fragment_other_transport_and_other_port_are_explicitly_unsupported() {
    for next in [0, 6, 43, 44, 50, 51, 59, 60] {
        let mut bytes = frame();
        bytes[20] = next;
        assert_eq!(
            decode_frame(1, &bytes),
            Err(DecodeError::Unsupported(
                "IPv6 next header is not direct UDP"
            ))
        );
    }
    let mut bytes = frame();
    put16(&mut bytes, 56, 5353);
    assert!(matches!(
        decode_frame(1, &bytes),
        Err(DecodeError::Unsupported(_))
    ));
}

#[test]
fn ipv6_udp_checksum_fixture_matches_independent_pseudoheader_sum() {
    let bytes = frame();
    let mut pseudo = bytes[22..54].to_vec();
    pseudo.extend_from_slice(&38u32.to_be_bytes());
    pseudo.extend_from_slice(&[0, 0, 0, 17]);
    pseudo.extend_from_slice(&bytes[54..]);
    let mut sum: u32 = pseudo
        .as_chunks::<2>()
        .0
        .iter()
        .map(|b| u32::from(u16::from_be_bytes([b[0], b[1]])))
        .sum();
    while sum > 65535 {
        sum = (sum & 65535) + (sum >> 16);
    }
    assert_eq!(sum, 65535);
    assert_ne!(&bytes[60..62], &[0, 0]);
    assert_eq!(
        Ipv6Addr::from(<[u8; 16]>::try_from(&bytes[22..38]).unwrap()),
        "2001:db8::10".parse::<Ipv6Addr>().unwrap()
    );
}

#[test]
fn bounded_ipv6_mutation_corpus_does_not_panic() {
    let original = frame();
    for offset in 0..original.len() {
        for value in [0, 0xff, 0xc0] {
            let mut bytes = original.clone();
            bytes[offset] = value;
            let _ = decode_frame(1, &bytes);
        }
    }
}
