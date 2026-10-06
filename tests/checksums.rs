use veil_blackhole::{
    decode::{DLT_EN10MB, decode_frame_checked},
    fixture::decode_hex,
};

fn fixture(name: &str) -> Vec<u8> {
    decode_hex(&std::fs::read(format!("tests/fixtures/{name}")).unwrap()).unwrap()
}

#[test]
fn known_checksums_options_and_padding() {
    for name in ["query-a.hex", "query-options.hex", "query-v6.hex"] {
        let mut frame = fixture(name);
        let (_, status) = decode_frame_checked(DLT_EN10MB, &frame).unwrap();
        assert_eq!(status.unwrap().udp, "valid");
        frame.extend_from_slice(&[1, 2, 3]);
        assert!(decode_frame_checked(DLT_EN10MB, &frame).is_ok());
    }
}

#[test]
fn mutations_and_zero_semantics() {
    let original = fixture("query-a.hex");
    for offset in [22, 26, 30, 34, 40, 42, 55] {
        let mut frame = original.clone();
        frame[offset] ^= 1;
        assert!(decode_frame_checked(DLT_EN10MB, &frame).is_err());
    }
    let mut frame = original;
    frame[40..42].fill(0);
    assert_eq!(
        decode_frame_checked(DLT_EN10MB, &frame)
            .unwrap()
            .1
            .unwrap()
            .udp,
        "omitted"
    );
    let mut v6 = fixture("query-v6.hex");
    v6[60..62].fill(0);
    assert!(decode_frame_checked(DLT_EN10MB, &v6).is_err());
    for offset in [22, 38, 54, 60, 62] {
        let mut v6 = fixture("query-v6.hex");
        v6[offset] ^= 1;
        assert!(decode_frame_checked(DLT_EN10MB, &v6).is_err());
    }
}

// Independent fixture encoder sums u64 words and folds only at the end.
fn checksum(bytes: &[u8]) -> u16 {
    let mut total: u64 = bytes
        .chunks(2)
        .map(|c| (u64::from(c[0]) << 8) + u64::from(*c.get(1).unwrap_or(&0)))
        .sum();
    while total >> 16 != 0 {
        total = (total & 65535) + (total >> 16);
    }
    !(total as u16)
}

#[test]
fn odd_payload_and_negative_zero_checksum() {
    let mut frame = fixture("query-a.hex");
    // Extend first DNS label by one character: a valid odd-length UDP payload.
    frame[54] = 8;
    frame.insert(62, b'x');
    frame[16..18].copy_from_slice(&59u16.to_be_bytes());
    frame[38..40].copy_from_slice(&39u16.to_be_bytes());
    frame[24..26].fill(0);
    let header = checksum(&frame[14..34]);
    frame[24..26].copy_from_slice(&header.to_be_bytes());
    frame[40..42].fill(0);
    let mut pseudo = frame[26..34].to_vec();
    pseudo.extend_from_slice(&[0, 17, 0, 39]);
    pseudo.extend_from_slice(&frame[34..]);
    let udp = checksum(&pseudo);
    frame[40..42].copy_from_slice(&udp.to_be_bytes());
    assert!(decode_frame_checked(DLT_EN10MB, &frame).is_ok());
    // Select DNS ID making the computed checksum zero, transmitted as 0xffff.
    for id in 0..=u16::MAX {
        frame[42..44].copy_from_slice(&id.to_be_bytes());
        frame[40..42].fill(0);
        pseudo.truncate(12);
        pseudo.extend_from_slice(&frame[34..]);
        if checksum(&pseudo) == 0 {
            frame[40..42].fill(255);
            assert!(decode_frame_checked(DLT_EN10MB, &frame).is_ok());
            return;
        }
    }
    panic!("no negative-zero fixture found");
}

#[test]
fn truncated_inputs_do_not_panic() {
    for name in ["query-a.hex", "query-v6.hex"] {
        let frame = fixture(name);
        for n in 0..frame.len() {
            assert!(decode_frame_checked(DLT_EN10MB, &frame[..n]).is_err());
        }
    }
}

fn with_ipv4_options(options: &[u8]) -> Vec<u8> {
    assert!(options.len().is_multiple_of(4));
    assert!(options.len() <= 40);
    let mut frame = fixture("query-a.hex");
    frame.splice(34..34, options.iter().copied());
    frame[14] = 0x40 | (5 + options.len() as u8 / 4);
    frame[16..18].copy_from_slice(&(58 + options.len() as u16).to_be_bytes());
    frame[24..26].fill(0);
    let header = checksum(&frame[14..34 + options.len()]);
    frame[24..26].copy_from_slice(&header.to_be_bytes());
    frame
}

#[test]
fn source_routes_never_report_udp_checksum_validity() {
    use veil_blackhole::{decode::decode_frame_offline, error::DecodeError};
    for kind in [131, 137] {
        // LSRR and SSRR
        let mut frame = with_ipv4_options(&[kind, 7, 4, 203, 0, 113, 53, 1]);
        assert!(decode_frame_offline(DLT_EN10MB, &frame).is_ok());
        // Original UDP checksum matches the base destination, not the route's final destination.
        assert_eq!(
            decode_frame_checked(DLT_EN10MB, &frame),
            Err(DecodeError::Unsupported("IPv4 source-route checksum"))
        );
        // A checksum calculated using the final destination is also explicitly unsupported.
        frame[48..50].fill(0);
        let mut pseudo = frame[26..30].to_vec();
        pseudo.extend_from_slice(&[203, 0, 113, 53, 0, 17, 0, 38]);
        pseudo.extend_from_slice(&frame[42..]);
        let udp = checksum(&pseudo);
        frame[48..50].copy_from_slice(&udp.to_be_bytes());
        assert_eq!(
            decode_frame_checked(DLT_EN10MB, &frame),
            Err(DecodeError::Unsupported("IPv4 source-route checksum"))
        );
        frame[48..50].fill(0);
        assert_eq!(
            decode_frame_checked(DLT_EN10MB, &frame),
            Err(DecodeError::Unsupported("IPv4 source-route checksum"))
        );
    }
}

#[test]
fn ipv4_option_lengths_are_checked_before_checksum_reporting() {
    use veil_blackhole::error::DecodeError;
    for options in [
        vec![130, 0, 0, 0],
        vec![130, 1, 0, 0],
        vec![130, 5, 0, 0],
        vec![1, 1, 1, 130],
        vec![131, 9, 4, 0],
    ] {
        let frame = with_ipv4_options(&options);
        assert!(matches!(
            decode_frame_checked(DLT_EN10MB, &frame),
            Err(DecodeError::Malformed(_))
        ));
    }
}

#[test]
fn ipv4_option_boundaries_avoid_false_source_route_detection() {
    for options in [
        vec![1; 40],
        vec![0, 131, 137, 0],
        vec![130, 4, 131, 137],
        vec![1, 130, 2, 0],
    ] {
        let frame = with_ipv4_options(&options);
        assert_eq!(
            decode_frame_checked(DLT_EN10MB, &frame)
                .unwrap()
                .1
                .unwrap()
                .udp,
            "valid"
        );
    }
    let original = with_ipv4_options(&[131, 7, 4, 203, 0, 113, 53, 1]);
    for offset in 14..42 {
        for value in [0, 255, 131, 137] {
            let mut frame = original.clone();
            frame[offset] = value;
            let _ = decode_frame_checked(DLT_EN10MB, &frame);
        }
    }
}
