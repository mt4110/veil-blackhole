use std::net::Ipv4Addr;

use veil_blackhole::decode::{DLT_EN10MB, decode_frame};
use veil_blackhole::dns::decode_query;
use veil_blackhole::error::DecodeError;
use veil_blackhole::fixture::{MAX_HEX_FILE_BYTES, decode_hex};
use veil_blackhole::records::decode_darwin_records;

fn fixture(name: &str) -> Vec<u8> {
    let input = match name {
        "frame" => include_bytes!("fixtures/query-a.hex").as_slice(),
        "options" => include_bytes!("fixtures/query-options.hex").as_slice(),
        "dns" => include_bytes!("fixtures/dns-query-a.hex").as_slice(),
        "records" => include_bytes!("fixtures/bpf-two-records.hex").as_slice(),
        _ => unreachable!(),
    };
    decode_hex(input).unwrap()
}

fn put16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_be_bytes());
}

#[test]
fn fixed_frame_has_independently_annotated_fields() {
    let packet = decode_frame(DLT_EN10MB, &fixture("frame")).unwrap();
    assert_eq!(packet.source_mac, [2, 0, 0, 0, 0, 0x10]);
    assert_eq!(packet.destination_mac, [2, 0, 0, 0, 0, 0x53]);
    assert_eq!(packet.source_ip, Ipv4Addr::new(192, 0, 2, 10));
    assert_eq!(packet.destination_ip, Ipv4Addr::new(198, 51, 100, 53));
    assert_eq!((packet.source_port, packet.destination_port), (53000, 53));
    assert_eq!(packet.dns.id, 0x1234);
    assert_eq!(packet.dns.flags, 0x0100);
    assert_eq!((packet.dns.query_type, packet.dns.query_class), (1, 1));
    assert_eq!(packet.dns.labels, [b"tracker".to_vec(), b"test".to_vec()]);
    assert_eq!(packet.dns.escaped_name(), "tracker.test.");
}

#[test]
fn ipv4_options_use_ihl_and_ethernet_padding_is_not_dns() {
    let mut bytes = fixture("options");
    bytes.extend([0xff; 16]);
    assert_eq!(
        decode_frame(1, &bytes).unwrap().dns.escaped_name(),
        "tracker.test."
    );
}

#[test]
fn every_truncated_prefix_is_rejected_without_panicking() {
    let frame = fixture("frame");
    for len in 0..frame.len() {
        assert!(decode_frame(1, &frame[..len]).is_err(), "length {len}");
    }
    let dns = fixture("dns");
    for len in 0..dns.len() {
        assert!(decode_query(&dns[..len]).is_err(), "DNS length {len}");
    }
}

#[test]
fn ipv4_and_udp_length_boundaries_are_checked() {
    for (offset, value, expected) in [
        (16, 19, "IPv4 total length"),
        (16, 65535, "IPv4 total length"),
        (38, 7, "UDP length"),
        (38, 37, "UDP length"),
        (38, 39, "UDP length"),
    ] {
        let mut frame = fixture("frame");
        put16(&mut frame, offset, value);
        assert_eq!(
            decode_frame(1, &frame),
            Err(DecodeError::Malformed(expected))
        );
    }
    for first in [0x44, 0x4f, 0x65] {
        let mut frame = fixture("frame");
        frame[14] = first;
        assert!(matches!(
            decode_frame(1, &frame),
            Err(DecodeError::Malformed(_))
        ));
    }
    let mut frame = fixture("frame");
    put16(&mut frame, 16, 27);
    assert_eq!(
        decode_frame(1, &frame),
        Err(DecodeError::Malformed("short UDP header"))
    );
}

#[test]
fn fragments_and_unsupported_encapsulations_are_distinct() {
    for fragment in [0x2000, 1, 0x3fff] {
        let mut frame = fixture("frame");
        put16(&mut frame, 20, fragment);
        assert_eq!(
            decode_frame(1, &frame),
            Err(DecodeError::Unsupported("IPv4 fragmentation"))
        );
    }
    let frame = fixture("frame"); // DF is already set and accepted.
    assert!(decode_frame(1, &frame).is_ok());
    assert_eq!(
        decode_frame(0, &frame),
        Err(DecodeError::Unsupported("datalink type"))
    );
    for ether_type in [0x0806, 0x8100, 0x88a8] {
        let mut frame = frame.clone();
        put16(&mut frame, 12, ether_type);
        assert!(matches!(
            decode_frame(1, &frame),
            Err(DecodeError::Unsupported(_))
        ));
    }
    let mut tcp = frame.clone();
    tcp[23] = 6;
    assert_eq!(
        decode_frame(1, &tcp),
        Err(DecodeError::Unsupported("IP protocol is not UDP"))
    );
    let mut response = frame;
    put16(&mut response, 36, 53000);
    assert_eq!(
        decode_frame(1, &response),
        Err(DecodeError::Unsupported("UDP destination port is not 53"))
    );
}

#[test]
fn dns_kind_class_counts_and_trailing_data_are_validated() {
    let mut dns = fixture("dns");
    dns[2] |= 0x80;
    assert_eq!(
        decode_query(&dns),
        Err(DecodeError::Unsupported("DNS response"))
    );
    dns[2] = 0x09;
    assert_eq!(
        decode_query(&dns),
        Err(DecodeError::Unsupported("DNS opcode"))
    );
    for count in [0, 2, 65535] {
        let mut dns = fixture("dns");
        put16(&mut dns, 4, count);
        assert!(matches!(decode_query(&dns), Err(DecodeError::Malformed(_))));
    }
    let mut dns = fixture("dns");
    let len = dns.len();
    put16(&mut dns, len - 2, 3);
    assert_eq!(
        decode_query(&dns),
        Err(DecodeError::Unsupported("DNS class is not IN"))
    );
    let mut dns = fixture("dns");
    dns.push(0);
    assert_eq!(
        decode_query(&dns),
        Err(DecodeError::Malformed("trailing DNS bytes"))
    );
    let mut dns = fixture("dns");
    put16(&mut dns, 6, 65535);
    assert_eq!(
        decode_query(&dns),
        Err(DecodeError::Malformed("DNS section counts exceed message"))
    );
}

#[test]
fn compressed_names_are_validated_in_all_sections() {
    let mut dns = fixture("dns");
    put16(&mut dns, 10, 1);
    // Additional A RR: owner points to the question at offset 12.
    dns.extend(decode_hex(b"c00c 0001 0001 00000000 0004 cb007107").unwrap());
    assert_eq!(decode_query(&dns).unwrap().escaped_name(), "tracker.test.");
    dns.pop();
    assert!(matches!(decode_query(&dns), Err(DecodeError::Malformed(_))));
    for pointer in [b"c00c".as_slice(), b"ffff", b"c00e"] {
        let mut dns = fixture("dns")[..12].to_vec();
        dns.extend(decode_hex(pointer).unwrap());
        dns.extend([0, 1, 0, 1]);
        assert!(matches!(decode_query(&dns), Err(DecodeError::Malformed(_))));
    }
}

#[test]
fn dns_binary_labels_are_terminal_safe_and_name_length_is_bounded() {
    let mut dns = fixture("dns")[..12].to_vec();
    dns.extend([4, 0x1b, b'.', b'\\', 0xff, 0, 0, 1, 0, 1]);
    let name = decode_query(&dns).unwrap().escaped_name();
    assert_eq!(name, "\\027\\046\\092\\255.");
    assert!(!name.contains('\x1b'));
    let mut long = fixture("dns")[..12].to_vec();
    for _ in 0..4 {
        long.push(63);
        long.extend([b'a'; 63]);
    }
    long.extend([0, 0, 1, 0, 1]);
    assert!(matches!(
        decode_query(&long),
        Err(DecodeError::Malformed(_))
    ));
}

#[test]
fn dns_root_and_maximum_wire_name_are_accepted_but_oversized_label_is_rejected() {
    let header = fixture("dns")[..12].to_vec();
    let mut root = header.clone();
    root.extend([0, 0, 65, 0, 1]);
    let query = decode_query(&root).unwrap();
    assert_eq!(query.escaped_name(), ".");
    assert_eq!(query.query_type, 65); // HTTPS query is still a query, not a response.
    let mut max_name = header.clone();
    for length in [63, 63, 63, 61] {
        max_name.push(length);
        max_name.extend(std::iter::repeat_n(b'a', usize::from(length)));
    }
    max_name.extend([0, 0, 1, 0, 1]);
    assert_eq!(decode_query(&max_name).unwrap().labels.len(), 4);
    let mut long_label = header;
    long_label.push(64);
    long_label.extend([b'a'; 64]);
    long_label.extend([0, 0, 1, 0, 1]);
    assert!(matches!(
        decode_query(&long_label),
        Err(DecodeError::Malformed(_))
    ));
}

#[test]
fn edns_and_unknown_rr_are_parsed_without_dnssec_validation() {
    let mut dns = fixture("dns");
    put16(&mut dns, 10, 1);
    dns.extend(decode_hex(b"00 0029 04d0 00008000 0000").unwrap());
    assert!(decode_query(&dns).is_ok());
    let mut unknown = fixture("dns");
    put16(&mut unknown, 10, 1);
    unknown.extend(decode_hex(b"c00c fde8 0001 00000000 0003 010203").unwrap());
    assert!(decode_query(&unknown).is_ok());
}

#[test]
fn bpf_multiple_records_alignment_and_final_record_without_padding() {
    let bytes = fixture("records");
    let records = decode_darwin_records(&bytes).unwrap();
    assert_eq!(records.len(), 2);
    for record in records {
        assert_eq!((record.seconds, record.microseconds), (1, 2));
        assert_eq!(record.original_len, 72);
        assert!(!record.truncated);
        assert!(decode_frame(1, record.frame).is_ok());
    }
    let mut with_padding = bytes;
    with_padding.extend([0; 2]);
    assert_eq!(decode_darwin_records(&with_padding).unwrap().len(), 2);
}

#[test]
fn darwin_wire_header_is_18_bytes_even_when_c_struct_size_is_20() {
    let frame = fixture("frame");
    let mut bytes = vec![0; 18];
    bytes[8..12].copy_from_slice(&(frame.len() as u32).to_le_bytes());
    bytes[12..16].copy_from_slice(&(frame.len() as u32).to_le_bytes());
    bytes[16..18].copy_from_slice(&18u16.to_le_bytes());
    bytes.extend_from_slice(&frame);
    let records = decode_darwin_records(&bytes).expect("Darwin's 18-byte wire header is valid");
    assert_eq!(records.len(), 1);
    assert_eq!(decode_frame(1, records[0].frame).unwrap().dns.id, 0x1234);
    // 18 + 72 = 90; next record begins at the 4-byte boundary 92.
    let mut two = bytes.clone();
    two.extend([0; 2]);
    two.extend(bytes);
    assert_eq!(decode_darwin_records(&two).unwrap().len(), 2);
}

#[test]
fn wire_header_field_bounds_and_variable_padding_are_validated() {
    let frame = fixture("frame");
    for hdrlen in [18usize, 20, 22] {
        let mut bytes = vec![0; hdrlen];
        bytes[8..12].copy_from_slice(&(frame.len() as u32).to_le_bytes());
        bytes[12..16].copy_from_slice(&(frame.len() as u32).to_le_bytes());
        bytes[16..18].copy_from_slice(&(hdrlen as u16).to_le_bytes());
        bytes.extend_from_slice(&frame);
        assert_eq!(decode_darwin_records(&bytes).unwrap()[0].frame, frame);
    }
    let mut empty = vec![0; 18];
    empty[16..18].copy_from_slice(&18u16.to_le_bytes());
    assert!(decode_darwin_records(&empty).unwrap()[0].frame.is_empty());
    for len in 1..18 {
        assert_eq!(
            decode_darwin_records(&empty[..len]),
            Err(DecodeError::Malformed("short BPF header"))
        );
    }
    empty[16..18].copy_from_slice(&17u16.to_le_bytes());
    assert!(decode_darwin_records(&empty).is_err());
}

#[test]
fn bpf_lengths_truncation_and_short_headers_are_checked() {
    let bytes = fixture("records");
    for len in 1..20 {
        assert!(decode_darwin_records(&bytes[..len]).is_err());
    }
    for (offset, replacement) in [(8, 1000u32), (12, 71), (4, 1_000_000)] {
        let mut bad = bytes.clone();
        bad[offset..offset + 4].copy_from_slice(&replacement.to_le_bytes());
        assert!(matches!(
            decode_darwin_records(&bad),
            Err(DecodeError::Malformed(_))
        ));
    }
    let mut bad = bytes.clone();
    bad[16..18].copy_from_slice(&17u16.to_le_bytes());
    assert!(decode_darwin_records(&bad).is_err());
    let mut truncated = bytes;
    truncated[12..16].copy_from_slice(&80u32.to_le_bytes());
    assert!(decode_darwin_records(&truncated).unwrap()[0].truncated);
}

#[test]
fn hex_inputs_are_bounded_and_not_echoed() {
    assert_eq!(decode_hex(b"0a FF\n10").unwrap(), [10, 255, 16]);
    for input in [b"".as_slice(), b"f", b"\x1bsecret", b"zz"] {
        let error = decode_hex(input).unwrap_err().to_string();
        assert!(!error.contains("secret"));
        assert!(!error.contains('\x1b'));
    }
    assert!(decode_hex(&vec![b'0'; MAX_HEX_FILE_BYTES + 1]).is_err());
}

#[test]
fn bounded_adversarial_corpus_does_not_panic() {
    // Deterministic mutation smoke test, not a claim of exhaustive fuzzing.
    let frame = fixture("frame");
    let dns = fixture("dns");
    let records = fixture("records");
    for original in [&frame, &dns, &records] {
        for index in 0..original.len() {
            for value in [0, 0xff, 0xc0] {
                let mut bytes = original.clone();
                bytes[index] = value;
                let _ = decode_frame(1, &bytes);
                let _ = decode_query(&bytes);
                let _ = decode_darwin_records(&bytes);
            }
        }
    }
}
