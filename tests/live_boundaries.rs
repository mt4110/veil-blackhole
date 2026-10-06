use std::net::Ipv4Addr;
use std::time::Duration;
use veil_blackhole::bpf::CaptureOptions;
use veil_blackhole::filter::{Instruction, SNAPLEN, query_filter};
use veil_blackhole::fixture::decode_hex;
use veil_blackhole::privilege::{DropOperations, drop_privileges};

// A small test interpreter, not used by the application. Loads fail closed
// when a capture prefix is too short, like classic BPF's interpreter.
fn evaluate(program: &[Instruction], bytes: &[u8]) -> u32 {
    let (mut a, mut x, mut pc) = (0u32, 0usize, 0usize);
    for _ in 0..program.len() {
        let i = program[pc];
        pc += 1;
        let offset = i.k as usize;
        match i.code {
            0x20 | 0x28 | 0x30 | 0x48 => {
                let offset = if i.code == 0x48 { offset + x } else { offset };
                let size = match i.code {
                    0x20 => 4,
                    0x30 => 1,
                    _ => 2,
                };
                let Some(data) = bytes.get(offset..offset + size) else {
                    return 0;
                };
                a = data
                    .iter()
                    .fold(0, |acc, byte| (acc << 8) | u32::from(*byte));
            }
            0xb1 => {
                let Some(byte) = bytes.get(offset) else {
                    return 0;
                };
                x = usize::from(byte & 0x0f) * 4;
            }
            0x54 => a &= i.k,
            0x15 | 0x35 | 0x45 => {
                let passed = match i.code {
                    0x15 => a == i.k,
                    0x35 => a >= i.k,
                    _ => a & i.k != 0,
                };
                pc += usize::from(if passed { i.jt } else { i.jf });
            }
            0x06 => return i.k,
            _ => panic!("unexpected opcode"),
        }
        assert!(pc < program.len(), "jump must remain inside filter");
    }
    panic!("filter did not terminate")
}

fn frame() -> Vec<u8> {
    decode_hex(include_bytes!("fixtures/query-a.hex")).unwrap()
}

#[test]
fn filter_accepts_local_dns_options_and_each_source_address() {
    let program = query_filter(&[
        Ipv4Addr::new(203, 0, 113, 1).into(),
        Ipv4Addr::new(192, 0, 2, 10).into(),
    ])
    .unwrap();
    assert_eq!(evaluate(&program, &frame()), SNAPLEN);
    let options = decode_hex(include_bytes!("fixtures/query-options.hex")).unwrap();
    assert_eq!(evaluate(&program, &options), SNAPLEN);
    let mut first = frame();
    first[26..30].copy_from_slice(&[203, 0, 113, 1]);
    assert_eq!(evaluate(&program, &first), SNAPLEN);
}

#[test]
fn filter_rejects_other_hosts_protocols_fragments_and_invalid_headers() {
    let program = query_filter(&[Ipv4Addr::new(192, 0, 2, 10).into()]).unwrap();
    for (offset, value) in [
        (12, 0x86),
        (14, 0x65),
        (14, 0x44),
        (23, 6),
        (20, 0x20),
        (20, 0x80),
        (21, 1),
        (29, 11),
        (37, 54),
    ] {
        let mut changed = frame();
        changed[offset] = value;
        assert_eq!(evaluate(&program, &changed), 0, "offset {offset}");
    }
    for length in 0..38 {
        assert_eq!(evaluate(&program, &frame()[..length]), 0);
    }
    assert!(query_filter(&[]).is_err());
    assert!(query_filter(&[Ipv4Addr::LOCALHOST.into(); 17]).is_err());
}

#[test]
fn filter_jump_offsets_remain_valid_at_address_limit() {
    let addresses: Vec<_> = (1..=16)
        .map(|last| std::net::IpAddr::from(Ipv4Addr::new(192, 0, 2, last)))
        .collect();
    let program = query_filter(&addresses).unwrap();
    assert_eq!(evaluate(&program, &frame()), SNAPLEN);
    let mut other = frame();
    other[29] = 17;
    assert_eq!(evaluate(&program, &other), 0);
}

#[test]
fn ipv6_filter_matches_all_address_words_and_separate_ipv4_branch() {
    let addresses = [
        "192.0.2.10".parse().unwrap(),
        "2001:db8:1::11".parse().unwrap(),
        "2001:db8::10".parse().unwrap(),
    ];
    let program = query_filter(&addresses).unwrap();
    let bytes = decode_hex(include_bytes!("fixtures/query-v6.hex")).unwrap();
    assert_eq!(evaluate(&program, &bytes), SNAPLEN);
    assert_eq!(evaluate(&program, &frame()), SNAPLEN);
    let mut other_allowed = bytes.clone();
    let other: std::net::Ipv6Addr = "2001:db8:1::11".parse().unwrap();
    other_allowed[22..38].copy_from_slice(&other.octets());
    assert_eq!(evaluate(&program, &other_allowed), SNAPLEN);
    for offset in [22, 26, 30, 37] {
        let mut other = bytes.clone();
        other[offset] ^= 1;
        assert_eq!(evaluate(&program, &other), 0, "source word at {offset}");
    }
    for (offset, value) in [(14, 0x45), (20, 0), (20, 44), (20, 6), (57, 54)] {
        let mut other = bytes.clone();
        other[offset] = value;
        assert_eq!(evaluate(&program, &other), 0);
    }
    for length in 0..58 {
        assert_eq!(evaluate(&program, &bytes[..length]), 0);
    }
}

#[test]
fn ipv6_only_and_maximum_address_filter_branches_terminate_correctly() {
    let addresses: Vec<_> = (1..=16)
        .map(|last| std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, last).into())
        .collect();
    let program = query_filter(&addresses).unwrap();
    assert!(program.len() < 512);
    let bytes = decode_hex(include_bytes!("fixtures/query-v6.hex")).unwrap();
    assert_eq!(evaluate(&program, &bytes), SNAPLEN);
    assert_eq!(evaluate(&program, &frame()), 0);
    let mut other = bytes.clone();
    other[37] = 17;
    assert_eq!(evaluate(&program, &other), 0);
    let v4_only = query_filter(&[Ipv4Addr::new(192, 0, 2, 10).into()]).unwrap();
    assert_eq!(evaluate(&v4_only, &bytes), 0);
}

struct MockDrop {
    fail: Option<usize>,
    called: Vec<usize>,
}
impl MockDrop {
    fn step(&mut self, number: usize) -> Result<(), String> {
        self.called.push(number);
        if self.fail == Some(number) {
            Err("injected failure".into())
        } else {
            Ok(())
        }
    }
}
impl DropOperations for MockDrop {
    fn initialize_groups(&mut self) -> Result<(), String> {
        self.step(0)
    }
    fn set_gid(&mut self) -> Result<(), String> {
        self.step(1)
    }
    fn set_uid(&mut self) -> Result<(), String> {
        self.step(2)
    }
    fn verify(&mut self) -> Result<(), String> {
        self.step(3)
    }
}

#[test]
fn credential_failures_stop_before_subsequent_steps_and_capture_start() {
    for fail in 0..4 {
        let mut operations = MockDrop {
            fail: Some(fail),
            called: vec![],
        };
        let mut capture_started = false;
        if drop_privileges(&mut operations).is_ok() {
            capture_started = true;
        }
        assert!(!capture_started);
        assert_eq!(operations.called, (0..=fail).collect::<Vec<_>>());
    }
    let mut operations = MockDrop {
        fail: None,
        called: vec![],
    };
    assert!(drop_privileges(&mut operations).is_ok());
    assert_eq!(operations.called, vec![0, 1, 2, 3]);
}

#[test]
fn capture_options_are_validated_without_os_access() {
    let mut options = CaptureOptions {
        interface: "en0".into(),
        duration: Duration::from_secs(1),
        show_names: false,
        show_endpoints: false,
    };
    assert!(options.validate().is_ok());
    for name in ["", "bad/name", "en0\0", "0123456789012345", "名前"] {
        options.interface = name.into();
        assert!(options.validate().is_err());
    }
    options.interface = "en0".into();
    for seconds in [0, 3601] {
        options.duration = Duration::from_secs(seconds);
        assert!(options.validate().is_err());
    }
}
