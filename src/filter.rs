//! Fixed classic BPF program; offsets are relative to untagged Ethernet.
use std::net::IpAddr;

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Instruction {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

pub const MAX_ADDRESSES: usize = 16;
pub const SNAPLEN: u32 = 65535 + 40 + 14;

pub fn query_filter(addresses: &[IpAddr]) -> Result<Vec<Instruction>, &'static str> {
    if addresses.is_empty() || addresses.len() > MAX_ADDRESSES {
        return Err("interfaceには1〜16個のIPアドレスが必要です");
    }
    let stmt = |code, k| Instruction {
        code,
        jt: 0,
        jf: 0,
        k,
    };
    let mut p = vec![
        stmt(0x28, 12),     // LD H ABS: EtherType
        stmt(0x15, 0x0800), // JEQ IPv4, else branch to IPv6
        stmt(0x30, 14),     // LD B ABS: version/IHL
        stmt(0x54, 0xf0),   // AND
        stmt(0x15, 0x40),
        stmt(0x30, 14),
        stmt(0x54, 0x0f),
        stmt(0x35, 5), // JGE minimum IHL
        stmt(0x30, 23),
        stmt(0x15, 17), // UDP
        stmt(0x28, 20),
        stmt(0x45, 0xbfff), // JSET reserved/MF/offset, allow DF only
        stmt(0x20, 26),     // LD W ABS: source address
    ];
    let v4: Vec<_> = addresses
        .iter()
        .filter_map(|address| match address {
            IpAddr::V4(address) => Some(*address),
            _ => None,
        })
        .collect();
    for address in &v4 {
        p.push(stmt(0x15, u32::from(*address)));
    }
    p.push(stmt(0x06, 0)); // no source match
    let udp = p.len();
    p.extend([
        stmt(0xb1, 14), // LDX B MSH: IPv4 IHL * 4
        stmt(0x48, 16), // LD H IND: Ethernet + IHL + destination port
        stmt(0x15, 53),
        stmt(0x06, SNAPLEN),
        stmt(0x06, 0),
    ]);
    let v4_reject = p.len() - 1;
    for i in [4, 7, 9, udp + 2] {
        p[i].jf = (v4_reject - i - 1) as u8;
    }
    p[11].jt = (v4_reject - 12) as u8;
    for (i, instruction) in p.iter_mut().enumerate().skip(13).take(v4.len()) {
        instruction.jt = (udp - i - 1) as u8;
    }
    let v6 = p.len();
    p[1].jf = (v6 - 2) as u8;
    // A still contains EtherType on this branch.
    p.extend([
        stmt(0x15, 0x86dd),
        stmt(0x30, 14),
        stmt(0x54, 0xf0),
        stmt(0x15, 0x60),
        stmt(0x30, 20),
        stmt(0x15, 17),
    ]);
    let mut source_checks = Vec::new();
    for address in addresses {
        let IpAddr::V6(address) = address else {
            continue;
        };
        let start = p.len();
        for (word, bytes) in address.octets().as_chunks::<4>().0.iter().enumerate() {
            p.push(stmt(0x20, (22 + word * 4) as u32));
            p.push(stmt(0x15, u32::from_be_bytes(*bytes)));
        }
        // Failed partial address comparisons continue at the next address.
        for word in 0..4 {
            p[start + word * 2 + 1].jf = (6 - word * 2) as u8;
        }
        source_checks.push(start + 7);
    }
    p.push(stmt(0x06, 0));
    let v6_udp = p.len();
    p.extend([
        stmt(0x28, 56),
        stmt(0x15, 53),
        stmt(0x06, SNAPLEN),
        stmt(0x06, 0),
    ]);
    let reject = p.len() - 1;
    for i in [v6, v6 + 3, v6 + 5, v6_udp + 1] {
        p[i].jf = (reject - i - 1) as u8;
    }
    for i in source_checks {
        p[i].jt = (v6_udp - i - 1) as u8;
    }
    Ok(p)
}
