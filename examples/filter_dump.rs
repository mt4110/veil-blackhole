//! Fixed synthetic identities only; never inspect an interface or open BPF.
use std::net::Ipv4Addr;
use veil_blackhole::filter::query_filter;

fn main() {
    let program = query_filter(&[
        Ipv4Addr::new(203, 0, 113, 1).into(),
        Ipv4Addr::new(192, 0, 2, 10).into(),
        "2001:db8::10".parse().expect("fixed IPv6"),
        "2001:db8:1::11".parse().expect("fixed IPv6"),
    ])
    .expect("fixed addresses");
    for i in program {
        println!("{} {} {} {}", i.code, i.jt, i.jf, i.k);
    }
}
