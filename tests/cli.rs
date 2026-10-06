use std::process::{Command, Output};

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_veil-blackhole"))
        .args(args)
        .output()
        .unwrap()
}

#[test]
fn defaults_to_help_and_invalid_live_args_fail_before_device_access() {
    let help = run(&[]);
    assert!(help.status.success());
    assert!(String::from_utf8_lossy(&help.stdout).contains("読み取り専用"));
    // Never call a valid capture command in an unprivileged test suite: a
    // developer may already have BPF access. Invalid name must fail pre-open.
    let live = run(&["capture", "--interface", "bad/name", "--duration", "60"]);
    assert_eq!(live.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&live.stderr).contains("不正"));
}

#[test]
fn names_and_endpoints_are_hidden_unless_requested() {
    let args = ["replay", "--fixture", "tests/fixtures/query-a.hex"];
    let hidden = run(&args);
    assert!(hidden.status.success());
    let text = String::from_utf8_lossy(&hidden.stdout);
    assert!(text.contains("queries=1"));
    assert!(!text.contains("tracker"));
    assert!(!text.contains("192.0.2.10"));
    let shown = run(&[
        args[0],
        args[1],
        args[2],
        "--show-names",
        "--show-endpoints",
    ]);
    let text = String::from_utf8_lossy(&shown.stdout);
    assert!(shown.status.success());
    assert!(text.contains("name=tracker.test."));
    assert!(text.contains("192.0.2.10:53000 -> 198.51.100.53:53"));
    assert!(text.contains("checksum=unverified direction=unverified"));
}

#[test]
fn replays_dns_and_multiple_bpf_records() {
    for (file, format, count) in [
        ("tests/fixtures/dns-query-a.hex", "dns", 1),
        ("tests/fixtures/bpf-two-records.hex", "bpf-darwin", 2),
    ] {
        let output = run(&["replay", "--fixture", file, "--format", format]);
        assert!(output.status.success());
        assert!(String::from_utf8_lossy(&output.stdout).contains(&format!("queries={count}")));
    }
}

#[test]
fn invalid_input_and_options_fail_explicitly() {
    let bad = run(&["replay", "--fixture", "tests/fixtures/bad-udp-length.hex"]);
    assert_eq!(bad.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&bad.stdout).contains("malformed=1"));
    for args in [
        vec!["replay"],
        vec![
            "replay",
            "--fixture",
            "tests/fixtures/query-a.hex",
            "--unknown",
        ],
        vec!["capture", "--interface", "en0", "--duration", "0"],
        vec!["capture", "--interface", "en0"],
        vec!["replay", "--fixture", "tests/fixtures"],
    ] {
        assert_eq!(run(&args).status.code(), Some(2));
    }
}

#[test]
fn ipv6_replay_is_private_by_default_and_formats_opt_in_endpoints() {
    let private = run(&["replay", "--fixture", "tests/fixtures/query-v6.hex"]);
    assert!(private.status.success());
    let text = String::from_utf8_lossy(&private.stdout);
    assert!(text.contains("queries=1"));
    assert!(!text.contains("2001:db8"));
    assert!(!text.contains("tracker"));
    let shown = run(&[
        "replay",
        "--fixture",
        "tests/fixtures/query-v6.hex",
        "--show-endpoints",
    ]);
    assert!(shown.status.success());
    assert!(
        String::from_utf8_lossy(&shown.stdout)
            .contains("[2001:db8::10]:53000 -> [2001:db8::53]:53")
    );
}
