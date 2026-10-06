use std::ffi::OsString;
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::time::Duration;
use veil_blackhole::bpf::CaptureOptions;

use veil_blackhole::decode::{DLT_EN10MB, decode_frame_checked, decode_frame_offline};
use veil_blackhole::dns::{DnsQuery, decode_query};
use veil_blackhole::error::DecodeError;
use veil_blackhole::fixture::{MAX_HEX_FILE_BYTES, decode_hex};
use veil_blackhole::records::decode_darwin_records;

const HELP: &str = "veil-blackhole — Phase 1 読み取り専用DNSアナライザー

使い方:
  veil-blackhole replay --fixture PATH [--format ethernet|dns|bpf-darwin]
                        [--show-names] [--show-endpoints] [--verify-checksums]
  veil-blackhole capture --interface NAME --duration SECONDS
                         [--show-names] [--show-endpoints]

fixtureはASCII hexの通常ファイルです（最大1 MiB）。既定formatはethernet。
既定は集計のみ。名前/IPは明示表示。replayの--verify-checksumsでIP/UDPを検証。
bpf-darwinはclassic Darwin LE record用です。
replayはpadding-onlyのIPv6 Hop-by-Hop/Destination Optionsに対応。DNS単体のchecksum検証は不可。
liveはmacOSのDLT_EN10MB・IPv4/IPv6（拡張ヘッダーなし）・非断片化UDP宛先53番・送信方向に限定。
liveの検証範囲はdocs/IPV6_VALIDATION.mdを参照。replay/build/testにsudoは不要です。
送信、遮断、OSネットワーク設定変更、pcap保存は提供しません。";

#[derive(Clone, Copy)]
enum Format {
    Ethernet,
    Dns,
    BpfDarwin,
}

struct Replay {
    path: PathBuf,
    format: Format,
    verify_checksums: bool,
    show_names: bool,
    show_endpoints: bool,
}

enum Command {
    Help,
    Replay(Replay),
    Capture(CaptureOptions),
}

fn parse_args(args: Vec<OsString>) -> Result<Command, &'static str> {
    let Some(command) = args.first() else {
        return Ok(Command::Help);
    };
    if command == "--help" || command == "-h" {
        return if args.len() == 1 {
            Ok(Command::Help)
        } else {
            Err("helpには追加引数を指定できません")
        };
    }
    if command == "capture" {
        let mut interface = None;
        let mut duration = None;
        let mut show_names = false;
        let mut show_endpoints = false;
        let mut i = 1;
        while i < args.len() {
            if args[i] == "--show-names" && !show_names {
                show_names = true;
                i += 1;
                continue;
            }
            if args[i] == "--show-endpoints" && !show_endpoints {
                show_endpoints = true;
                i += 1;
                continue;
            }
            let value = args.get(i + 1).ok_or("capture引数の値がありません")?;
            if args[i] == "--interface" && interface.is_none() {
                interface = Some(
                    value
                        .to_str()
                        .filter(|s| !s.is_empty())
                        .ok_or("interfaceが不正です")?,
                );
            } else if args[i] == "--duration" && duration.is_none() {
                duration = Some(
                    value
                        .to_str()
                        .and_then(|s| s.parse::<u32>().ok())
                        .filter(|v| (1..=3600).contains(v))
                        .ok_or("durationは1〜3600秒です")?,
                );
            } else {
                return Err("未知または重複したcapture引数です");
            }
            i += 2;
        }
        if interface.is_none() || duration.is_none() {
            return Err("captureには--interfaceと--durationが必要です");
        }
        let options = CaptureOptions {
            interface: interface.expect("checked interface").to_owned(),
            duration: Duration::from_secs(u64::from(duration.expect("checked duration"))),
            show_names,
            show_endpoints,
        };
        options
            .validate()
            .map_err(|_| "captureのinterfaceまたはdurationが不正です")?;
        return Ok(Command::Capture(options));
    }
    if command != "replay" {
        return Err("未知のコマンドです。--helpを参照してください");
    }
    let mut path = None;
    let mut format = None;
    let mut verify_checksums = false;
    let mut show_names = false;
    let mut show_endpoints = false;
    let mut i = 1;
    while i < args.len() {
        if args[i] == "--show-names" && !show_names {
            show_names = true;
            i += 1;
        } else if args[i] == "--show-endpoints" && !show_endpoints {
            show_endpoints = true;
            i += 1;
        } else if args[i] == "--verify-checksums" && !verify_checksums {
            verify_checksums = true;
            i += 1;
        } else if args[i] == "--fixture" && path.is_none() {
            path = Some(PathBuf::from(
                args.get(i + 1).ok_or("fixtureの値がありません")?,
            ));
            i += 2;
        } else if args[i] == "--format" && format.is_none() {
            format = Some(match args.get(i + 1).and_then(|s| s.to_str()) {
                Some("ethernet") => Format::Ethernet,
                Some("dns") => Format::Dns,
                Some("bpf-darwin") => Format::BpfDarwin,
                _ => return Err("formatはethernet、dns、bpf-darwinから選びます"),
            });
            i += 2;
        } else {
            return Err("未知または重複したreplay引数です");
        }
    }
    if verify_checksums && matches!(format, Some(Format::Dns)) {
        return Err("DNS単体にはIP/UDP headerがなくチェックサム検証できません");
    }
    Ok(Command::Replay(Replay {
        path: path.ok_or("--fixtureが必要です")?,
        format: format.unwrap_or(Format::Ethernet),
        verify_checksums,
        show_names,
        show_endpoints,
    }))
}

#[derive(Default)]
struct Counts {
    queries: usize,
    unsupported: usize,
    malformed: usize,
    truncated: usize,
}

fn display_query(out: &mut impl Write, query: &DnsQuery, show: bool) -> io::Result<()> {
    if show {
        writeln!(
            out,
            "query id={} type={} class={} name={}",
            query.id,
            query.query_type,
            query.query_class,
            query.escaped_name()
        )?;
    }
    Ok(())
}

fn display_frame(
    out: &mut impl Write,
    frame: &[u8],
    options: &Replay,
    counts: &mut Counts,
) -> io::Result<()> {
    let decoded = if options.verify_checksums {
        decode_frame_checked(DLT_EN10MB, frame)
    } else {
        decode_frame_offline(DLT_EN10MB, frame).map(|packet| (packet, None))
    };
    match decoded {
        Ok((packet, checksum)) => {
            if let Some(checksum) = checksum {
                writeln!(
                    out,
                    "checksum ipv4_header={} udp={}",
                    checksum.ipv4_header, checksum.udp
                )?;
            }
            counts.queries += 1;
            display_query(out, &packet.dns, options.show_names)?;
            if options.show_endpoints {
                writeln!(
                    out,
                    "endpoint {} -> {}",
                    std::net::SocketAddr::new(packet.source_ip, packet.source_port),
                    std::net::SocketAddr::new(packet.destination_ip, packet.destination_port)
                )?;
            }
        }
        Err(error) => record_error(out, error, counts)?,
    }
    Ok(())
}

fn record_error(out: &mut impl Write, error: DecodeError, counts: &mut Counts) -> io::Result<()> {
    match error {
        DecodeError::Unsupported(_) => counts.unsupported += 1,
        DecodeError::TruncatedCapture => counts.truncated += 1,
        _ => counts.malformed += 1,
    }
    writeln!(out, "{error}")
}

fn replay(options: &Replay, out: &mut impl Write) -> Result<i32, &'static str> {
    // Do not deliberately open directories, devices, symlinks, or FIFO inputs.
    let metadata =
        std::fs::symlink_metadata(&options.path).map_err(|_| "fixtureの情報を取得できません")?;
    if !metadata.is_file() {
        return Err("fixtureはsymlinkやdeviceではない通常ファイルを指定してください");
    }
    let file = File::open(&options.path).map_err(|_| "fixtureを開けません")?;
    if !file
        .metadata()
        .map_err(|_| "fixtureの情報を確認できません")?
        .is_file()
    {
        return Err("開いたfixtureは通常ファイルではありません");
    }
    let mut input = Vec::new();
    file.take(MAX_HEX_FILE_BYTES as u64 + 1)
        .read_to_end(&mut input)
        .map_err(|_| "fixtureを読み込めません")?;
    let bytes = match decode_hex(&input) {
        Ok(bytes) => bytes,
        Err(_) => return Err("fixtureは最大1 MiBの偶数桁ASCII hexで指定してください"),
    };
    let mut counts = Counts::default();
    let mut render = || -> io::Result<()> {
        writeln!(
            out,
            "mode=offline checksum={} direction=unverified",
            if options.verify_checksums {
                "verification-enabled"
            } else {
                "unverified"
            }
        )?;
        match options.format {
            Format::Ethernet => display_frame(out, &bytes, options, &mut counts)?,
            Format::Dns => match decode_query(&bytes) {
                Ok(query) => {
                    counts.queries += 1;
                    display_query(out, &query, options.show_names)?;
                }
                Err(error) => record_error(out, error, &mut counts)?,
            },
            Format::BpfDarwin => match decode_darwin_records(&bytes) {
                Ok(records) => {
                    for record in records {
                        if record.truncated {
                            record_error(out, DecodeError::TruncatedCapture, &mut counts)?;
                        } else {
                            display_frame(out, record.frame, options, &mut counts)?;
                        }
                    }
                }
                Err(error) => record_error(out, error, &mut counts)?,
            },
        }
        writeln!(
            out,
            "queries={} unsupported={} malformed={} truncated={}",
            counts.queries, counts.unsupported, counts.malformed, counts.truncated
        )
    };
    if let Err(error) = render() {
        return if error.kind() == io::ErrorKind::BrokenPipe {
            Ok(0)
        } else {
            Err("標準出力への表示に失敗しました")
        };
    }
    Ok(if counts.malformed > 0 || counts.truncated > 0 {
        2
    } else {
        0
    })
}

fn main() {
    let code = match parse_args(std::env::args_os().skip(1).collect()) {
        Err(error) => {
            eprintln!("{error}");
            2
        }
        Ok(Command::Help) => {
            let _ = writeln!(io::stdout().lock(), "{HELP}");
            0
        }
        Ok(Command::Capture(options)) => {
            let mut out = io::stdout().lock();
            match veil_blackhole::bpf::capture(options, &mut out) {
                Ok(counts) => {
                    let result = writeln!(
                        out,
                        "queries={} unsupported={} malformed={} truncated={} display_dropped={} kernel_received={} kernel_dropped={} interrupted={}",
                        counts.queries,
                        counts.unsupported,
                        counts.malformed,
                        counts.truncated,
                        counts.display_dropped,
                        counts.kernel_received,
                        counts.kernel_dropped,
                        counts.interrupted
                    );
                    if result.is_err() {
                        3
                    } else if counts.interrupted {
                        130
                    } else {
                        0
                    }
                }
                Err(error) => {
                    eprintln!("{error}");
                    3
                }
            }
        }
        Ok(Command::Replay(options)) => {
            let mut out = io::stdout().lock();
            match replay(&options, &mut out) {
                Ok(code) => code,
                Err(error) => {
                    eprintln!("{error}");
                    2
                }
            }
        }
    };
    std::process::exit(code);
}
