//! Read-only live capture. Parsing starts only after verified privilege reduction.
use std::time::Duration;

#[derive(Clone, Debug)]
pub struct CaptureOptions {
    pub interface: String,
    pub duration: Duration,
    pub show_names: bool,
    pub show_endpoints: bool,
}

impl CaptureOptions {
    pub fn validate(&self) -> Result<(), String> {
        if self.interface.is_empty()
            || self.interface.len() >= 16
            || !self
                .interface
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
        {
            return Err("interface名は1〜15文字の英数字・_・-で指定してください".into());
        }
        if self.duration < Duration::from_secs(1) || self.duration > Duration::from_secs(3600) {
            return Err("durationは1〜3600秒です".into());
        }
        Ok(())
    }
}

#[derive(Default, Debug)]
pub struct CaptureCounts {
    pub queries: u64,
    pub unsupported: u64,
    pub malformed: u64,
    pub truncated: u64,
    pub display_dropped: u64,
    pub kernel_received: u32,
    pub kernel_dropped: u32,
    pub interrupted: bool,
}

#[cfg(target_os = "macos")]
mod live {
    use super::*;
    use crate::{
        decode::{DLT_EN10MB, PacketQuery, decode_frame},
        error::DecodeError,
        filter::query_filter,
        platform::{self, Credentials, Device, Interface, Signals},
        privilege::drop_privileges,
        records::decode_darwin_records,
    };
    use std::io::{self, Write};
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    };
    use std::thread;
    use std::time::Instant;

    struct Worker {
        stop: Arc<AtomicBool>,
        handle: Option<thread::JoinHandle<Result<CaptureCounts, String>>>,
    }
    impl Worker {
        fn finish(mut self) -> Result<CaptureCounts, String> {
            self.stop.store(true, Ordering::Relaxed);
            self.handle
                .take()
                .expect("worker owned")
                .join()
                .map_err(|_| "capture workerが異常終了しました".to_owned())?
        }
    }
    impl Drop for Worker {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Relaxed);
            if let Some(handle) = self.handle.take() {
                let _ = handle.join();
            }
        }
    }

    trait CaptureSource {
        fn buffer_len(&self) -> usize;
        fn matches_interface(&self) -> Result<bool, String>;
        fn read(&mut self, buffer: &mut [u8], milliseconds: i32) -> Result<Option<usize>, String>;
        fn stats(&self) -> Result<(u32, u32), String>;
    }
    struct LiveSource {
        device: Device,
        name: String,
        snapshot: Interface,
    }
    impl CaptureSource for LiveSource {
        fn buffer_len(&self) -> usize {
            self.device.buffer_len
        }
        fn matches_interface(&self) -> Result<bool, String> {
            Ok(platform::interface(&self.name)? == self.snapshot)
        }
        fn read(&mut self, buffer: &mut [u8], milliseconds: i32) -> Result<Option<usize>, String> {
            self.device.read(buffer, milliseconds)
        }
        fn stats(&self) -> Result<(u32, u32), String> {
            self.device.stats()
        }
    }

    fn capture_loop(
        mut device: impl CaptureSource,
        snapshot: Interface,
        options: CaptureOptions,
        stop: Arc<AtomicBool>,
        events: mpsc::SyncSender<PacketQuery>,
    ) -> Result<CaptureCounts, String> {
        let started = Instant::now();
        let mut next_interface_check = started;
        let mut buffer = vec![0; device.buffer_len()];
        let mut counts = CaptureCounts::default();
        while started.elapsed() < options.duration && !stop.load(Ordering::Relaxed) {
            if platform::interrupted() {
                counts.interrupted = true;
                break;
            }
            if Instant::now() >= next_interface_check {
                let matches = device.matches_interface().map_err(|reason| {
                    format!("取得中に対象インターフェースの情報を再確認できないため停止しました: {reason}")
                })?;
                if !matches {
                    return Err("interfaceのindex・IP・flagsが変わったため停止しました".into());
                }
                next_interface_check = Instant::now() + Duration::from_millis(500);
            }
            let remaining = options.duration.saturating_sub(started.elapsed());
            let milliseconds = remaining.as_millis().min(100) as i32;
            let Some(length) = device.read(&mut buffer, milliseconds)? else {
                continue;
            };
            let records = decode_darwin_records(&buffer[..length]).map_err(|error| {
                // Only static error reason and record lengths; no packet bytes,
                // timestamps, IPs, domains, or MACs are printed on failure.
                let first_hdrlen = buffer[..length].get(16..18)
                    .map(|b| u16::from_le_bytes([b[0], b[1]]));
                format!("BPF recordの構造が不正です。取得を停止しました: {error}; read_bytes={length} first_hdrlen={first_hdrlen:?}")
            })?;
            for record in records {
                if stop.load(Ordering::Relaxed)
                    || platform::interrupted()
                    || started.elapsed() >= options.duration
                {
                    break;
                }
                if record.truncated {
                    counts.truncated += 1;
                    continue;
                }
                match decode_frame(DLT_EN10MB, record.frame) {
                    Ok(packet) => {
                        if !snapshot.addresses.contains(&packet.source_ip) {
                            return Err("限定filter外の送信元を受信したため停止しました".into());
                        }
                        counts.queries += 1;
                        if options.show_names || options.show_endpoints {
                            match events.try_send(packet) {
                                Ok(()) => (),
                                Err(mpsc::TrySendError::Full(_)) => counts.display_dropped += 1,
                                Err(mpsc::TrySendError::Disconnected(_)) => {
                                    return Err("表示channelが終了しました".into());
                                }
                            }
                        }
                    }
                    Err(DecodeError::Unsupported(_)) => counts.unsupported += 1,
                    Err(_) => counts.malformed += 1,
                }
            }
        }
        counts.interrupted |= platform::interrupted();
        (counts.kernel_received, counts.kernel_dropped) = device.stats()?;
        Ok(counts)
    }

    /// Intended for a fresh single-threaded CLI, not an embedded library host.
    pub fn capture(options: CaptureOptions, out: &mut impl Write) -> Result<CaptureCounts, String> {
        options.validate()?;
        let mut credentials = Credentials::resolve()?;
        let snapshot = platform::interface(&options.interface)?;
        let program = query_filter(&snapshot.addresses)?;
        let device = Device::open(&options.interface, &program)?;
        let _dropped = drop_privileges(&mut credentials)?;
        if platform::interface(&options.interface)? != snapshot {
            return Err("初期化中にinterface情報が変わりました".into());
        }
        let _signals = Signals::install()?;
        let (sender, receiver) = mpsc::sync_channel(16);
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = Arc::clone(&stop);
        let worker_options = options.clone();
        let source = LiveSource {
            device,
            name: options.interface.clone(),
            snapshot: snapshot.clone(),
        };
        let handle = thread::Builder::new()
            .name("dns-capture".into())
            .spawn(move || capture_loop(source, snapshot, worker_options, worker_stop, sender))
            .map_err(|_| "capture workerを開始できません")?;
        let worker = Worker {
            stop,
            handle: Some(handle),
        };
        writeln!(out, "mode=live access=read-only direction=outbound checksum=unverified names={} endpoints={}",
            options.show_names, options.show_endpoints).map_err(|_| "標準出力への表示に失敗しました")?;
        let display = (|| -> io::Result<()> {
            while let Ok(packet) = receiver.recv() {
                if options.show_names {
                    writeln!(
                        out,
                        "query id={} type={} class={} name={}",
                        packet.dns.id,
                        packet.dns.query_type,
                        packet.dns.query_class,
                        packet.dns.escaped_name()
                    )?;
                }
                if options.show_endpoints {
                    writeln!(
                        out,
                        "endpoint {} -> {}",
                        std::net::SocketAddr::new(packet.source_ip, packet.source_port),
                        std::net::SocketAddr::new(packet.destination_ip, packet.destination_port)
                    )?;
                }
            }
            Ok(())
        })();
        let counts = worker.finish()?;
        if let Err(error) = display
            && error.kind() != io::ErrorKind::BrokenPipe
        {
            return Err("標準出力への表示に失敗しました".into());
        }
        Ok(counts)
    }
    #[cfg(test)]
    mod tests {
        use super::*;
        use std::net::Ipv4Addr;

        struct SyntheticSource {
            data: Option<Vec<u8>>,
            stop: Arc<AtomicBool>,
            closed: Arc<AtomicBool>,
            changed: bool,
            interface_error: bool,
            read_error: bool,
        }
        impl CaptureSource for SyntheticSource {
            fn buffer_len(&self) -> usize {
                1024
            }
            fn matches_interface(&self) -> Result<bool, String> {
                if self.interface_error {
                    return Err("interfaceには1〜16個のIPアドレスが必要です".into());
                }
                Ok(!self.changed)
            }
            fn read(&mut self, buffer: &mut [u8], timeout: i32) -> Result<Option<usize>, String> {
                assert!((0..=100).contains(&timeout));
                if self.read_error {
                    return Err("synthetic read failure".into());
                }
                if let Some(data) = self.data.take() {
                    buffer[..data.len()].copy_from_slice(&data);
                    Ok(Some(data.len()))
                } else {
                    self.stop.store(true, Ordering::Relaxed);
                    Ok(None)
                }
            }
            fn stats(&self) -> Result<(u32, u32), String> {
                Ok((42, 3))
            }
        }
        impl Drop for SyntheticSource {
            fn drop(&mut self) {
                self.closed.store(true, Ordering::Relaxed);
            }
        }
        fn options() -> CaptureOptions {
            CaptureOptions {
                interface: "en0".into(),
                duration: Duration::from_secs(1),
                show_names: true,
                show_endpoints: false,
            }
        }
        fn snapshot() -> Interface {
            Interface {
                index: 1,
                flags: 1,
                addresses: vec![Ipv4Addr::new(192, 0, 2, 10).into()],
            }
        }
        fn synthetic_source(data: Vec<u8>) -> SyntheticSource {
            SyntheticSource {
                data: Some(data),
                stop: Arc::new(AtomicBool::new(false)),
                closed: Arc::new(AtomicBool::new(false)),
                changed: false,
                interface_error: false,
                read_error: false,
            }
        }
        fn fixture() -> Vec<u8> {
            crate::fixture::decode_hex(include_bytes!("../tests/fixtures/bpf-two-records.hex"))
                .unwrap()
        }

        #[test]
        fn loop_has_bounded_delivery_and_closes_source() {
            let source = synthetic_source(fixture());
            let stop = source.stop.clone();
            let closed = source.closed.clone();
            let (sender, receiver) = mpsc::sync_channel(1);
            let counts = capture_loop(source, snapshot(), options(), stop, sender).unwrap();
            assert_eq!(counts.queries, 2);
            assert_eq!(counts.display_dropped, 1);
            assert_eq!((counts.kernel_received, counts.kernel_dropped), (42, 3));
            assert_eq!(receiver.try_iter().count(), 1);
            assert!(closed.load(Ordering::Relaxed));
        }

        #[test]
        fn default_display_sends_no_names_or_endpoints() {
            let source = synthetic_source(fixture());
            let stop = source.stop.clone();
            let (sender, receiver) = mpsc::sync_channel(1);
            let mut options = options();
            options.show_names = false;
            let counts = capture_loop(source, snapshot(), options, stop, sender).unwrap();
            assert_eq!(counts.queries, 2);
            assert_eq!(counts.display_dropped, 0);
            assert_eq!(receiver.try_iter().count(), 0);
        }

        #[test]
        fn loop_decodes_a_synthetic_ipv6_bpf_record() {
            let frame =
                crate::fixture::decode_hex(include_bytes!("../tests/fixtures/query-v6.hex"))
                    .unwrap();
            let mut bytes = vec![0; 18];
            bytes[8..12].copy_from_slice(&(frame.len() as u32).to_le_bytes());
            bytes[12..16].copy_from_slice(&(frame.len() as u32).to_le_bytes());
            bytes[16..18].copy_from_slice(&18u16.to_le_bytes());
            bytes.extend(frame);
            let source = synthetic_source(bytes);
            let stop = source.stop.clone();
            let mut snapshot = snapshot();
            snapshot.addresses = vec!["2001:db8::10".parse().unwrap()];
            let (sender, receiver) = mpsc::sync_channel(16);
            let counts = capture_loop(source, snapshot, options(), stop, sender).unwrap();
            assert_eq!(counts.queries, 1);
            assert_eq!(
                receiver.try_iter().next().unwrap().source_ip,
                "2001:db8::10".parse::<std::net::IpAddr>().unwrap()
            );
        }

        #[test]
        fn loop_fails_closed_and_releases_source_on_structural_interface_or_io_error() {
            for kind in 0..5 {
                let mut source = synthetic_source(if kind == 0 { vec![0] } else { fixture() });
                source.changed = kind == 1;
                source.read_error = kind == 2;
                source.interface_error = kind == 4;
                if kind == 3 {
                    source.data.as_mut().unwrap()[22 + 29] = 11;
                }
                let stop = source.stop.clone();
                let closed = source.closed.clone();
                let (sender, _receiver) = mpsc::sync_channel(16);
                let error = capture_loop(source, snapshot(), options(), stop, sender).unwrap_err();
                if kind == 4 {
                    assert_eq!(
                        error,
                        "取得中に対象インターフェースの情報を再確認できないため停止しました: interfaceには1〜16個のIPアドレスが必要です"
                    );
                }
                assert!(closed.load(Ordering::Relaxed));
            }
        }

        #[test]
        fn loop_skips_truncated_record_and_stops_on_disconnected_display() {
            let mut bytes = fixture();
            bytes[12..16].copy_from_slice(&73u32.to_le_bytes());
            let source = synthetic_source(bytes);
            let stop = source.stop.clone();
            let (sender, _receiver) = mpsc::sync_channel(16);
            let counts = capture_loop(source, snapshot(), options(), stop, sender).unwrap();
            assert_eq!(counts.truncated, 1);
            assert_eq!(counts.queries, 1);
            let source = synthetic_source(fixture());
            let stop = source.stop.clone();
            let closed = source.closed.clone();
            let (sender, receiver) = mpsc::sync_channel(16);
            drop(receiver);
            assert!(capture_loop(source, snapshot(), options(), stop, sender).is_err());
            assert!(closed.load(Ordering::Relaxed));
        }

        #[test]
        fn stop_and_deadline_prevent_reads_and_worker_guard_joins() {
            for deadline in [false, true] {
                let mut source = synthetic_source(fixture());
                source.read_error = true;
                let stop = source.stop.clone();
                let closed = source.closed.clone();
                let mut options = options();
                if deadline {
                    options.duration = Duration::ZERO;
                } else {
                    stop.store(true, Ordering::Relaxed);
                }
                let (sender, _receiver) = mpsc::sync_channel(16);
                let counts = capture_loop(source, snapshot(), options, stop, sender).unwrap();
                assert_eq!(counts.queries, 0);
                assert!(closed.load(Ordering::Relaxed));
            }
            let stop = Arc::new(AtomicBool::new(false));
            let worker_stop = stop.clone();
            let completed = Arc::new(AtomicBool::new(false));
            let worker_completed = completed.clone();
            let handle = thread::spawn(move || {
                while !worker_stop.load(Ordering::Relaxed) {
                    thread::yield_now();
                }
                worker_completed.store(true, Ordering::Relaxed);
                Ok(CaptureCounts::default())
            });
            drop(Worker {
                stop,
                handle: Some(handle),
            });
            assert!(completed.load(Ordering::Relaxed));
        }
    }
}

#[cfg(target_os = "macos")]
pub use live::capture;

#[cfg(not(target_os = "macos"))]
pub fn capture(
    options: CaptureOptions,
    _: &mut impl std::io::Write,
) -> Result<CaptureCounts, String> {
    options.validate()?;
    Err("live captureはmacOSのみ対応しています".into())
}
