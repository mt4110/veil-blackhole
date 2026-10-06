//! The only Rust module permitted to call unsafe Darwin APIs.
//! Call capture preparation from a single-threaded CLI, never a library host
//! with existing threads: Unix credential changes are process-wide.
use std::ffi::{CStr, CString};
use std::io::{self, Read};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::FileTypeExt;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::filter::{Instruction, MAX_ADDRESSES};
use crate::privilege::{DropOperations, Identity};

unsafe extern "C" {
    fn veil_single_threaded() -> i32;
    fn veil_check_inherited() -> i32;
    fn veil_audit_uid(uid: *mut u32) -> i32;
    fn veil_bpf_configure(
        fd: i32,
        name: *const libc::c_char,
        p: *const Instruction,
        count: u32,
        length: *mut u32,
    ) -> i32;
    fn veil_bpf_stats(fd: i32, received: *mut u32, dropped: *mut u32) -> i32;
}

fn errno(code: i32, operation: &str) -> Result<(), String> {
    if code == 0 {
        Ok(())
    } else {
        Err(format!(
            "{operation}: {}",
            io::Error::from_raw_os_error(code)
        ))
    }
}

fn result(code: i32, operation: &str) -> Result<(), String> {
    if code == 0 {
        Ok(())
    } else {
        Err(format!("{operation}: {}", io::Error::last_os_error()))
    }
}

pub struct Credentials {
    pub identity: Identity,
    name: CString,
    root: bool,
}

impl Credentials {
    pub fn resolve() -> Result<Self, String> {
        // SAFETY: getter has no pointers or side effects. Credential setup must
        // not be embedded in a previously threaded process.
        errno(unsafe { veil_single_threaded() }, "single-thread初期化確認")?;
        // SAFETY: helper only enumerates this process's FDs, never closes them.
        errno(
            unsafe { veil_check_inherited() },
            "継承FD確認（stdio以外は拒否）",
        )?;
        // SAFETY: getters have no pointers and do not mutate process credentials.
        let (uid, euid, gid, egid) = unsafe {
            (
                libc::getuid(),
                libc::geteuid(),
                libc::getgid(),
                libc::getegid(),
            )
        };
        let target = if euid == 0 {
            let mut audit_uid = 0;
            // SAFETY: C writes one u32, using the SDK audit structure internally.
            errno(
                unsafe { veil_audit_uid(&mut audit_uid) },
                "監査セッションのUID確認",
            )?;
            if uid != 0 && uid != audit_uid {
                return Err("real UIDと監査セッションのUIDが一致しません".into());
            }
            audit_uid
        } else {
            if uid == 0 || uid != euid || gid != egid {
                return Err("部分的に昇格したidentityは対応しません".into());
            }
            uid
        };
        // A bounded reentrant lookup; no environment-variable identity authority.
        let mut buffer = vec![0u8; 65536];
        // SAFETY: passwd may be zero initialized; the API initializes it on success.
        let mut passwd: libc::passwd = unsafe { std::mem::zeroed() };
        let mut found = std::ptr::null_mut();
        // SAFETY: buffer and output pointers live across the call; length matches allocation.
        errno(
            unsafe {
                libc::getpwuid_r(
                    target,
                    &mut passwd,
                    buffer.as_mut_ptr().cast(),
                    buffer.len(),
                    &mut found,
                )
            },
            "account確認",
        )?;
        if found.is_null()
            || passwd.pw_uid != target
            || target == 0
            || passwd.pw_gid == 0
            || passwd.pw_gid > i32::MAX as u32
            || passwd.pw_name.is_null()
        {
            return Err("有効な非root accountとprimary GIDを確認できません".into());
        }
        // SAFETY: successful getpwuid_r returns NUL-terminated strings inside buffer.
        let name = unsafe { CStr::from_ptr(passwd.pw_name) }.to_owned();
        if euid != 0 && gid != passwd.pw_gid {
            return Err("primary GIDと実GIDが一致しません".into());
        }
        Ok(Self {
            identity: Identity {
                uid: target,
                gid: passwd.pw_gid,
            },
            name,
            root: euid == 0,
        })
    }
}

impl DropOperations for Credentials {
    fn initialize_groups(&mut self) -> Result<(), String> {
        if !self.root {
            return Ok(());
        }
        // SAFETY: name is an owned C string, gid range checked during resolution.
        result(
            unsafe { libc::initgroups(self.name.as_ptr(), self.identity.gid as i32) },
            "initgroups",
        )
    }
    fn set_gid(&mut self) -> Result<(), String> {
        if !self.root {
            return Ok(());
        }
        // SAFETY: invoked before threads; setgid resets real/effective/saved GID as root.
        result(unsafe { libc::setgid(self.identity.gid) }, "setgid")
    }
    fn set_uid(&mut self) -> Result<(), String> {
        if !self.root {
            return Ok(());
        }
        // SAFETY: invoked before threads; setuid resets real/effective/saved UID as root.
        result(unsafe { libc::setuid(self.identity.uid) }, "setuid")
    }
    fn verify(&mut self) -> Result<(), String> {
        // SAFETY: read-only credential getters.
        let ids = unsafe {
            (
                libc::getuid(),
                libc::geteuid(),
                libc::getgid(),
                libc::getegid(),
            )
        };
        if ids
            != (
                self.identity.uid,
                self.identity.uid,
                self.identity.gid,
                self.identity.gid,
            )
        {
            return Err("権限降格後のUID/GIDが一致しません".into());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Interface {
    pub index: u32,
    pub addresses: Vec<IpAddr>,
    pub flags: u32,
}

pub fn interface(name: &str) -> Result<Interface, String> {
    let name = CString::new(name).map_err(|_| "interface名が不正です")?;
    // SAFETY: name is a NUL-terminated string.
    let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
    if index == 0 {
        return Err("interfaceが存在しません".into());
    }
    let mut head = std::ptr::null_mut();
    // SAFETY: API initializes head, freed exactly once by guard below.
    result(unsafe { libc::getifaddrs(&mut head) }, "getifaddrs")?;
    struct Guard(*mut libc::ifaddrs);
    impl Drop for Guard {
        fn drop(&mut self) {
            // SAFETY: pointer came from successful getifaddrs and is uniquely owned.
            unsafe { libc::freeifaddrs(self.0) };
        }
    }
    let _guard = Guard(head);
    let mut addresses = Vec::new();
    let mut flags = None;
    let mut cursor = head;
    while !cursor.is_null() {
        // SAFETY: the list is owned by guard and each entry/name is initialized by OS.
        let entry = unsafe { &*cursor };
        if !entry.ifa_name.is_null() && unsafe { CStr::from_ptr(entry.ifa_name) } == name.as_c_str()
        {
            flags = Some(entry.ifa_flags);
            if !entry.ifa_addr.is_null() {
                // SAFETY: the address is valid and family selects the IPv4 struct.
                let address = unsafe { &*entry.ifa_addr };
                if address.sa_family as i32 == libc::AF_INET {
                    // SAFETY: OS-provided IPv4 sockaddr has sockaddr_in layout.
                    let v4 = unsafe { &*entry.ifa_addr.cast::<libc::sockaddr_in>() };
                    addresses.push(Ipv4Addr::from(v4.sin_addr.s_addr.to_ne_bytes()).into());
                } else if address.sa_family as i32 == libc::AF_INET6 {
                    // SAFETY: OS-provided IPv6 sockaddr has sockaddr_in6 layout.
                    let v6 = unsafe { &*entry.ifa_addr.cast::<libc::sockaddr_in6>() };
                    addresses.push(Ipv6Addr::from(v6.sin6_addr.s6_addr).into());
                }
            }
        }
        cursor = entry.ifa_next;
    }
    let flags = flags.ok_or("interface情報がありません")?;
    if flags & libc::IFF_UP as u32 == 0 || flags & libc::IFF_LOOPBACK as u32 != 0 {
        return Err("UPな非loopback interfaceを指定してください".into());
    }
    addresses.sort_unstable();
    addresses.dedup();
    if addresses.is_empty() || addresses.len() > MAX_ADDRESSES {
        return Err("interfaceには1〜16個のIPアドレスが必要です".into());
    }
    Ok(Interface {
        index,
        addresses,
        flags,
    })
}

pub struct Device {
    file: std::fs::File,
    pub buffer_len: usize,
}

impl Device {
    pub fn open(name: &str, program: &[Instruction]) -> Result<Self, String> {
        let mut selected = None;
        for number in 0..128 {
            let path = CString::new(format!("/dev/bpf{number}")).expect("fixed path");
            // SAFETY: fixed NUL-terminated device path; no write/create flags.
            let raw = unsafe {
                libc::open(
                    path.as_ptr(),
                    libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NONBLOCK | libc::O_NOFOLLOW,
                )
            };
            if raw >= 0 {
                // SAFETY: open returned a new uniquely owned FD.
                selected = Some(unsafe { OwnedFd::from_raw_fd(raw) });
                break;
            }
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::EBUSY) {
                return Err(format!(
                    "BPF O_RDONLY open: {error}（自動昇格は行いません）"
                ));
            }
        }
        let fd = selected.ok_or("128個のBPF deviceが使用中です")?;
        let file: std::fs::File = fd.into();
        if !file
            .metadata()
            .map_err(|_| "BPF device情報を確認できません")?
            .file_type()
            .is_char_device()
        {
            return Err("BPF pathはcharacter deviceではありません".into());
        }
        let fd: OwnedFd = file.into();
        // SAFETY: valid owned FD, fcntl getters take no third argument.
        let (access, descriptor) = unsafe {
            (
                libc::fcntl(fd.as_raw_fd(), libc::F_GETFL),
                libc::fcntl(fd.as_raw_fd(), libc::F_GETFD),
            )
        };
        if access < 0
            || descriptor < 0
            || access & libc::O_ACCMODE != libc::O_RDONLY
            || access & libc::O_NONBLOCK == 0
            || descriptor & libc::FD_CLOEXEC == 0
        {
            return Err("BPF FDのread-only/nonblocking/cloexec確認に失敗しました".into());
        }
        let name = CString::new(name).map_err(|_| "interface名が不正です")?;
        let mut buffer_len = 0;
        // SAFETY: name/program live across call, C copies filter, output is one u32.
        errno(
            unsafe {
                veil_bpf_configure(
                    fd.as_raw_fd(),
                    name.as_ptr(),
                    program.as_ptr(),
                    program.len() as u32,
                    &mut buffer_len,
                )
            },
            "BPF限定初期化",
        )?;
        Ok(Self {
            file: fd.into(),
            buffer_len: buffer_len as usize,
        })
    }

    pub fn read(&mut self, buffer: &mut [u8], milliseconds: i32) -> Result<Option<usize>, String> {
        let mut poll = libc::pollfd {
            fd: self.file.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one valid pollfd, bounded nonnegative timeout.
        let ready = unsafe { libc::poll(&mut poll, 1, milliseconds) };
        if ready < 0 {
            let error = io::Error::last_os_error();
            return if error.kind() == io::ErrorKind::Interrupted {
                Ok(None)
            } else {
                Err(format!("BPF poll: {error}"))
            };
        }
        if ready == 0 {
            return Ok(None);
        }
        if poll.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
            return Err("BPF pollのdevice状態が不正です".into());
        }
        match self.file.read(buffer) {
            Ok(0) => Err("BPF deviceがEOFを返しました".into()),
            Ok(length) => Ok(Some(length)),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) =>
            {
                Ok(None)
            }
            Err(error) => Err(format!("BPF read: {error}")),
        }
    }

    pub fn stats(&self) -> Result<(u32, u32), String> {
        let mut received = 0;
        let mut dropped = 0;
        // SAFETY: valid FD and two writable u32 outputs.
        errno(
            unsafe { veil_bpf_stats(self.file.as_raw_fd(), &mut received, &mut dropped) },
            "BPF stats",
        )?;
        Ok((received, dropped))
    }
}

static INTERRUPTED: AtomicBool = AtomicBool::new(false);
extern "C" fn interrupt(number: i32) {
    if INTERRUPTED.swap(true, Ordering::Relaxed) {
        // SAFETY: _exit is async-signal-safe. A second stop signal forces
        // process termination even if a stdout sink/OS service is blocked.
        // Kernel closes all FDs; no Rust cleanup or summary is promised here.
        unsafe { libc::_exit(128 + number) };
    }
}
pub fn interrupted() -> bool {
    INTERRUPTED.load(Ordering::Relaxed)
}

pub struct Signals {
    previous: Vec<(i32, libc::sigaction)>,
}
impl Signals {
    pub fn install() -> Result<Self, String> {
        INTERRUPTED.store(false, Ordering::Relaxed);
        let mut installed = Self {
            previous: Vec::new(),
        };
        for number in [libc::SIGINT, libc::SIGTERM] {
            // SAFETY: zero initialized sigaction is subsequently populated before use.
            let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
            let mut previous = action;
            action.sa_sigaction = interrupt as *const () as usize;
            // SAFETY: mask and sigactions are valid local structs. Handler only sets atomic.
            unsafe { libc::sigemptyset(&mut action.sa_mask) };
            result(
                unsafe { libc::sigaction(number, &action, &mut previous) },
                "停止signal設定",
            )?;
            installed.previous.push((number, previous));
        }
        Ok(installed)
    }
}
impl Drop for Signals {
    fn drop(&mut self) {
        for (number, previous) in self.previous.iter().rev() {
            // SAFETY: restores the valid action saved by successful sigaction.
            unsafe { libc::sigaction(*number, previous, std::ptr::null_mut()) };
        }
    }
}
