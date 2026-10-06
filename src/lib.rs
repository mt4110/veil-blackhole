//! Read-only capture and decoders. There is no packet sender.

pub mod bpf;
pub mod decode;
pub mod dns;
pub mod error;
pub mod filter;
pub mod fixture;
#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
mod platform;
pub mod privilege;
pub mod records;
