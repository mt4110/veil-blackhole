use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    Malformed(&'static str),
    Unsupported(&'static str),
    TruncatedCapture,
    NotImplemented,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed(reason) => write!(f, "入力不正: {reason}"),
            Self::Unsupported(reason) => write!(f, "対象外: {reason}"),
            Self::TruncatedCapture => write!(f, "キャプチャ時に切り詰められたレコード"),
            Self::NotImplemented => write!(
                f,
                "NotImplemented: live captureは未実装です。デバイスを開いていません"
            ),
        }
    }
}

impl std::error::Error for DecodeError {}
