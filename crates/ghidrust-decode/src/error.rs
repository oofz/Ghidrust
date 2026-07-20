use std::fmt;

/// Decode failure for decode error categories.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    Decode(String),
    Arch(String),
    Mode(String),
    Option(String),
    Handle(String),
    Mem(String),
    Detail(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Decode(m) => write!(f, "decode: {m}"),
            Error::Arch(m) => write!(f, "arch: {m}"),
            Error::Mode(m) => write!(f, "mode: {m}"),
            Error::Option(m) => write!(f, "option: {m}"),
            Error::Handle(m) => write!(f, "handle: {m}"),
            Error::Mem(m) => write!(f, "mem: {m}"),
            Error::Detail(m) => write!(f, "detail: {m}"),
        }
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;
