use std::fmt;

#[derive(Debug, Clone)]
pub enum Error {
    Io(String),
    UnsupportedFormat(String),
    Parse(String),
    OutOfBounds(String),
    Decode(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(m) => write!(f, "io: {m}"),
            Error::UnsupportedFormat(m) => write!(f, "format: {m}"),
            Error::Parse(m) => write!(f, "parse: {m}"),
            Error::OutOfBounds(m) => write!(f, "oob: {m}"),
            Error::Decode(m) => write!(f, "decode: {m}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<ghidrust_decode::Error> for Error {
    fn from(e: ghidrust_decode::Error) -> Self {
        Error::Decode(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, Error>;
