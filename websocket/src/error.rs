use std::fmt;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    Incomplete,
    InvalidHttp(&'static str),
    InvalidHandshake(&'static str),
    InvalidHeaderValue(&'static str),
    InvalidFrame(&'static str),
    ProtocolViolation(&'static str),
    PolicyViolation(&'static str),
    StateViolation(&'static str),
    Utf8,
    PayloadTooLarge {
        configured_max: usize,
        actual: usize,
    },
    SizeLimitExceeded {
        category: &'static str,
        configured_max: usize,
        actual: usize,
    },
}

impl std::error::Error for Error {}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Incomplete => write!(f, "incomplete data"),
            Self::InvalidHttp(msg) => write!(f, "invalid HTTP: {msg}"),
            Self::InvalidHandshake(msg) => write!(f, "invalid handshake: {msg}"),
            Self::InvalidHeaderValue(msg) => write!(f, "invalid header value: {msg}"),
            Self::InvalidFrame(msg) => write!(f, "invalid frame: {msg}"),
            Self::ProtocolViolation(msg) => write!(f, "protocol violation: {msg}"),
            Self::PolicyViolation(msg) => write!(f, "policy violation: {msg}"),
            Self::StateViolation(msg) => write!(f, "state violation: {msg}"),
            Self::Utf8 => write!(f, "invalid UTF-8"),
            Self::PayloadTooLarge {
                configured_max,
                actual,
            } => {
                write!(
                    f,
                    "payload too large: max={configured_max} bytes, actual={actual} bytes"
                )
            }
            Self::SizeLimitExceeded {
                category,
                configured_max,
                actual,
            } => {
                write!(
                    f,
                    "size limit exceeded for {category}: max={configured_max} bytes, actual={actual} bytes"
                )
            }
        }
    }
}

impl From<std::str::Utf8Error> for Error {
    fn from(_: std::str::Utf8Error) -> Self {
        Self::Utf8
    }
}

impl From<std::string::FromUtf8Error> for Error {
    fn from(_: std::string::FromUtf8Error) -> Self {
        Self::Utf8
    }
}
