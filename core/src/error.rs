use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum E2eeError {
    InvalidInput(&'static str),
    InvalidPayload(&'static str),
    UnsupportedWrapVersion(u64),
    UnsupportedWrapScheme(String),
    UnsupportedFormatVersion(u8),
    DecryptFailure,
    AuthFailure,
    RandomFailure,
}

impl fmt::Display for E2eeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            E2eeError::InvalidInput(m) => write!(f, "invalid input: {m}"),
            E2eeError::InvalidPayload(m) => write!(f, "invalid payload: {m}"),
            E2eeError::UnsupportedWrapVersion(v) => write!(f, "unsupported wrap version: {v}"),
            E2eeError::UnsupportedWrapScheme(s) => write!(f, "unsupported wrap scheme: {s}"),            E2eeError::UnsupportedFormatVersion(v) => {
                write!(f, "unsupported content format version: {v}")
            }
            E2eeError::DecryptFailure => write!(f, "decryption failed"),
            E2eeError::AuthFailure => write!(f, "authentication failed"),
            E2eeError::RandomFailure => write!(f, "random source failure"),
        }
    }
}

impl std::error::Error for E2eeError {}

pub type Result<T> = std::result::Result<T, E2eeError>;
