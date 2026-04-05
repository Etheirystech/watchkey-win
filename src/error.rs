use std::fmt;

#[derive(Debug)]
pub enum WatchkeyError {
    WindowsHelloNotSupported,
    AuthenticationFailed(String),
    AuthenticationCancelled,
    CredentialCreateFailed(String),
    MasterKeyCorrupted,
    ServiceNotFound(String),
    StorageIo(std::io::Error),
    CryptoError(String),
    SerializationError(String),
    InvalidArgument(String),
    NotSupportedOnWindows(String),
}

impl fmt::Display for WatchkeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WindowsHelloNotSupported => write!(
                f,
                "Windows Hello is not available. Please enable it in Settings > Accounts > Sign-in options."
            ),
            Self::AuthenticationFailed(msg) => write!(f, "Authentication failed: {msg}"),
            Self::AuthenticationCancelled => write!(f, "Authentication cancelled."),
            Self::CredentialCreateFailed(msg) => {
                write!(f, "Failed to create Windows Hello credential: {msg}")
            }
            Self::MasterKeyCorrupted => write!(
                f,
                "Master key is corrupted or Windows Hello was reset. Run `watchkey reset` to start fresh (existing secrets will be lost)."
            ),
            Self::ServiceNotFound(service) => {
                write!(f, "No item found for \"{service}\"")
            }
            Self::StorageIo(err) => write!(f, "Storage error: {err}"),
            Self::CryptoError(msg) => write!(f, "Encryption error: {msg}"),
            Self::SerializationError(msg) => write!(f, "Data error: {msg}"),
            Self::InvalidArgument(msg) => write!(f, "{msg}"),
            Self::NotSupportedOnWindows(flag) => {
                write!(f, "{flag} is not supported on Windows")
            }
        }
    }
}

impl From<std::io::Error> for WatchkeyError {
    fn from(err: std::io::Error) -> Self {
        Self::StorageIo(err)
    }
}

impl From<serde_json::Error> for WatchkeyError {
    fn from(err: serde_json::Error) -> Self {
        Self::SerializationError(err.to_string())
    }
}

impl From<windows::core::Error> for WatchkeyError {
    fn from(err: windows::core::Error) -> Self {
        Self::AuthenticationFailed(err.message().to_string())
    }
}
