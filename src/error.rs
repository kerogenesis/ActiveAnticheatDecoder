//! Typed errors for the decoder crate.
use std::io;
use std::path::PathBuf;
use thiserror::Error as ThisError;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoAction {
    Read,
    Write,
    CreateDir,
}

impl std::fmt::Display for IoAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Read => f.write_str("read"),
            Self::Write => f.write_str("write"),
            Self::CreateDir => f.write_str("create directory"),
        }
    }
}

#[derive(Debug, ThisError)]
pub enum Error {
    #[error("cannot {action} {path}: {source}")]
    Io {
        action: IoAction,
        path: PathBuf,
        #[source]
        source: io::Error,
    },

    #[error("the proxy DLL was not embedded in this build")]
    ProxyDllMissing,

    #[error("no system folder at {path}")]
    NoSystemFolder { path: PathBuf },

    #[error("no {exe} in {directory}")]
    NoClientExe { exe: String, directory: PathBuf },

    #[error("every candidate proxy name is already present in the system folder")]
    ProxyNamesTaken,

    #[error("could not create the capture pipe")]
    PipeCreate,

    #[error("cannot start {path}: error {code}")]
    ProcessStart { path: PathBuf, code: u32 },

    #[error("the client did not return a key before the timeout")]
    CaptureTimeout,

    #[error(
        "protected build refused to capture in an instrumented environment; set {override_name}=1 to override for local debugging"
    )]
    ProtectedEnvironment { override_name: String },

    #[error("RSA modulus is zero or even")]
    InvalidModulus,

    #[error("{name} not found")]
    MissingKeyComponent { name: &'static str },

    #[error("not an ActiveAnticheatCrypt container")]
    NotAacContainer,

    #[error("ciphertext is not smaller than the modulus")]
    CiphertextOutOfRange,

    #[error("PKCS#1 padding invalid (this key does not match the file)")]
    Pkcs1PaddingInvalid,

    #[error("40-byte RSA message lacks the container magic")]
    AacMagicMissing,

    #[error("unexpected RSA message length {got}, expected 20 or 40")]
    UnexpectedRsaMessageLen { got: usize },

    #[error("decode failed:\n  {}", join_failures(failures))]
    DecodeAttemptsFailed { failures: Vec<PerKeyFailure> },

    #[error("EOF reading {what}")]
    ManifestEof { what: &'static str },

    #[error("file count exceeds the manifest size")]
    ManifestFileCount,

    #[error("path length exceeds the manifest size")]
    ManifestPathLength,

    #[error("digest count exceeds the manifest size")]
    ManifestDigestCount,

    #[error("trailing bytes: parsed {parsed} of {total}")]
    ManifestTrailing { parsed: usize, total: usize },

    #[error(
        "ActiveAnticheatCrypt files need the live client: drop the client folder, or run the decoder and pick it, instead of a single file"
    )]
    DroppedAacNeedsClient,
}

impl Error {
    pub fn io(action: IoAction, path: impl AsRef<std::path::Path>, source: io::Error) -> Self {
        Self::Io { action, path: path.as_ref().to_path_buf(), source }
    }

    pub const ELEVATION_REQUIRED_CODE: u32 = 740;

    #[must_use]
    pub fn is_elevation_required(&self) -> bool {
        matches!(self, Self::ProcessStart { code, .. } if *code == Self::ELEVATION_REQUIRED_CODE)
    }

    pub fn is_key_mismatch(&self) -> bool {
        match self {
            Self::DecodeAttemptsFailed { failures } => {
                !failures.is_empty()
                    && failures
                        .iter()
                        .all(|failure| matches!(failure.error, Self::Pkcs1PaddingInvalid))
            }
            _ => false,
        }
    }
}

#[derive(Debug)]
pub struct PerKeyFailure {
    pub key_origin: String,
    pub error: Error,
}

impl std::fmt::Display for PerKeyFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.key_origin, self.error)
    }
}

fn join_failures(failures: &[PerKeyFailure]) -> String {
    failures.iter().map(ToString::to_string).collect::<Vec<_>>().join("\n  ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_mismatch_detects_padding_failures_only() {
        let mismatch = Error::DecodeAttemptsFailed {
            failures: vec![
                PerKeyFailure { key_origin: "cache".to_owned(), error: Error::Pkcs1PaddingInvalid },
                PerKeyFailure {
                    key_origin: "client memory".to_owned(),
                    error: Error::Pkcs1PaddingInvalid,
                },
            ],
        };
        assert!(mismatch.is_key_mismatch());
        assert_eq!(
            mismatch.to_string(),
            "decode failed:\n  cache: PKCS#1 padding invalid (this key does not match the file)\n  client memory: PKCS#1 padding invalid (this key does not match the file)"
        );
        let other = Error::DecodeAttemptsFailed {
            failures: vec![PerKeyFailure {
                key_origin: "cache".to_owned(),
                error: Error::CiphertextOutOfRange,
            }],
        };
        assert!(!other.is_key_mismatch());
        assert!(!Error::NotAacContainer.is_key_mismatch());
    }

    #[test]
    fn elevation_required_detects_win32_740() {
        assert!(
            Error::ProcessStart { path: PathBuf::from("l2.exe"), code: 740 }
                .is_elevation_required()
        );
        assert!(
            !Error::ProcessStart { path: PathBuf::from("l2.exe"), code: 2 }.is_elevation_required()
        );
        assert!(!Error::NotAacContainer.is_elevation_required());
    }
}
