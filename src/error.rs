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
            Self::CreateDir => f.write_str("create"),
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

    #[error("modulus is zero")]
    ModulusZero,

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

    #[error("decode failed:\n  {}", reasons.join("\n  "))]
    DecodeFailed { reasons: Vec<String> },

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

    #[error("not an ActiveAnticheatCrypt container")]
    DroppedUnknownFormat,

    #[error("GamekitData payload decoding failed")]
    GamekitDecodeFailed,
}

impl Error {
    pub fn io(action: IoAction, path: impl AsRef<std::path::Path>, source: io::Error) -> Self {
        Self::Io { action, path: path.as_ref().to_path_buf(), source }
    }
}
