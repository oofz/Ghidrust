use serde_json::{json, Value};
use std::fmt;

#[derive(Debug, Clone)]
pub enum Error {
    Io(String),
    EncryptedOrObfuscated { magic: u32, version_field: i32 },
    UnsupportedVersion { version: i32, hint: String },
    Parse(String),
    Bounds(String),
}

/// Agent-oriented next steps when metadata fails closed as encrypted/obfuscated.
pub const ENCRYPTED_METADATA_NEXT_STEPS: &[&str] = &[
    "Use engine PE strings + il2cpp icalls for native internal-call RVAs",
    "Treat GameAssembly resolve stubs as lazy thunks, not gameplay callers (xrefs --skip-stubs)",
    "Instance/type latch may require live inspection when metadata is unavailable",
    "If you have a decrypted dump: il2cpp touch-map --meta PATH|--meta-sections DIR --filter SUB",
    "meta-sections DIR expects global-metadata.dat (or clear metadata.dat); section dumps documented in docs/IL2CPP.md",
];

impl Error {
    /// Structured JSON for CLI/MCP when metadata is encrypted/obfuscated.
    pub fn encrypted_json(magic: u32, _version_field: i32) -> Value {
        json!({
            "error": "metadata_encrypted_or_obfuscated",
            "magic": format!("{magic:#010x}"),
            "next_steps": ENCRYPTED_METADATA_NEXT_STEPS,
        })
    }

    /// Structured JSON for this error when it is encrypt/obfuscate; otherwise null.
    pub fn to_structured_json(&self) -> Option<Value> {
        match self {
            Error::EncryptedOrObfuscated { magic, version_field } => {
                Some(Self::encrypted_json(*magic, *version_field))
            }
            _ => None,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(m) => write!(f, "io: {m}"),
            Error::EncryptedOrObfuscated { magic, version_field } => write!(
                f,
                "metadata encrypted or obfuscated (magic={magic:#010x}, version_field={version_field}); refuse to mis-parse"
            ),
            Error::UnsupportedVersion { version, hint } => {
                write!(f, "unsupported metadata version {version}: {hint}")
            }
            Error::Parse(m) => write!(f, "parse: {m}"),
            Error::Bounds(m) => write!(f, "bounds: {m}"),
        }
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypted_json_has_next_steps() {
        let v = Error::encrypted_json(0xDEADBEEF, -1);
        assert_eq!(v["error"], "metadata_encrypted_or_obfuscated");
        assert_eq!(v["magic"], "0xdeadbeef");
        let steps = v["next_steps"].as_array().expect("next_steps");
        assert!(steps.len() >= 3);
        assert!(steps.iter().any(|s| s.as_str().unwrap_or("").contains("il2cpp icalls")));
        assert!(steps.iter().any(|s| s.as_str().unwrap_or("").contains("touch-map")));
    }
}
