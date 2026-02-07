// ╔══════════════════════════════════════════════════════════════════╗
// ║              GhostShell — Unified Error Types                     ║
// ║         thiserror-derived enum with source chain support          ║
// ╚══════════════════════════════════════════════════════════════════╝

use std::fmt;

/// Unified error type for GhostShell operations
#[derive(Debug, thiserror::Error)]
pub enum GhostError {
    /// Cryptographic operation failure
    #[error("Crypto error: {0}")]
    Crypto(String),

    /// I/O error (file, network, PTY)
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Configuration error
    #[error("Config error: {0}")]
    Config(String),

    /// TOML deserialization failure
    #[error("Config parse error: {0}")]
    TomlParse(#[from] toml::de::Error),

    /// TOML serialization failure
    #[error("Config serialize error: {0}")]
    TomlSerialize(#[from] toml::ser::Error),

    /// PTY/terminal error
    #[error("PTY error: {0}")]
    Pty(String),

    /// Stealth subsystem error
    #[error("Stealth error: {0}")]
    Stealth(String),

    /// Network error
    #[error("Network error: {0}")]
    Network(String),

    /// IDS error
    #[error("IDS error: {0}")]
    Ids(String),

    /// Plugin system error
    #[error("Plugin error: {0}")]
    Plugin(String),

    /// Audit log error
    #[error("Audit error: {0}")]
    Audit(String),

    /// Nonce exhausted — cipher must be rekeyed
    #[error("Nonce space exhausted — rekey required")]
    NonceExhausted,

    /// Disk space insufficient for operation
    #[error("Insufficient disk space: {available} bytes available, {required} bytes required")]
    InsufficientDiskSpace { available: u64, required: u64 },

    /// Crossterm terminal error
    #[error("Terminal error: {0}")]
    Terminal(String),

    /// Shutdown requested
    #[error("Shutdown")]
    Shutdown,
}

impl From<anyhow::Error> for GhostError {
    fn from(err: anyhow::Error) -> Self {
        Self::Config(format!("{:#}", err))
    }
}

impl From<Box<dyn std::error::Error>> for GhostError {
    fn from(err: Box<dyn std::error::Error>) -> Self {
        Self::Config(err.to_string())
    }
}

impl From<Box<dyn std::error::Error + Send + Sync>> for GhostError {
    fn from(err: Box<dyn std::error::Error + Send + Sync>) -> Self {
        Self::Config(err.to_string())
    }
}

/// Report of cleanup actions taken
#[derive(Debug, Default)]
pub struct CleanupReport {
    /// Number of files securely deleted
    pub files_deleted: usize,
    /// Number of environment variables sanitized
    pub env_vars_cleaned: usize,
    /// Number of history entries removed
    pub history_entries_removed: usize,
    /// Number of log entries cleaned
    pub log_entries_cleaned: usize,
    /// Bytes of memory scrubbed
    pub memory_scrubbed: usize,
    /// Warnings encountered during cleanup (non-fatal)
    pub warnings: Vec<String>,
}

impl fmt::Display for CleanupReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Cleanup: {} files, {} env vars, {} history entries, {} log entries, {} bytes scrubbed",
            self.files_deleted,
            self.env_vars_cleaned,
            self.history_entries_removed,
            self.log_entries_cleaned,
            self.memory_scrubbed,
        )?;
        if !self.warnings.is_empty() {
            write!(f, " ({} warnings)", self.warnings.len())?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    #[test]
    fn test_error_display() {
        let err = GhostError::Crypto("bad key".to_string());
        assert_eq!(format!("{}", err), "Crypto error: bad key");

        let err = GhostError::NonceExhausted;
        assert!(format!("{}", err).contains("rekey"));

        let err = GhostError::InsufficientDiskSpace {
            available: 100,
            required: 1000,
        };
        assert!(format!("{}", err).contains("100"));
    }

    #[test]
    fn test_io_error_conversion() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file gone");
        let ghost_err: GhostError = io_err.into();
        assert!(matches!(ghost_err, GhostError::Io(_)));
        assert!(ghost_err.source().is_some());
    }

    #[test]
    fn test_cleanup_report_display() {
        let report = CleanupReport {
            files_deleted: 3,
            env_vars_cleaned: 5,
            memory_scrubbed: 1024,
            ..Default::default()
        };
        let s = format!("{}", report);
        assert!(s.contains("3 files"));
        assert!(s.contains("5 env vars"));
    }

    #[test]
    fn test_thiserror_derive() {
        // Verify thiserror-generated Display works
        let err = GhostError::Plugin("bad plugin".to_string());
        assert_eq!(format!("{}", err), "Plugin error: bad plugin");

        let err = GhostError::Audit("log corrupted".to_string());
        assert_eq!(format!("{}", err), "Audit error: log corrupted");
    }

    #[test]
    fn test_toml_error_conversion() {
        let bad_toml = "not = [valid";
        let result: Result<toml::Value, _> = toml::from_str(bad_toml);
        let ghost_err: GhostError = result.unwrap_err().into();
        assert!(matches!(ghost_err, GhostError::TomlParse(_)));
    }
}
