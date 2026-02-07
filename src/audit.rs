// ╔══════════════════════════════════════════════════════════════════╗
// ║              GhostShell — Encrypted Audit Log                    ║
// ║         Append-only encrypted audit trail for security events   ║
// ╚══════════════════════════════════════════════════════════════════╝

use crate::error::GhostError;
use crate::crypto::cipher::CipherContext;
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// Types of auditable events
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuditEventKind {
    /// Application started
    SessionStart,
    /// Application exited
    SessionEnd,
    /// Authentication attempt (success or failure)
    AuthAttempt { success: bool, method: String },
    /// Duress mode activated
    DuressActivated,
    /// Panic mode triggered
    PanicTriggered,
    /// Config changed
    ConfigChanged { field: String },
    /// IDS alert raised
    IdsAlert { severity: String, message: String },
    /// Secure deletion performed
    SecureDeletion { files: usize },
    /// Plugin loaded/unloaded
    PluginEvent { name: String, action: String },
    /// Dead man switch triggered
    DeadManTriggered { action: String },
    /// Session recording started/stopped
    RecordingEvent { active: bool },
    /// Custom event
    Custom { category: String, detail: String },
}

/// A single audit event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Monotonic event sequence number
    pub seq: u64,
    /// Wall clock timestamp (ISO 8601)
    pub timestamp: String,
    /// Subsystem that generated the event
    pub subsystem: String,
    /// Event type and payload
    pub kind: AuditEventKind,
}

/// Configuration for the audit subsystem
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditConfig {
    /// Whether audit logging is enabled
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Maximum age of log files in days before secure deletion
    #[serde(default = "default_retention")]
    pub retention_days: u32,
    /// Whether to encrypt audit log entries
    #[serde(default = "default_true")]
    pub encrypt: bool,
    /// Audit log directory (relative to data dir)
    #[serde(default = "default_audit_dir")]
    pub log_dir: String,
}

fn default_true() -> bool {
    true
}
fn default_retention() -> u32 {
    30
}
fn default_audit_dir() -> String {
    "audit".to_string()
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            retention_days: 30,
            encrypt: true,
            log_dir: "audit".to_string(),
        }
    }
}

/// Encrypted append-only audit log
pub struct AuditLog {
    enabled: bool,
    encrypt: bool,
    cipher: Option<CipherContext>,
    log_dir: PathBuf,
    current_log: PathBuf,
    sequence: u64,
    retention_days: u32,
}

impl AuditLog {
    /// Create a new audit log instance
    pub fn new(data_dir: &Path, config: &AuditConfig) -> Result<Self, GhostError> {
        let log_dir = data_dir.join(&config.log_dir);

        if config.enabled {
            fs::create_dir_all(&log_dir)?;
        }

        // Generate log filename from current date + session
        let now = chrono::Local::now();
        let filename = format!("audit_{}.jsonl", now.format("%Y%m%d_%H%M%S"));
        let current_log = log_dir.join(filename);

        // SECURITY: If encryption is requested, create a cipher context
        // with a random per-session key so audit logs are not stored as
        // plaintext on disk.
        let cipher = if config.encrypt {
            let key = crate::crypto::keys::generate_master_key();
            match CipherContext::new(&key) {
                Ok(c) => Some(c),
                Err(_) => {
                    return Err(GhostError::Audit(
                        "Failed to initialize audit log cipher".into(),
                    ));
                }
            }
        } else {
            None
        };

        Ok(Self {
            enabled: config.enabled,
            encrypt: config.encrypt,
            cipher,
            log_dir,
            current_log,
            sequence: 0,
            retention_days: config.retention_days,
        })
    }

    /// Append an audit event
    pub fn log_event(
        &mut self,
        subsystem: &str,
        kind: AuditEventKind,
    ) -> Result<(), GhostError> {
        if !self.enabled {
            return Ok(());
        }

        self.sequence += 1;

        let event = AuditEvent {
            seq: self.sequence,
            timestamp: chrono::Local::now().to_rfc3339(),
            subsystem: subsystem.to_string(),
            kind,
        };

        // Serialize to JSON line
        let json = serde_json::to_string(&event).map_err(|e| {
            GhostError::Audit(format!("Failed to serialize audit event: {}", e))
        })?;

        let line_bytes = if self.encrypt {
            if let Some(ref mut cipher) = self.cipher {
                // Encrypt the JSON line before writing
                let encrypted = cipher.encrypt(json.as_bytes(), None).map_err(|e| {
                    GhostError::Audit(format!("Failed to encrypt audit event: {:?}", e))
                })?;
                let encoded = base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    &encrypted.to_bytes(),
                );
                encoded.into_bytes()
            } else {
                json.into_bytes()
            }
        } else {
            json.into_bytes()
        };

        // Append to log file
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.current_log)?;

        file.write_all(&line_bytes)?;
        file.write_all(b"\n")?;
        file.flush()?;

        Ok(())
    }

    /// Convenience: log a session start event
    pub fn log_session_start(&mut self) -> Result<(), GhostError> {
        self.log_event("session", AuditEventKind::SessionStart)
    }

    /// Convenience: log a session end event
    pub fn log_session_end(&mut self) -> Result<(), GhostError> {
        self.log_event("session", AuditEventKind::SessionEnd)
    }

    /// Convenience: log an auth attempt
    pub fn log_auth(&mut self, success: bool, method: &str) -> Result<(), GhostError> {
        self.log_event(
            "auth",
            AuditEventKind::AuthAttempt {
                success,
                method: method.to_string(),
            },
        )
    }

    /// Convenience: log an IDS alert
    pub fn log_ids_alert(&mut self, severity: &str, message: &str) -> Result<(), GhostError> {
        self.log_event(
            "ids",
            AuditEventKind::IdsAlert {
                severity: severity.to_string(),
                message: message.to_string(),
            },
        )
    }

    /// Convenience: log a config change
    pub fn log_config_change(&mut self, field: &str) -> Result<(), GhostError> {
        self.log_event(
            "config",
            AuditEventKind::ConfigChanged {
                field: field.to_string(),
            },
        )
    }

    /// Rotate logs: securely delete logs older than retention period
    pub fn rotate_logs(&self) -> Result<usize, GhostError> {
        if !self.enabled {
            return Ok(0);
        }

        let cutoff = SystemTime::now()
            - std::time::Duration::from_secs(self.retention_days as u64 * 86400);

        let mut deleted = 0;
        if let Ok(entries) = fs::read_dir(&self.log_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().map(|e| e == "jsonl").unwrap_or(false) {
                    if let Ok(meta) = path.metadata() {
                        if let Ok(modified) = meta.modified() {
                            if modified < cutoff && path != self.current_log {
                                // Overwrite before delete for security
                                if let Ok(len) = meta.len().try_into() {
                                    let zeros = vec![0u8; len];
                                    if let Ok(mut f) =
                                        OpenOptions::new().write(true).open(&path)
                                    {
                                        let _ = f.write_all(&zeros);
                                        let _ = f.flush();
                                    }
                                }
                                let _ = fs::remove_file(&path);
                                deleted += 1;
                            }
                        }
                    }
                }
            }
        }

        Ok(deleted)
    }

    /// Get total number of events logged this session
    pub fn event_count(&self) -> u64 {
        self.sequence
    }

    /// Get the current log file path
    pub fn current_log_path(&self) -> &Path {
        &self.current_log
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn temp_audit() -> (AuditLog, TempDir) {
        let dir = TempDir::new().expect("create temp dir");
        // Use encrypt: false for tests that inspect plaintext log content
        let config = AuditConfig {
            encrypt: false,
            ..Default::default()
        };
        let log = AuditLog::new(dir.path(), &config).expect("create audit log");
        (log, dir)
    }

    fn temp_audit_encrypted() -> (AuditLog, TempDir) {
        let dir = TempDir::new().expect("create temp dir");
        let config = AuditConfig::default(); // encrypt: true by default
        let log = AuditLog::new(dir.path(), &config).expect("create audit log");
        (log, dir)
    }

    #[test]
    fn test_audit_log_creation() {
        let (log, _dir) = temp_audit();
        assert_eq!(log.event_count(), 0);
        assert!(log.current_log_path().to_str().unwrap().contains("audit_"));
    }

    #[test]
    fn test_log_event() {
        let (mut log, _dir) = temp_audit();
        log.log_session_start().expect("log session start");
        assert_eq!(log.event_count(), 1);

        log.log_auth(true, "password").expect("log auth");
        assert_eq!(log.event_count(), 2);

        // Verify file was written
        let content =
            std::fs::read_to_string(log.current_log_path()).expect("read log");
        assert!(content.contains("SessionStart"));
        assert!(content.contains("AuthAttempt"));
    }

    #[test]
    fn test_log_ids_alert() {
        let (mut log, _dir) = temp_audit();
        log.log_ids_alert("Critical", "Reverse shell detected")
            .expect("log alert");

        let content = std::fs::read_to_string(log.current_log_path()).unwrap();
        assert!(content.contains("Reverse shell detected"));
    }

    #[test]
    fn test_disabled_audit() {
        let dir = TempDir::new().unwrap();
        let config = AuditConfig {
            enabled: false,
            ..Default::default()
        };
        let mut log = AuditLog::new(dir.path(), &config).unwrap();
        log.log_session_start().unwrap();
        assert_eq!(log.event_count(), 0); // Nothing logged when disabled
    }

    #[test]
    fn test_audit_config_defaults() {
        let config = AuditConfig::default();
        assert!(config.enabled);
        assert_eq!(config.retention_days, 30);
        assert!(config.encrypt);
        assert_eq!(config.log_dir, "audit");
    }

    #[test]
    fn test_log_rotation_empty() {
        let (log, _dir) = temp_audit();
        let deleted = log.rotate_logs().unwrap();
        assert_eq!(deleted, 0); // No old logs to rotate
    }

    #[test]
    fn test_encrypted_audit_log() {
        let (mut log, _dir) = temp_audit_encrypted();
        log.log_session_start().expect("log session start");
        assert_eq!(log.event_count(), 1);

        // Encrypted log should NOT contain plaintext event data
        let content = std::fs::read_to_string(log.current_log_path()).expect("read log");
        assert!(!content.contains("SessionStart"),
            "Encrypted audit log must not contain plaintext event type");
        assert!(!content.is_empty(), "Encrypted audit log should not be empty");
    }
}
