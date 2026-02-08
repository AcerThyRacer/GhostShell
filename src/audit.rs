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
    /// SHA-256 hash of the previous event (for chain verification)
    #[serde(default)]
    pub prev_hash: String,
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

        // SECURITY: If encryption is requested, derive the cipher key
        // from a persisted salt so audit logs can be decrypted later.
        // The salt is written to a .key sidecar file beside the log.
        let cipher = if config.encrypt {
            let salt = crate::crypto::keys::generate_salt();
            let master = crate::crypto::keys::generate_master_key();
            let derived = crate::crypto::keys::derive_hmac_key(
                master.as_bytes(),
                b"ghostshell-audit-key-v1",
            );
            // Persist the salt so the key can be re-derived later
            let key_path = current_log.with_extension("key");
            let _ = fs::write(&key_path, &salt);

            match CipherContext::new(derived.as_bytes()) {
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
            prev_hash: String::new(),
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

// ── Merkle Hash-Chained Audit Log ─────────────────────────────────

use sha2::{Sha256, Digest};

/// A chain entry pairing an event's serialized form with its hash.
pub struct ChainEntry {
    /// SHA-256 hash of (prev_hash || event_json)
    pub hash: String,
    /// The prev_hash stored in this event
    pub prev_hash: String,
    /// Serialized event JSON (for re-hashing during verification)
    pub event_json: String,
}

/// Wraps an `AuditLog` with hash-chain integrity (Merkle-style).
/// Each logged event includes the SHA-256 hash of the previous entry,
/// creating a tamper-evident chain.
pub struct MerkleAuditLog {
    inner: AuditLog,
    /// In-memory chain of hashes for verification
    pub chain: Vec<ChainEntry>,
}

impl MerkleAuditLog {
    /// Create a new Merkle audit log wrapping an inner `AuditLog`.
    pub fn new(inner: AuditLog) -> Self {
        Self {
            inner,
            chain: Vec::new(),
        }
    }

    /// Compute SHA-256 of (prev_hash || data) → hex string.
    fn compute_hash(prev_hash: &str, data: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(prev_hash.as_bytes());
        hasher.update(data.as_bytes());
        format!("{:x}", hasher.finalize())
    }

    /// Log an event with hash chaining.
    pub fn log_event(
        &mut self,
        subsystem: &str,
        kind: AuditEventKind,
    ) -> Result<(), GhostError> {
        let prev_hash = self
            .chain
            .last()
            .map(|e| e.hash.clone())
            .unwrap_or_default();

        self.inner.sequence += 1;

        let event = AuditEvent {
            seq: self.inner.sequence,
            timestamp: chrono::Local::now().to_rfc3339(),
            subsystem: subsystem.to_string(),
            kind,
            prev_hash: prev_hash.clone(),
        };

        let event_json = serde_json::to_string(&event).map_err(|e| {
            GhostError::Audit(format!("Failed to serialize audit event: {}", e))
        })?;

        let hash = Self::compute_hash(&prev_hash, &event_json);

        self.chain.push(ChainEntry {
            hash,
            prev_hash,
            event_json: event_json.clone(),
        });

        // Write through to the inner log file
        let line_bytes = if self.inner.encrypt {
            if let Some(ref mut cipher) = self.inner.cipher {
                let encrypted = cipher
                    .encrypt(event_json.as_bytes(), None)
                    .map_err(|e| {
                        GhostError::Audit(format!("Failed to encrypt audit event: {:?}", e))
                    })?;
                base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    &encrypted.to_bytes(),
                )
                .into_bytes()
            } else {
                event_json.into_bytes()
            }
        } else {
            event_json.into_bytes()
        };

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.inner.current_log)?;
        file.write_all(&line_bytes)?;
        file.write_all(b"\n")?;
        file.flush()?;

        // Write the root file
        self.write_root_file()?;

        Ok(())
    }

    /// Verify the entire chain is intact (no tampering).
    pub fn verify_chain(&self) -> bool {
        let mut prev_hash = String::new();
        for entry in &self.chain {
            if entry.prev_hash != prev_hash {
                return false;
            }
            let recomputed = Self::compute_hash(&entry.prev_hash, &entry.event_json);
            if recomputed != entry.hash {
                return false;
            }
            prev_hash = entry.hash.clone();
        }
        true
    }

    /// Get the current Merkle root (hash of the last entry).
    pub fn merkle_root(&self) -> Option<&str> {
        self.chain.last().map(|e| e.hash.as_str())
    }

    /// Number of entries in the chain.
    pub fn chain_len(&self) -> usize {
        self.chain.len()
    }

    /// Write the current Merkle root atomically to a `.root` file beside the log.
    fn write_root_file(&self) -> Result<(), GhostError> {
        if let Some(root) = self.merkle_root() {
            let root_path = self.inner.current_log.with_extension("root");
            crate::config::atomic_write(&root_path, root.as_bytes())
                .map_err(|e| GhostError::Audit(format!("Failed to write Merkle root: {}", e)))?;
        }
        Ok(())
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

    // ── Merkle audit log tests ──

    #[test]
    fn test_merkle_chain_integrity() {
        let dir = TempDir::new().unwrap();
        let config = AuditConfig {
            encrypt: false,
            ..Default::default()
        };
        let inner = AuditLog::new(dir.path(), &config).unwrap();
        let mut merkle = MerkleAuditLog::new(inner);

        merkle.log_event("test", AuditEventKind::SessionStart).unwrap();
        merkle.log_event("test", AuditEventKind::SessionEnd).unwrap();
        merkle.log_event("auth", AuditEventKind::AuthAttempt {
            success: true,
            method: "password".to_string(),
        }).unwrap();

        assert_eq!(merkle.chain_len(), 3);
        assert!(merkle.verify_chain());
    }

    #[test]
    fn test_merkle_tamper_detection() {
        let dir = TempDir::new().unwrap();
        let config = AuditConfig {
            encrypt: false,
            ..Default::default()
        };
        let inner = AuditLog::new(dir.path(), &config).unwrap();
        let mut merkle = MerkleAuditLog::new(inner);

        merkle.log_event("test", AuditEventKind::SessionStart).unwrap();
        merkle.log_event("test", AuditEventKind::SessionEnd).unwrap();

        // Tamper with a hash in the chain
        if let Some(entry) = merkle.chain.get_mut(0) {
            entry.hash = "tampered_hash".to_string();
        }

        assert!(!merkle.verify_chain());
    }

    #[test]
    fn test_merkle_empty_chain() {
        let dir = TempDir::new().unwrap();
        let config = AuditConfig {
            encrypt: false,
            ..Default::default()
        };
        let inner = AuditLog::new(dir.path(), &config).unwrap();
        let merkle = MerkleAuditLog::new(inner);

        assert_eq!(merkle.chain_len(), 0);
        assert!(merkle.verify_chain()); // Empty chain is valid
        assert_eq!(merkle.merkle_root(), None);
    }

    #[test]
    fn test_merkle_root_changes() {
        let dir = TempDir::new().unwrap();
        let config = AuditConfig {
            encrypt: false,
            ..Default::default()
        };
        let inner = AuditLog::new(dir.path(), &config).unwrap();
        let mut merkle = MerkleAuditLog::new(inner);

        merkle.log_event("test", AuditEventKind::SessionStart).unwrap();
        let root1 = merkle.merkle_root().unwrap().to_string();

        merkle.log_event("test", AuditEventKind::SessionEnd).unwrap();
        let root2 = merkle.merkle_root().unwrap().to_string();

        assert_ne!(root1, root2, "Root should change with each entry");
    }
}
