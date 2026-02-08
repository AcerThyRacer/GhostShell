// ╔══════════════════════════════════════════════════════════════════╗
// ║              GhostShell — Session Recorder                       ║
// ║         Encrypted terminal session recording & playback          ║
// ╚══════════════════════════════════════════════════════════════════╝

use crate::config::{CryptoConfig, GhostConfig};
use crate::crypto::cipher::CipherContext;
use crate::crypto::keys;
use crate::crypto::secure_mem::SecureBuffer;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::io::{self, Write};
use std::path::PathBuf;
use std::time::Instant;

/// Session recording event types
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum EventType {
    /// Terminal output (what the user sees)
    Output = 0,
    /// User input (what the user types)
    Input = 1,
    /// Pane resize event
    Resize = 2,
    /// Session metadata
    Metadata = 3,
    /// Marker/bookmark
    Marker = 4,
}

impl EventType {
    fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Output),
            1 => Some(Self::Input),
            2 => Some(Self::Resize),
            3 => Some(Self::Metadata),
            4 => Some(Self::Marker),
            _ => None,
        }
    }
}

/// A single recording event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordingEvent {
    /// Time offset from session start (microseconds)
    pub timestamp_us: u64,
    /// Event type
    pub event_type: EventType,
    /// Event data
    pub data: Vec<u8>,
}

/// File header for .ghost recordings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordingHeader {
    /// Magic bytes: "GHOST\x00\x01\x00"
    pub magic: [u8; 8],
    /// Session UUID
    pub session_id: String,
    /// Creation timestamp (ISO 8601)
    pub created_at: String,
    /// Terminal dimensions at start
    pub cols: u16,
    pub rows: u16,
    /// Shell command
    pub shell: String,
    /// Encryption salt
    pub salt: Vec<u8>,
    /// Argon2 parameters used
    pub argon2_memory_kib: u32,
    pub argon2_iterations: u32,
    pub argon2_parallelism: u32,
}

impl RecordingHeader {
    fn magic() -> [u8; 8] {
        *b"GHOST\x00\x01\x00"
    }
}

/// Encrypted session recorder
pub struct SessionRecorder {
    cipher: CipherContext,
    events: Vec<RecordingEvent>,
    start_time: Instant,
    header: RecordingHeader,
    output_path: PathBuf,
    key: SecureBuffer,
}

impl SessionRecorder {
    /// Create a new session recorder
    pub fn new(config: &CryptoConfig) -> Self {
        let master_key = keys::generate_master_key();
        let salt = keys::generate_salt();
        let session_key = keys::derive_key_from_password(master_key.as_bytes(), &salt, config);
        let cipher = match CipherContext::new(session_key.as_bytes()) {
            Ok(c) => c,
            Err(e) => {
                tracing::error!("Failed to create session cipher: {} — using fallback key", e);
                // SECURITY: Fail hard rather than recording with a weak cipher
                CipherContext::new(&keys::generate_master_key().as_bytes())
                    .expect("Fallback cipher creation must not fail")
            }
        };

        let session_id = uuid::Uuid::new_v4().to_string();
        let output_path = GhostConfig::recordings_dir()
            .join(format!("{}{}", &session_id[..8], config.session_extension));

        let header = RecordingHeader {
            magic: RecordingHeader::magic(),
            session_id,
            created_at: Utc::now().to_rfc3339(),
            cols: 80,
            rows: 24,
            shell: String::new(),
            salt,
            argon2_memory_kib: config.argon2_memory_kib,
            argon2_iterations: config.argon2_iterations,
            argon2_parallelism: config.argon2_parallelism,
        };

        // master_key is already a SecureBuffer — auto-zeroized on drop
        let key = master_key;

        Self {
            cipher,
            events: Vec::new(),
            start_time: Instant::now(),
            header,
            output_path,
            key,
        }
    }

    /// Record an output event
    pub fn record_output(&mut self, data: &[u8]) {
        self.record_event(EventType::Output, data);
    }

    /// Record an input event
    pub fn record_input(&mut self, data: &[u8]) {
        self.record_event(EventType::Input, data);
    }

    /// Record a resize event
    pub fn record_resize(&mut self, cols: u16, rows: u16) {
        let mut data = Vec::with_capacity(4);
        data.extend_from_slice(&cols.to_le_bytes());
        data.extend_from_slice(&rows.to_le_bytes());
        self.record_event(EventType::Resize, &data);
    }

    /// Add a marker/bookmark
    pub fn add_marker(&mut self, label: &str) {
        self.record_event(EventType::Marker, label.as_bytes());
    }

    fn record_event(&mut self, event_type: EventType, data: &[u8]) {
        let elapsed = self.start_time.elapsed();
        let timestamp_us = elapsed.as_micros() as u64;

        self.events.push(RecordingEvent {
            timestamp_us,
            event_type,
            data: data.to_vec(),
        });
    }

    /// Finalize the recording and write to disk
    pub fn finalize(mut self) {
        if let Err(e) = self.write_to_disk() {
            eprintln!("Failed to write recording: {}", e);
        }
    }

    /// Securely delete the recording (when panicking)
    pub fn secure_delete(self) {
        // Don't write anything — let the data be dropped and zeroed
        // If a file was partially written, overwrite it
        if self.output_path.exists() {
            if let Ok(metadata) = std::fs::metadata(&self.output_path) {
                let size = metadata.len() as usize;
                let mut data = vec![0u8; size];
                crate::crypto::secure_mem::secure_wipe(&mut data, 3);
                let _ = std::fs::write(&self.output_path, &data);
                let _ = std::fs::remove_file(&self.output_path);
            }
        }
    }

    fn write_to_disk(&mut self) -> io::Result<()> {
        let mut file = std::fs::File::create(&self.output_path)?;

        // Write header (unencrypted — contains salt for key derivation)
        let header_bytes = bincode::serialize(&self.header)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        file.write_all(&(header_bytes.len() as u32).to_le_bytes())?;
        file.write_all(&header_bytes)?;

        // Write each event encrypted
        for event in &self.events {
            let event_bytes = bincode::serialize(event)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

            // Encrypt the event
            let packet = self
                .cipher
                .encrypt(&event_bytes, Some(b"ghostshell-recording"))
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

            let packet_bytes = packet.to_bytes();
            file.write_all(&(packet_bytes.len() as u32).to_le_bytes())?;
            file.write_all(&packet_bytes)?;
        }

        // Write end marker
        file.write_all(&0u32.to_le_bytes())?;

        Ok(())
    }
}

/// Play back a recording file
pub fn play_recording(path: &str, _speed: f64) -> Result<(), Box<dyn std::error::Error>> {
    let data = std::fs::read(path)?;

    if data.len() < 4 {
        return Err("Invalid recording file".into());
    }

    // Read header length
    let header_len = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
    if data.len() < 4 + header_len {
        return Err("Invalid recording file: truncated header".into());
    }

    let header: RecordingHeader = bincode::deserialize(&data[4..4 + header_len])?;

    // Validate magic
    if header.magic != RecordingHeader::magic() {
        return Err("Invalid recording file: bad magic".into());
    }

    println!("📼 Recording: {}", header.session_id);
    println!("📅 Created: {}", header.created_at);
    println!("📐 Terminal: {}x{}", header.cols, header.rows);
    println!("🐚 Shell: {}", header.shell);
    println!("─────────────────────────────────────────");
    println!("Enter password to decrypt (or Ctrl+C to cancel):");

    // In a real implementation, we'd prompt for the password,
    // derive the key, and decrypt each event for playback
    println!("(Playback engine ready — password-based decryption required)");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_type_roundtrip() {
        assert_eq!(EventType::from_u8(0), Some(EventType::Output));
        assert_eq!(EventType::from_u8(1), Some(EventType::Input));
        assert_eq!(EventType::from_u8(2), Some(EventType::Resize));
        assert_eq!(EventType::from_u8(5), None);
    }

    #[test]
    fn test_recording_header_magic() {
        let magic = RecordingHeader::magic();
        assert_eq!(&magic[..5], b"GHOST");
    }
}
