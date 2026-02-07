// ╔══════════════════════════════════════════════════════════════════╗
// ║              GhostShell — Session Sharing                        ║
// ║         Share terminal sessions with E2E encryption              ║
// ╚══════════════════════════════════════════════════════════════════╝

use crate::network::noise_transport::NoiseTransport;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Session sharing mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SharingMode {
    /// Full read-write access
    ReadWrite,
    /// Read-only observer
    ReadOnly,
    /// Input only (remote can type, host sees output)
    InputOnly,
}

/// A shared session participant
#[derive(Debug, Clone)]
pub struct Participant {
    pub id: String,
    pub display_name: String,
    pub mode: SharingMode,
    pub public_key: Vec<u8>,
    pub connected: bool,
}

/// Session sharing manager
pub struct SessionSharing {
    /// Our session ID
    session_id: String,
    /// Our role (host or guest)
    role: SharingRole,
    /// Connected participants
    participants: HashMap<String, Participant>,
    /// Maximum participants
    max_participants: usize,
    /// Whether sharing is active
    active: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SharingRole {
    Host,
    Guest,
}

/// Events that can be shared
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SharedEvent {
    /// Terminal output
    Output(Vec<u8>),
    /// User input (keyboard)
    Input(Vec<u8>),
    /// Terminal resize
    Resize { cols: u16, rows: u16 },
    /// Participant joined
    Join { id: String, name: String },
    /// Participant left
    Leave { id: String },
    /// Chat message
    Chat { from: String, message: String },
    /// Cursor position update
    Cursor { pane_id: u32, row: u16, col: u16 },
}

impl SessionSharing {
    pub fn new_host(session_id: &str, max_participants: usize) -> Self {
        Self {
            session_id: session_id.to_string(),
            role: SharingRole::Host,
            participants: HashMap::new(),
            max_participants,
            active: false,
        }
    }

    pub fn new_guest(session_id: &str) -> Self {
        Self {
            session_id: session_id.to_string(),
            role: SharingRole::Guest,
            participants: HashMap::new(),
            max_participants: 0,
            active: false,
        }
    }

    /// Start sharing
    pub fn start(&mut self) -> Result<(), String> {
        if self.active {
            return Err("Sharing already active".to_string());
        }
        self.active = true;
        Ok(())
    }

    /// Stop sharing
    pub fn stop(&mut self) {
        self.active = false;
        self.participants.clear();
    }

    /// Add a participant
    pub fn add_participant(&mut self, participant: Participant) -> Result<(), String> {
        if self.participants.len() >= self.max_participants && self.role == SharingRole::Host {
            return Err("Maximum participants reached".to_string());
        }

        self.participants.insert(participant.id.clone(), participant);
        Ok(())
    }

    /// Remove a participant
    pub fn remove_participant(&mut self, id: &str) {
        self.participants.remove(id);
    }

    /// Get participant count
    pub fn participant_count(&self) -> usize {
        self.participants.len()
    }

    /// Check if sharing is active
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Get our role
    pub fn role(&self) -> SharingRole {
        self.role
    }

    /// Generate a sharing invite (connection info)
    pub fn generate_invite(&self, host: &str, port: u16, public_key: &[u8]) -> SharingInvite {
        SharingInvite {
            session_id: self.session_id.clone(),
            host: host.to_string(),
            port,
            public_key: public_key.to_vec(),
        }
    }
}

/// Sharing invite that can be sent to peers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharingInvite {
    pub session_id: String,
    pub host: String,
    pub port: u16,
    pub public_key: Vec<u8>,
}

impl SharingInvite {
    /// Encode as a base64 string for easy sharing
    pub fn encode(&self) -> String {
        let json = serde_json::to_string(self).unwrap_or_default();
        base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE,
            json.as_bytes(),
        )
    }

    /// Decode from a base64 string
    pub fn decode(encoded: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let bytes = base64::Engine::decode(
            &base64::engine::general_purpose::URL_SAFE,
            encoded,
        )?;
        let json = String::from_utf8(bytes)?;
        Ok(serde_json::from_str(&json)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_host_creation() {
        let sharing = SessionSharing::new_host("test-session", 5);
        assert_eq!(sharing.role(), SharingRole::Host);
        assert!(!sharing.is_active());
    }

    #[test]
    fn test_start_stop() {
        let mut sharing = SessionSharing::new_host("test", 5);
        sharing.start().unwrap();
        assert!(sharing.is_active());
        sharing.stop();
        assert!(!sharing.is_active());
    }

    #[test]
    fn test_add_participant() {
        let mut sharing = SessionSharing::new_host("test", 2);
        sharing.start().unwrap();

        sharing.add_participant(Participant {
            id: "user1".to_string(),
            display_name: "Alice".to_string(),
            mode: SharingMode::ReadOnly,
            public_key: vec![0; 32],
            connected: true,
        }).unwrap();

        assert_eq!(sharing.participant_count(), 1);
    }
}
