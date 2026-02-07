// ╔══════════════════════════════════════════════════════════════════╗
// ║              GhostShell — IDS Signatures                         ║
// ║         Extensible signature database for threat detection       ║
// ╚══════════════════════════════════════════════════════════════════╝

use serde::{Deserialize, Serialize};

/// A threat signature
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signature {
    pub id: String,
    pub name: String,
    pub category: SignatureCategory,
    pub pattern: String,
    pub description: String,
    pub severity: u8, // 1-10
    pub enabled: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignatureCategory {
    ReverseShell,
    PrivilegeEscalation,
    DataExfiltration,
    Persistence,
    Reconnaissance,
    Destructive,
    CryptoMining,
    AntiForensics,
    Malware,
    Custom,
}

/// Signature database
pub struct SignatureDatabase {
    signatures: Vec<Signature>,
}

impl SignatureDatabase {
    pub fn new() -> Self {
        let mut db = Self {
            signatures: Vec::new(),
        };
        db.load_defaults();
        db
    }

    fn load_defaults(&mut self) {
        // Core signatures are handled by CommandAnalyzer
        // This DB provides the extensible layer for user-defined rules
        self.signatures.push(Signature {
            id: "CUSTOM-001".to_string(),
            name: "SSH Brute Force Tool".to_string(),
            category: SignatureCategory::Reconnaissance,
            pattern: r"(hydra|medusa|patator).*ssh".to_string(),
            description: "Known SSH brute force tool detected".to_string(),
            severity: 8,
            enabled: true,
        });

        self.signatures.push(Signature {
            id: "CUSTOM-002".to_string(),
            name: "Web Shell Upload".to_string(),
            category: SignatureCategory::Persistence,
            pattern: r"(wget|curl).*\.(php|jsp|asp)".to_string(),
            description: "Potential web shell download".to_string(),
            severity: 7,
            enabled: true,
        });

        self.signatures.push(Signature {
            id: "CUSTOM-003".to_string(),
            name: "Kernel Exploit".to_string(),
            category: SignatureCategory::PrivilegeEscalation,
            pattern: r"(dirtycow|dirtypipe|overlayfs|exploit)".to_string(),
            description: "Potential kernel exploit reference".to_string(),
            severity: 9,
            enabled: true,
        });
    }

    /// Get all enabled signatures
    pub fn enabled_signatures(&self) -> Vec<&Signature> {
        self.signatures.iter().filter(|s| s.enabled).collect()
    }

    /// Add a custom signature
    pub fn add_signature(&mut self, sig: Signature) {
        self.signatures.push(sig);
    }

    /// Get signature count
    pub fn count(&self) -> usize {
        self.signatures.len()
    }

    /// Toggle a signature by ID
    pub fn toggle(&mut self, id: &str) -> bool {
        if let Some(sig) = self.signatures.iter_mut().find(|s| s.id == id) {
            sig.enabled = !sig.enabled;
            sig.enabled
        } else {
            false
        }
    }
}

impl Default for SignatureDatabase {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_signatures() {
        let db = SignatureDatabase::new();
        assert!(db.count() > 0);
        assert!(!db.enabled_signatures().is_empty());
    }

    #[test]
    fn test_add_custom() {
        let mut db = SignatureDatabase::new();
        let initial = db.count();
        db.add_signature(Signature {
            id: "TEST-001".to_string(),
            name: "Test Sig".to_string(),
            category: SignatureCategory::Custom,
            pattern: "test_pattern".to_string(),
            description: "Test".to_string(),
            severity: 5,
            enabled: true,
        });
        assert_eq!(db.count(), initial + 1);
    }

    #[test]
    fn test_toggle_signature() {
        let mut db = SignatureDatabase::new();
        assert!(db.toggle("CUSTOM-001") == false); // Was true, now false
    }
}
