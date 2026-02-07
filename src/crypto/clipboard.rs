// ╔══════════════════════════════════════════════════════════════════╗
// ║              GhostShell — Secure Clipboard                       ║
// ║         Encrypted clipboard with TTL, paste limits, isolation   ║
// ╚══════════════════════════════════════════════════════════════════╝

use crate::crypto::secure_mem::SecureBuffer;
use std::time::{Duration, Instant};
use zeroize::Zeroize;

// ── Content Classification ───────────────────────────────────────

/// Classified content type for automatic handling
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentType {
    /// Regular text
    Text,
    /// Likely a password (high entropy, short)
    Password,
    /// SSH private key
    SshKey,
    /// API token or secret key
    ApiToken,
    /// Credit card number (passes Luhn check)
    CreditCard,
    /// Unknown / binary data
    Unknown,
}

/// Classifies clipboard content by detecting sensitive data patterns
pub struct ContentClassifier;

impl ContentClassifier {
    /// Classify the content of a clipboard entry
    pub fn classify(data: &[u8]) -> ContentType {
        let text = match std::str::from_utf8(data) {
            Ok(s) => s.trim(),
            Err(_) => return ContentType::Unknown,
        };

        if text.is_empty() {
            return ContentType::Text;
        }

        // SSH key detection
        if text.starts_with("-----BEGIN") && text.contains("PRIVATE KEY") {
            return ContentType::SshKey;
        }
        if text.starts_with("ssh-rsa ") || text.starts_with("ssh-ed25519 ") {
            return ContentType::SshKey;
        }

        // API token patterns
        if text.starts_with("sk-") || text.starts_with("sk_live_") || text.starts_with("sk_test_") {
            return ContentType::ApiToken;
        }
        if text.starts_with("ghp_") || text.starts_with("gho_") || text.starts_with("ghs_") {
            return ContentType::ApiToken;
        }
        if text.starts_with("AKIA") && text.len() == 20 && text.chars().all(|c| c.is_ascii_alphanumeric()) {
            return ContentType::ApiToken;
        }
        if text.starts_with("xoxb-") || text.starts_with("xoxp-") || text.starts_with("xoxa-") {
            return ContentType::ApiToken;
        }

        // Credit card detection (digits only, Luhn check)
        let digits_only: String = text.chars().filter(|c| c.is_ascii_digit()).collect();
        if digits_only.len() >= 13 && digits_only.len() <= 19 && Self::luhn_check(&digits_only) {
            return ContentType::CreditCard;
        }

        // Password heuristics: short, high entropy, mixed character classes
        if text.len() >= 8 && text.len() <= 128 && !text.contains(' ') {
            let entropy = Self::shannon_entropy(text.as_bytes());
            if entropy > 3.5 {
                let has_upper = text.chars().any(|c| c.is_ascii_uppercase());
                let has_lower = text.chars().any(|c| c.is_ascii_lowercase());
                let has_digit = text.chars().any(|c| c.is_ascii_digit());
                let has_special = text.chars().any(|c| !c.is_alphanumeric());

                let classes = [has_upper, has_lower, has_digit, has_special]
                    .iter()
                    .filter(|&&v| v)
                    .count();

                if classes >= 3 {
                    return ContentType::Password;
                }
            }
        }

        ContentType::Text
    }

    /// Luhn check for credit card numbers
    fn luhn_check(digits: &str) -> bool {
        let mut sum = 0u32;
        let mut alternate = false;

        for ch in digits.chars().rev() {
            let mut n = ch.to_digit(10).unwrap_or(0);
            if alternate {
                n *= 2;
                if n > 9 {
                    n -= 9;
                }
            }
            sum += n;
            alternate = !alternate;
        }

        sum % 10 == 0
    }

    /// Shannon entropy of byte data (bits per byte)
    fn shannon_entropy(data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }

        let mut freq = [0u32; 256];
        for &byte in data {
            freq[byte as usize] += 1;
        }

        let len = data.len() as f64;
        let mut entropy = 0.0;

        for &count in &freq {
            if count > 0 {
                let p = count as f64 / len;
                entropy -= p * p.log2();
            }
        }

        entropy
    }

    /// Check if content should be auto-redacted from recordings
    pub fn should_redact(content_type: ContentType) -> bool {
        matches!(
            content_type,
            ContentType::Password | ContentType::SshKey | ContentType::ApiToken | ContentType::CreditCard
        )
    }
}

// ── Clipboard Entry ──────────────────────────────────────────────

/// A clipboard entry with expiration and paste counting
struct ClipboardEntry {
    data: SecureBuffer,
    created_at: Instant,
    ttl: Duration,
    remaining_pastes: Option<u32>,
    mime_type: String,
    /// Pane isolation: if set, only this pane can access the entry
    pane_id: Option<u64>,
    /// Classified content type
    content_type: ContentType,
}

impl ClipboardEntry {
    fn is_expired(&self) -> bool {
        self.created_at.elapsed() > self.ttl
    }

    fn can_paste(&self) -> bool {
        match self.remaining_pastes {
            Some(0) => false,
            _ => true,
        }
    }

    fn consume_paste(&mut self) {
        if let Some(ref mut count) = self.remaining_pastes {
            *count = count.saturating_sub(1);
        }
    }

    fn accessible_from(&self, pane_id: Option<u64>) -> bool {
        match self.pane_id {
            Some(entry_pane) => pane_id == Some(entry_pane),
            None => true,
        }
    }
}

// ── Secure Clipboard ─────────────────────────────────────────────

/// Secure clipboard that never touches the system clipboard
pub struct SecureClipboard {
    entries: Vec<ClipboardEntry>,
    max_entries: usize,
    default_ttl: Duration,
    default_max_pastes: Option<u32>,
    pub isolation_enabled: bool,
    pub classify_content: bool,
}

impl SecureClipboard {
    pub fn new(ttl_seconds: u64, max_pastes: u32) -> Self {
        Self {
            entries: Vec::new(),
            max_entries: 64,
            default_ttl: if ttl_seconds > 0 {
                Duration::from_secs(ttl_seconds)
            } else {
                Duration::from_secs(u64::MAX)
            },
            default_max_pastes: if max_pastes > 0 {
                Some(max_pastes)
            } else {
                None
            },
            isolation_enabled: false,
            classify_content: true,
        }
    }

    pub fn copy(&mut self, data: &[u8]) {
        self.copy_with_options(data, "text/plain", None, None, None);
    }

    pub fn copy_for_pane(&mut self, data: &[u8], pane_id: u64) {
        self.copy_with_options(data, "text/plain", None, None, Some(pane_id));
    }

    pub fn copy_with_options(
        &mut self,
        data: &[u8],
        mime_type: &str,
        ttl: Option<Duration>,
        max_pastes: Option<u32>,
        pane_id: Option<u64>,
    ) {
        self.purge_expired();

        while self.entries.len() >= self.max_entries {
            if let Some(entry) = self.entries.first_mut() {
                entry.data.wipe();
            }
            self.entries.remove(0);
        }

        let content_type = if self.classify_content {
            ContentClassifier::classify(data)
        } else {
            ContentType::Text
        };

        let effective_pane_id = if self.isolation_enabled { pane_id } else { None };

        self.entries.push(ClipboardEntry {
            data: SecureBuffer::from_data(data),
            created_at: Instant::now(),
            ttl: ttl.unwrap_or(self.default_ttl),
            remaining_pastes: max_pastes.or(self.default_max_pastes),
            mime_type: mime_type.to_string(),
            pane_id: effective_pane_id,
            content_type,
        });
    }

    pub fn paste(&mut self) -> Option<Vec<u8>> {
        self.paste_for_pane(None)
    }

    pub fn paste_for_pane(&mut self, pane_id: Option<u64>) -> Option<Vec<u8>> {
        self.purge_expired();

        let idx = self.entries.iter().rposition(|e| {
            !e.is_expired() && e.can_paste() && e.accessible_from(pane_id)
        });

        if let Some(idx) = idx {
            let entry = &mut self.entries[idx];
            entry.consume_paste();
            let data = entry.data.as_bytes().to_vec();

            if !entry.can_paste() {
                entry.data.wipe();
                self.entries.remove(idx);
            }

            Some(data)
        } else {
            None
        }
    }

    pub fn last_content_type(&self) -> Option<ContentType> {
        self.entries.last().map(|e| e.content_type)
    }

    pub fn should_redact_last(&self) -> bool {
        self.entries
            .last()
            .map(|e| ContentClassifier::should_redact(e.content_type))
            .unwrap_or(false)
    }

    pub fn count(&self) -> usize {
        self.entries.len()
    }

    pub fn wipe(&mut self) {
        for entry in &mut self.entries {
            entry.data.wipe();
        }
        self.entries.clear();
    }

    fn purge_expired(&mut self) {
        let mut i = 0;
        while i < self.entries.len() {
            if self.entries[i].is_expired() || !self.entries[i].can_paste() {
                self.entries[i].data.wipe();
                self.entries.remove(i);
            } else {
                i += 1;
            }
        }
    }

    pub fn history(&self) -> Vec<ClipboardHistoryEntry> {
        self.entries
            .iter()
            .map(|e| ClipboardHistoryEntry {
                size: e.data.len(),
                mime_type: e.mime_type.clone(),
                age_seconds: e.created_at.elapsed().as_secs(),
                remaining_pastes: e.remaining_pastes,
                expired: e.is_expired(),
                content_type: e.content_type,
                pane_id: e.pane_id,
            })
            .collect()
    }
}

/// Metadata about a clipboard entry (no actual data exposed)
#[derive(Debug, Clone)]
pub struct ClipboardHistoryEntry {
    pub size: usize,
    pub mime_type: String,
    pub age_seconds: u64,
    pub remaining_pastes: Option<u32>,
    pub expired: bool,
    pub content_type: ContentType,
    pub pane_id: Option<u64>,
}

impl Drop for SecureClipboard {
    fn drop(&mut self) {
        self.wipe();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_copy_paste() {
        let mut clipboard = SecureClipboard::new(60, 0);
        clipboard.copy(b"test data");
        let pasted = clipboard.paste().unwrap();
        assert_eq!(&pasted, b"test data");
    }

    #[test]
    fn test_paste_limit() {
        let mut clipboard = SecureClipboard::new(60, 2);
        clipboard.copy(b"limited data");
        assert!(clipboard.paste().is_some());
        assert!(clipboard.paste().is_some());
        assert!(clipboard.paste().is_none());
    }

    #[test]
    fn test_wipe() {
        let mut clipboard = SecureClipboard::new(60, 0);
        clipboard.copy(b"data 1");
        clipboard.copy(b"data 2");
        assert_eq!(clipboard.count(), 2);
        clipboard.wipe();
        assert_eq!(clipboard.count(), 0);
        assert!(clipboard.paste().is_none());
    }

    #[test]
    fn test_history() {
        let mut clipboard = SecureClipboard::new(60, 0);
        clipboard.copy(b"hello");
        clipboard.copy_with_options(b"world", "text/html", None, Some(3), None);
        let history = clipboard.history();
        assert_eq!(history.len(), 2);
        assert_eq!(history[0].size, 5);
        assert_eq!(history[1].mime_type, "text/html");
        assert_eq!(history[1].remaining_pastes, Some(3));
    }

    #[test]
    fn test_classify_ssh_key() {
        let key = b"-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCA...";
        assert_eq!(ContentClassifier::classify(key), ContentType::SshKey);
        let pub_key = b"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA user@host";
        assert_eq!(ContentClassifier::classify(pub_key), ContentType::SshKey);
    }

    #[test]
    fn test_classify_api_tokens() {
        assert_eq!(ContentClassifier::classify(b"ghp_1234567890abcdef1234567890abcdef12345678"), ContentType::ApiToken);
        assert_eq!(ContentClassifier::classify(b"sk-1234567890abcdef123456"), ContentType::ApiToken);
        assert_eq!(ContentClassifier::classify(b"xoxb-123-456-789"), ContentType::ApiToken);
    }

    #[test]
    fn test_classify_credit_card() {
        assert_eq!(ContentClassifier::classify(b"4111111111111111"), ContentType::CreditCard);
    }

    #[test]
    fn test_classify_password() {
        assert_eq!(ContentClassifier::classify(b"MyP@ssw0rd!2024"), ContentType::Password);
    }

    #[test]
    fn test_classify_plain_text() {
        assert_eq!(ContentClassifier::classify(b"Hello, this is normal text"), ContentType::Text);
    }

    #[test]
    fn test_pane_isolation() {
        let mut clipboard = SecureClipboard::new(60, 0);
        clipboard.isolation_enabled = true;
        clipboard.copy_for_pane(b"pane 1 secret", 1);
        clipboard.copy_for_pane(b"pane 2 secret", 2);

        let pasted = clipboard.paste_for_pane(Some(2)).unwrap();
        assert_eq!(&pasted, b"pane 2 secret");
        let pasted = clipboard.paste_for_pane(Some(1)).unwrap();
        assert_eq!(&pasted, b"pane 1 secret");
        assert!(clipboard.paste_for_pane(Some(3)).is_none());
    }

    #[test]
    fn test_should_redact() {
        assert!(ContentClassifier::should_redact(ContentType::Password));
        assert!(ContentClassifier::should_redact(ContentType::SshKey));
        assert!(ContentClassifier::should_redact(ContentType::ApiToken));
        assert!(ContentClassifier::should_redact(ContentType::CreditCard));
        assert!(!ContentClassifier::should_redact(ContentType::Text));
    }

    #[test]
    fn test_content_type_in_history() {
        let mut clipboard = SecureClipboard::new(60, 0);
        clipboard.copy(b"ghp_abc123def456ghi789jkl012mno345pqr678");
        let history = clipboard.history();
        assert_eq!(history[0].content_type, ContentType::ApiToken);
    }
}
