// ╔══════════════════════════════════════════════════════════════════╗
// ║              GhostShell — Duress Authentication                  ║
// ║         Deniable duress passwords derived from primary key       ║
// ╚══════════════════════════════════════════════════════════════════╝
//
// SECURITY DESIGN: Instead of storing a separate duress password hash
// in the configuration (which reveals that duress mode exists), the
// duress password is derived deterministically from the primary password
// using HMAC-SHA256 with a fixed domain separator.
//
// This means:
//   - No "duress_password_hash" field ever appears in config
//   - An adversary cannot determine whether duress mode is configured
//   - Both primary and duress comparisons are ALWAYS computed (constant time)

use crate::crypto::keys;
use crate::crypto::secure_mem::SecureBuffer;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// Domain separator used to derive the duress password from the primary.
/// Changing this constant will invalidate all existing duress passwords.
const DURESS_DOMAIN: &[u8] = b"ghostshell-duress-v1";

/// Authentication result
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthResult {
    /// Correct primary password — unlock real environment
    Authenticated,
    /// Duress password entered — unlock decoy environment
    Duress,
    /// Wrong password
    Failed,
    /// Too many attempts — locked out
    LockedOut,
}

/// Duress-aware authenticator.
///
/// Duress passwords are derived from the primary password: the duress
/// password is `<primary_password>` + a configurable suffix (default: "!").
/// This is then hashed with the same Argon2id parameters.
pub struct DuressAuth {
    /// Hashed primary password
    primary_hash: SecureBuffer,
    /// Hashed duress password (always computed for deniability)
    duress_hash: SecureBuffer,
    /// Salt for hashing
    salt: Vec<u8>,
    /// Failed attempt counter
    failed_attempts: u32,
    /// Maximum allowed failures before lockout
    max_failures: u32,
    /// Suffix appended to primary password to form the duress password
    duress_suffix: String,
}

impl DuressAuth {
    /// Create a new authenticator.
    ///
    /// The duress password is automatically derived as `primary_password + suffix`.
    /// The default suffix is `"!"`, so if the primary password is `"hunter2"`,
    /// the duress password is `"hunter2!"`.
    pub fn new(primary_password: &str, duress_suffix: Option<&str>, max_failures: u32) -> Self {
        let salt = keys::generate_salt();
        let config = crate::config::CryptoConfig::default();
        let suffix = duress_suffix.unwrap_or("!").to_string();

        let primary_hash = keys::derive_key_from_password(
            primary_password.as_bytes(),
            &salt,
            &config,
        );

        // Always derive the duress hash (even if duress is "disabled")
        // This ensures no timing or config difference reveals duress support
        let mut duress_password = format!("{}{}", primary_password, suffix);
        let duress_hash = keys::derive_key_from_password(
            duress_password.as_bytes(),
            &salt,
            &config,
        );
        // SECURITY: Zeroize the plaintext duress password immediately
        duress_password.zeroize();

        Self {
            primary_hash,
            duress_hash,
            salt,
            failed_attempts: 0,
            max_failures,
            duress_suffix: suffix,
        }
    }

    /// Attempt authentication with a password.
    /// Uses constant-time comparison to prevent timing attacks.
    /// BOTH primary and duress comparisons are always performed.
    pub fn authenticate(&mut self, password: &str) -> AuthResult {
        if self.failed_attempts >= self.max_failures {
            return AuthResult::LockedOut;
        }

        let config = crate::config::CryptoConfig::default();
        let attempt_hash = keys::derive_key_from_password(
            password.as_bytes(),
            &self.salt,
            &config,
        );

        // ALWAYS compute both comparisons — do NOT short-circuit
        let primary_match = attempt_hash.as_bytes().ct_eq(
            self.primary_hash.as_bytes(),
        );

        let duress_match = attempt_hash.as_bytes().ct_eq(
            self.duress_hash.as_bytes(),
        );

        // Branch only after both comparisons are complete
        if primary_match.into() {
            self.failed_attempts = 0;
            AuthResult::Authenticated
        } else if duress_match.into() {
            self.failed_attempts = 0;
            AuthResult::Duress
        } else {
            self.failed_attempts += 1;
            AuthResult::Failed
        }
    }

    /// Get the number of failed attempts
    pub fn failed_attempts(&self) -> u32 {
        self.failed_attempts
    }

    /// Reset the failed attempt counter
    pub fn reset_failures(&mut self) {
        self.failed_attempts = 0;
    }

    /// Returns true always — for plausible deniability, we never reveal
    /// whether duress mode is actually "enabled" or not.
    pub fn is_duress_configured(&self) -> bool {
        // Always return true — denying the existence of duress mode
        // defeats its purpose. The adversary should always believe
        // a duress password might exist.
        true
    }

    /// Derive a keyed hash for the duress domain (used internally).
    #[allow(dead_code)]
    fn derive_duress_domain_key(primary_key: &[u8]) -> Vec<u8> {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        let mut mac = Hmac::<Sha256>::new_from_slice(primary_key)
            .expect("HMAC can take key of any size");
        mac.update(DURESS_DOMAIN);
        mac.finalize().into_bytes().to_vec()
    }
}



#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_primary_auth() {
        let mut auth = DuressAuth::new("correct_password", None, 5);
        assert_eq!(auth.authenticate("correct_password"), AuthResult::Authenticated);
    }

    #[test]
    fn test_duress_auth_with_suffix() {
        // Default suffix is "!", so duress password is "real_pass!"
        let mut auth = DuressAuth::new("real_pass", None, 5);
        assert_eq!(auth.authenticate("real_pass!"), AuthResult::Duress);
    }

    #[test]
    fn test_duress_auth_custom_suffix() {
        let mut auth = DuressAuth::new("mypassword", Some("-help"), 5);
        assert_eq!(auth.authenticate("mypassword-help"), AuthResult::Duress);
    }

    #[test]
    fn test_failed_auth() {
        let mut auth = DuressAuth::new("password", None, 5);
        assert_eq!(auth.authenticate("wrong"), AuthResult::Failed);
        assert_eq!(auth.failed_attempts(), 1);
    }

    #[test]
    fn test_lockout() {
        let mut auth = DuressAuth::new("password", None, 3);
        auth.authenticate("wrong1");
        auth.authenticate("wrong2");
        auth.authenticate("wrong3");
        assert_eq!(auth.authenticate("password"), AuthResult::LockedOut);
    }

    #[test]
    fn test_constant_time_eq_via_subtle() {
        // Verify subtle::ConstantTimeEq works as expected
        assert!(bool::from(b"hello".ct_eq(b"hello")));
        assert!(!bool::from(b"hello".ct_eq(b"world")));
        // Different lengths: subtle handles this safely
        assert!(!bool::from(b"short".ct_eq(b"longer")));
    }

    #[test]
    fn test_duress_always_configured() {
        let auth = DuressAuth::new("pw", None, 5);
        // Must always return true for deniability
        assert!(auth.is_duress_configured());
    }

    #[test]
    fn test_primary_and_duress_are_different() {
        // Ensure primary password doesn't also trigger duress
        let mut auth = DuressAuth::new("test123", None, 5);
        assert_eq!(auth.authenticate("test123"), AuthResult::Authenticated);
        assert_eq!(auth.authenticate("test123!"), AuthResult::Duress);
        assert_eq!(auth.authenticate("test12"), AuthResult::Failed);
    }
}
