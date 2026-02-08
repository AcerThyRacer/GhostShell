// ╔══════════════════════════════════════════════════════════════════╗
// ║              GhostShell — Key Management                         ║
// ║         Argon2id KDF, key hierarchy, and generation              ║
// ╚══════════════════════════════════════════════════════════════════╝

use crate::config::CryptoConfig;
use crate::crypto::secure_mem::SecureBuffer;
use argon2::{
    Argon2, Params, Version,
};
use rand::RngCore;
use zeroize::Zeroize;

/// Key size constants
pub const MASTER_KEY_SIZE: usize = 32;
pub const SESSION_KEY_SIZE: usize = 32;
pub const NONCE_SIZE: usize = 12;
pub const SALT_SIZE: usize = 32;

/// A key in the hierarchy
#[derive(Clone)]
pub struct DerivedKey {
    pub key: SecureBuffer,
    pub salt: Vec<u8>,
    pub purpose: String,
}

impl DerivedKey {
    /// Derive a sub-key from this key for a specific purpose
    pub fn derive_subkey(&self, purpose: &str, config: &CryptoConfig) -> Self {
        let mut salt = vec![0u8; SALT_SIZE];
        rand::thread_rng().fill_bytes(&mut salt);

        let key_material = derive_key_argon2id(
            self.key.as_bytes(),
            &salt,
            config.argon2_memory_kib,
            config.argon2_iterations,
            config.argon2_parallelism,
        );

        Self {
            key: key_material,
            salt,
            purpose: purpose.to_string(),
        }
    }
}

/// Generate a new random master key.
/// SECURITY: Returns a SecureBuffer (mlock'd, zeroize-on-drop) —
/// callers never need to manually zeroize.
pub fn generate_master_key() -> SecureBuffer {
    let mut key = vec![0u8; MASTER_KEY_SIZE];
    rand::thread_rng().fill_bytes(&mut key);
    let buf = SecureBuffer::from_data(&key);
    key.zeroize();
    buf
}

/// Generate a random nonce for encryption
pub fn generate_nonce() -> [u8; NONCE_SIZE] {
    let mut nonce = [0u8; NONCE_SIZE];
    rand::thread_rng().fill_bytes(&mut nonce);
    nonce
}

/// Generate a random salt
pub fn generate_salt() -> Vec<u8> {
    let mut salt = vec![0u8; SALT_SIZE];
    rand::thread_rng().fill_bytes(&mut salt);
    salt
}

/// Derive a key from a password using Argon2id
pub fn derive_key_from_password(
    password: &[u8],
    salt: &[u8],
    config: &CryptoConfig,
) -> SecureBuffer {
    derive_key_argon2id(
        password,
        salt,
        config.argon2_memory_kib,
        config.argon2_iterations,
        config.argon2_parallelism,
    )
}

/// Core Argon2id key derivation
pub fn derive_key_argon2id(
    input: &[u8],
    salt: &[u8],
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
) -> SecureBuffer {
    let params = Params::new(
        memory_kib,
        iterations,
        parallelism,
        Some(MASTER_KEY_SIZE),
    )
    .expect("Argon2id parameter error — refusing to use weak defaults");

    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, Version::V0x13, params);

    let mut output = vec![0u8; MASTER_KEY_SIZE];

    // Use raw hash API — fail hard if Argon2id cannot run.
    // SECURITY: Never silently fall back to a weaker KDF.
    argon2
        .hash_password_into(input, salt, &mut output)
        .expect("Argon2id key derivation failed — refusing to use weak fallback");

    let buf = SecureBuffer::from_data(&output);
    output.zeroize();
    buf
}

/// Derive an HMAC key from a master key
pub fn derive_hmac_key(master_key: &[u8], context: &[u8]) -> SecureBuffer {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(master_key)
        .expect("HMAC key size error");
    mac.update(context);
    mac.update(b"ghostshell-hmac-derivation");
    let result = mac.finalize();

    SecureBuffer::from_data(&result.into_bytes())
}

/// Key rotation: generates a new key and re-encrypts data
pub struct KeyRotation {
    pub old_key: SecureBuffer,
    pub new_key: SecureBuffer,
    pub new_salt: Vec<u8>,
}

impl KeyRotation {
    pub fn new(old_key: SecureBuffer, _config: &CryptoConfig) -> Self {
        let new_salt = generate_salt();
        let new_key = generate_master_key();

        Self {
            old_key,
            new_key,
            new_salt,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_master_key_generation() {
        let key = generate_master_key();
        assert_eq!(key.len(), MASTER_KEY_SIZE);
        // Should be random, not all zeros
        assert!(!key.as_bytes().iter().all(|&b| b == 0));
    }

    #[test]
    fn test_nonce_generation() {
        let nonce1 = generate_nonce();
        let nonce2 = generate_nonce();
        assert_ne!(nonce1, nonce2); // Should be unique
    }

    #[test]
    fn test_key_derivation() {
        let config = CryptoConfig::default();
        let password = b"test-password-123";
        let salt = generate_salt();

        let key1 = derive_key_from_password(password, &salt, &config);
        let key2 = derive_key_from_password(password, &salt, &config);

        // Same password + salt should produce same key
        assert_eq!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn test_different_salts_different_keys() {
        let config = CryptoConfig::default();
        let password = b"test-password-123";

        let key1 = derive_key_from_password(password, &generate_salt(), &config);
        let key2 = derive_key_from_password(password, &generate_salt(), &config);

        // Different salts should produce different keys
        assert_ne!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn test_hmac_derivation() {
        let master = generate_master_key();
        let hmac_key = derive_hmac_key(master.as_bytes(), b"test-context");
        assert_eq!(hmac_key.len(), 32);
    }

}
