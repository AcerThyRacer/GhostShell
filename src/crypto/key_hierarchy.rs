// ╔══════════════════════════════════════════════════════════════════╗
// ║              GhostShell — Key Hierarchy & Secret Sharing         ║
// ║         Master → Session → Per-Message keys + Shamir SSS        ║
// ╚══════════════════════════════════════════════════════════════════╝

use crate::config::CryptoConfig;
use crate::crypto::keys::{generate_salt, derive_key_argon2id, SALT_SIZE};
use crate::crypto::secure_mem::SecureBuffer;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};
use zeroize::Zeroize;

// ── Key Purpose ──────────────────────────────────────────────────

/// The purpose of a derived key in the hierarchy
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum KeyPurpose {
    /// Session-level encryption (PTY I/O)
    Session,
    /// Recording encryption (.ghost files)
    Recording,
    /// Audit log encryption
    Audit,
    /// Clipboard encryption
    Clipboard,
    /// Network transport encryption
    Network,
    /// HMAC / integrity verification
    Integrity,
}

impl KeyPurpose {
    /// Domain separation label used in key derivation
    pub fn label(&self) -> &'static [u8] {
        match self {
            Self::Session => b"ghostshell-session-key-v1",
            Self::Recording => b"ghostshell-recording-key-v1",
            Self::Audit => b"ghostshell-audit-key-v1",
            Self::Clipboard => b"ghostshell-clipboard-key-v1",
            Self::Network => b"ghostshell-network-key-v1",
            Self::Integrity => b"ghostshell-integrity-key-v1",
        }
    }
}

// ── Key Schedule ─────────────────────────────────────────────────

/// When to rotate a key
#[derive(Debug, Clone)]
pub struct KeySchedule {
    /// Maximum lifetime before forced rotation
    pub max_age: Duration,
    /// Maximum messages encrypted before rotation
    pub max_messages: u64,
    /// When this schedule was created
    created_at: Instant,
    /// Messages encrypted with current key
    message_count: u64,
}

impl KeySchedule {
    pub fn new(max_age_secs: u64, max_messages: u64) -> Self {
        Self {
            max_age: Duration::from_secs(max_age_secs),
            max_messages,
            created_at: Instant::now(),
            message_count: 0,
        }
    }

    /// Default schedule: 1 hour, 1M messages
    pub fn default_session() -> Self {
        Self::new(3600, 1_000_000)
    }

    /// Conservative schedule for long-lived keys: 24h, 10M messages
    pub fn default_master() -> Self {
        Self::new(86400, 10_000_000)
    }

    /// Record a message encryption
    pub fn tick(&mut self) {
        self.message_count += 1;
    }

    /// Check if rotation is needed
    pub fn needs_rotation(&self) -> bool {
        self.created_at.elapsed() >= self.max_age || self.message_count >= self.max_messages
    }

    /// Reset after rotation
    pub fn reset(&mut self) {
        self.created_at = Instant::now();
        self.message_count = 0;
    }

    /// Remaining messages before rotation
    pub fn remaining_messages(&self) -> u64 {
        self.max_messages.saturating_sub(self.message_count)
    }

    /// Remaining time before rotation
    pub fn remaining_time(&self) -> Duration {
        self.max_age
            .checked_sub(self.created_at.elapsed())
            .unwrap_or(Duration::ZERO)
    }
}

// ── Key Hierarchy ────────────────────────────────────────────────

/// A node in the key hierarchy tree
#[derive(Clone)]
pub struct HierarchyKey {
    pub key: SecureBuffer,
    pub salt: Vec<u8>,
    pub purpose: KeyPurpose,
    pub generation: u32,
}

/// The full key hierarchy: Master → purpose-specific derived keys
pub struct KeyHierarchy {
    master: HierarchyKey,
    session_key: HierarchyKey,
    recording_key: HierarchyKey,
    audit_key: HierarchyKey,
    clipboard_key: HierarchyKey,
    network_key: HierarchyKey,
    integrity_key: HierarchyKey,
    schedule: KeySchedule,
}

impl KeyHierarchy {
    /// Initialize a new key hierarchy from a master key
    pub fn new(master_key: &[u8], config: &CryptoConfig) -> Self {
        let master_salt = generate_salt();
        let master = HierarchyKey {
            key: SecureBuffer::from_data(master_key),
            salt: master_salt,
            purpose: KeyPurpose::Session, // master is root
            generation: 0,
        };

        let session_key = Self::derive_purpose_key(&master, KeyPurpose::Session, config);
        let recording_key = Self::derive_purpose_key(&master, KeyPurpose::Recording, config);
        let audit_key = Self::derive_purpose_key(&master, KeyPurpose::Audit, config);
        let clipboard_key = Self::derive_purpose_key(&master, KeyPurpose::Clipboard, config);
        let network_key = Self::derive_purpose_key(&master, KeyPurpose::Network, config);
        let integrity_key = Self::derive_purpose_key(&master, KeyPurpose::Integrity, config);

        Self {
            master,
            session_key,
            recording_key,
            audit_key,
            clipboard_key,
            network_key,
            integrity_key,
            schedule: KeySchedule::default_session(),
        }
    }

    /// Derive a purpose-specific key from the master
    fn derive_purpose_key(
        master: &HierarchyKey,
        purpose: KeyPurpose,
        config: &CryptoConfig,
    ) -> HierarchyKey {
        let mut salt = vec![0u8; SALT_SIZE];
        rand::thread_rng().fill_bytes(&mut salt);

        // Combine master key with purpose label for domain separation
        let mut input = Vec::with_capacity(master.key.len() + 32);
        input.extend_from_slice(master.key.as_bytes());
        input.extend_from_slice(purpose.label());

        let key = derive_key_argon2id(
            &input,
            &salt,
            config.argon2_memory_kib,
            config.argon2_iterations,
            config.argon2_parallelism,
        );

        // SECURITY: Use zeroize() instead of manual zeroing — the compiler
        // is allowed to optimize away plain writes to dead variables.
        input.zeroize();

        HierarchyKey {
            key,
            salt,
            purpose,
            generation: 0,
        }
    }

    /// Get the key for a specific purpose
    pub fn key_for(&self, purpose: KeyPurpose) -> &SecureBuffer {
        match purpose {
            KeyPurpose::Session => &self.session_key.key,
            KeyPurpose::Recording => &self.recording_key.key,
            KeyPurpose::Audit => &self.audit_key.key,
            KeyPurpose::Clipboard => &self.clipboard_key.key,
            KeyPurpose::Network => &self.network_key.key,
            KeyPurpose::Integrity => &self.integrity_key.key,
        }
    }

    /// Record a message encryption and check if rotation is needed
    pub fn tick(&mut self) -> bool {
        self.schedule.tick();
        self.schedule.needs_rotation()
    }

    /// Rotate a specific purpose key
    pub fn rotate_key(&mut self, purpose: KeyPurpose, config: &CryptoConfig) -> &SecureBuffer {
        let new_key = Self::derive_purpose_key(&self.master, purpose, config);
        let target = match purpose {
            KeyPurpose::Session => &mut self.session_key,
            KeyPurpose::Recording => &mut self.recording_key,
            KeyPurpose::Audit => &mut self.audit_key,
            KeyPurpose::Clipboard => &mut self.clipboard_key,
            KeyPurpose::Network => &mut self.network_key,
            KeyPurpose::Integrity => &mut self.integrity_key,
        };
        target.key = new_key.key;
        target.salt = new_key.salt;
        target.generation += 1;
        self.schedule.reset();
        &target.key
    }

    /// Get the key generation (how many times rotated)
    pub fn generation(&self, purpose: KeyPurpose) -> u32 {
        match purpose {
            KeyPurpose::Session => self.session_key.generation,
            KeyPurpose::Recording => self.recording_key.generation,
            KeyPurpose::Audit => self.audit_key.generation,
            KeyPurpose::Clipboard => self.clipboard_key.generation,
            KeyPurpose::Network => self.network_key.generation,
            KeyPurpose::Integrity => self.integrity_key.generation,
        }
    }

    /// Get remaining messages before rotation is needed
    pub fn remaining_messages(&self) -> u64 {
        self.schedule.remaining_messages()
    }
}

// ── Shamir's Secret Sharing ──────────────────────────────────────

/// A single share of a split secret
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShamirShare {
    /// Share index (1-based, used as x-coordinate)
    pub x: u8,
    /// Share data (same length as the original secret)
    pub y: Vec<u8>,
}

/// GF(256) finite field arithmetic for Shamir's scheme
/// Using the irreducible polynomial x^8 + x^4 + x^3 + x + 1 (0x11B)
mod gf256 {
    /// Multiply two elements in GF(256)
    pub fn mul(a: u8, b: u8) -> u8 {
        let mut result: u16 = 0;
        let mut a = a as u16;
        let mut b = b as u16;

        for _ in 0..8 {
            if b & 1 != 0 {
                result ^= a;
            }
            let carry = a & 0x80;
            a <<= 1;
            if carry != 0 {
                a ^= 0x1B; // Reduction polynomial
            }
            b >>= 1;
        }

        result as u8
    }

    /// Compute multiplicative inverse in GF(256) using extended Euclidean
    pub fn inv(a: u8) -> u8 {
        if a == 0 {
            return 0; // 0 has no inverse
        }
        // a^254 = a^(-1) in GF(256) (by Fermat's little theorem for finite fields)
        let mut result = a;
        for _ in 0..6 {
            result = mul(result, result);
            result = mul(result, a);
        }
        // Final square
        mul(result, result)
    }

    /// Evaluate a polynomial at point x in GF(256)
    pub fn eval_poly(coeffs: &[u8], x: u8) -> u8 {
        let mut result = 0u8;
        let mut x_pow = 1u8;
        for &coeff in coeffs {
            result ^= mul(coeff, x_pow);
            x_pow = mul(x_pow, x);
        }
        result
    }
}

/// Split a secret into `n` shares requiring `k` shares to reconstruct
///
/// Uses Shamir's Secret Sharing over GF(256). Each byte of the secret
/// is independently split using random polynomial coefficients.
///
/// # Arguments
/// * `secret` — the secret to split
/// * `k` — threshold (minimum shares needed to reconstruct)
/// * `n` — total number of shares to generate (n >= k)
///
/// # Returns
/// Vector of `n` shares
pub fn split_secret(secret: &[u8], k: u8, n: u8) -> Result<Vec<ShamirShare>, &'static str> {
    if k < 2 {
        return Err("threshold must be at least 2");
    }
    if n < k {
        return Err("total shares must be >= threshold");
    }
    if n > 254 {
        return Err("maximum 254 shares supported");
    }
    if secret.is_empty() {
        return Err("secret must not be empty");
    }

    let mut rng = rand::thread_rng();
    let mut shares: Vec<ShamirShare> = (1..=n)
        .map(|x| ShamirShare {
            x,
            y: vec![0u8; secret.len()],
        })
        .collect();

    // For each byte of the secret, create a random polynomial of degree k-1
    // where the constant term (x=0) is the secret byte
    for (byte_idx, &secret_byte) in secret.iter().enumerate() {
        let mut coeffs = vec![0u8; k as usize];
        coeffs[0] = secret_byte;

        // Random coefficients for degrees 1..k-1
        for coeff in coeffs.iter_mut().skip(1) {
            let mut buf = [0u8; 1];
            rng.fill_bytes(&mut buf);
            *coeff = buf[0];
        }

        // Evaluate polynomial at each share's x coordinate
        for share in &mut shares {
            share.y[byte_idx] = gf256::eval_poly(&coeffs, share.x);
        }

        // Wipe the coefficients
        coeffs.zeroize();
    }

    Ok(shares)
}

/// Reconstruct a secret from k shares using Lagrange interpolation in GF(256)
/// SECURITY: Returns a SecureBuffer (mlock'd, zeroize-on-drop) since the
/// reconstructed value is sensitive master key material.
pub fn reconstruct_secret(shares: &[ShamirShare]) -> Result<SecureBuffer, &'static str> {
    if shares.is_empty() {
        return Err("need at least one share");
    }

    let secret_len = shares[0].y.len();
    if shares.iter().any(|s| s.y.len() != secret_len) {
        return Err("all shares must have the same length");
    }

    // Check for duplicate x coordinates
    let mut seen_x = std::collections::HashSet::new();
    for share in shares {
        if !seen_x.insert(share.x) {
            return Err("duplicate share index");
        }
    }

    let k = shares.len();
    let mut secret = vec![0u8; secret_len];

    // Lagrange interpolation at x=0 for each byte position
    for byte_idx in 0..secret_len {
        let mut value = 0u8;

        for i in 0..k {
            let xi = shares[i].x;
            let yi = shares[i].y[byte_idx];

            // Compute Lagrange basis polynomial L_i(0)
            let mut basis = 1u8;
            for j in 0..k {
                if i == j {
                    continue;
                }
                let xj = shares[j].x;

                // L_i(0) *= (0 - xj) / (xi - xj) = xj / (xi ^ xj) in GF(256)
                let numerator = xj;
                let denominator = xi ^ xj;
                basis = gf256::mul(basis, gf256::mul(numerator, gf256::inv(denominator)));
            }

            value ^= gf256::mul(yi, basis);
        }

        secret[byte_idx] = value;
    }

    let result = SecureBuffer::from_data(&secret);
    // SECURITY: Zeroize the intermediate Vec before dropping
    secret.zeroize();
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::{generate_master_key, MASTER_KEY_SIZE};

    #[test]
    fn test_gf256_mul_identity() {
        // a * 1 = a
        assert_eq!(gf256::mul(42, 1), 42);
        assert_eq!(gf256::mul(1, 42), 42);
    }

    #[test]
    fn test_gf256_mul_zero() {
        assert_eq!(gf256::mul(42, 0), 0);
        assert_eq!(gf256::mul(0, 42), 0);
    }

    #[test]
    fn test_gf256_inverse() {
        // a * a^(-1) = 1 for all non-zero a
        for a in 1..=255u8 {
            let inv = gf256::inv(a);
            assert_eq!(gf256::mul(a, inv), 1, "inverse failed for a={}", a);
        }
    }

    #[test]
    fn test_shamir_2_of_3() {
        let secret = b"GhostShell master key!";
        let shares = split_secret(secret, 2, 3).unwrap();
        assert_eq!(shares.len(), 3);

        // Any 2 shares should reconstruct
        let recovered = reconstruct_secret(&shares[0..2]).unwrap();
        assert_eq!(recovered.as_bytes(), secret);

        let recovered = reconstruct_secret(&shares[1..3]).unwrap();
        assert_eq!(recovered.as_bytes(), secret);

        let recovered = reconstruct_secret(&[shares[0].clone(), shares[2].clone()]).unwrap();
        assert_eq!(recovered.as_bytes(), secret);
    }

    #[test]
    fn test_shamir_3_of_5() {
        let secret = b"super-secret-256-bit-master-key!";
        let shares = split_secret(secret, 3, 5).unwrap();
        assert_eq!(shares.len(), 5);

        // 3 shares should suffice
        let recovered = reconstruct_secret(&shares[0..3]).unwrap();
        assert_eq!(recovered.as_bytes(), &secret[..]);

        let recovered = reconstruct_secret(&shares[2..5]).unwrap();
        assert_eq!(recovered.as_bytes(), &secret[..]);
    }

    #[test]
    fn test_shamir_insufficient_shares() {
        let secret = b"secret data here";
        let shares = split_secret(secret, 3, 5).unwrap();

        // Only 2 shares with a 3-of-5 scheme should NOT recover correctly
        let recovered = reconstruct_secret(&shares[0..2]).unwrap();
        // The result should exist but be incorrect
        assert_ne!(recovered.as_bytes(), &secret[..]);
    }

    #[test]
    fn test_shamir_invalid_params() {
        assert!(split_secret(b"test", 1, 3).is_err()); // threshold too low
        assert!(split_secret(b"test", 5, 3).is_err()); // n < k
        assert!(split_secret(b"", 2, 3).is_err());     // empty secret
    }

    #[test]
    fn test_key_hierarchy_creation() {
        let master = generate_master_key();
        let config = CryptoConfig::default();
        let hierarchy = KeyHierarchy::new(master.as_bytes(), &config);

        // All keys should be 32 bytes
        assert_eq!(hierarchy.key_for(KeyPurpose::Session).len(), MASTER_KEY_SIZE);
        assert_eq!(hierarchy.key_for(KeyPurpose::Recording).len(), MASTER_KEY_SIZE);
        assert_eq!(hierarchy.key_for(KeyPurpose::Audit).len(), MASTER_KEY_SIZE);

        // Different purposes should yield different keys
        assert_ne!(
            hierarchy.key_for(KeyPurpose::Session).as_bytes(),
            hierarchy.key_for(KeyPurpose::Recording).as_bytes()
        );
    }

    #[test]
    fn test_key_rotation() {
        let master = generate_master_key();
        let config = CryptoConfig::default();
        let mut hierarchy = KeyHierarchy::new(master.as_bytes(), &config);

        let old_key = hierarchy.key_for(KeyPurpose::Session).as_bytes().to_vec();
        assert_eq!(hierarchy.generation(KeyPurpose::Session), 0);

        hierarchy.rotate_key(KeyPurpose::Session, &config);
        let new_key = hierarchy.key_for(KeyPurpose::Session).as_bytes().to_vec();

        assert_ne!(old_key, new_key);
        assert_eq!(hierarchy.generation(KeyPurpose::Session), 1);
    }

    #[test]
    fn test_key_schedule_rotation_by_count() {
        let mut schedule = KeySchedule::new(3600, 3); // rotate after 3 messages
        assert!(!schedule.needs_rotation());

        schedule.tick();
        schedule.tick();
        assert!(!schedule.needs_rotation());

        schedule.tick(); // 3rd message
        assert!(schedule.needs_rotation());

        schedule.reset();
        assert!(!schedule.needs_rotation());
    }
}
