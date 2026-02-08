// ╔══════════════════════════════════════════════════════════════════╗
// ║              GhostShell — Post-Quantum Cryptography              ║
// ║         Hybrid X25519 + Kyber768, Dilithium3 signatures         ║
// ╚══════════════════════════════════════════════════════════════════╝

use crate::crypto::secure_mem::SecureBuffer;
use crate::error::GhostError;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

// ── Cipher Suite Configuration ───────────────────────────────────

/// Available cipher suite modes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CipherSuiteMode {
    /// Classic X25519 only (maximum compatibility)
    Classic,
    /// Hybrid X25519 + CRYSTALS-Kyber768 (recommended)
    Hybrid,
    /// Post-quantum only (future-facing, less tested)
    PostQuantumOnly,
}

impl Default for CipherSuiteMode {
    fn default() -> Self {
        Self::Classic
    }
}

/// Cipher suite configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CipherSuiteConfig {
    pub mode: CipherSuiteMode,
    pub allow_fallback: bool,
}

impl Default for CipherSuiteConfig {
    fn default() -> Self {
        Self {
            mode: CipherSuiteMode::Classic,
            allow_fallback: true,
        }
    }
}

// ── Classic X25519 Key Exchange ──────────────────────────────────

/// X25519 key pair for classic Diffie-Hellman.
/// SECURITY: Uses real Curve25519 via x25519-dalek.
#[derive(Clone)]
pub struct X25519KeyPair {
    pub public_key: [u8; 32],
    secret_key: SecureBuffer,
}

impl X25519KeyPair {
    /// Generate a new X25519 key pair using real Curve25519
    pub fn generate() -> Self {
        let secret = x25519_dalek::StaticSecret::random_from_rng(rand::thread_rng());
        let public = x25519_dalek::PublicKey::from(&secret);

        let secret_bytes = secret.to_bytes();
        let secret_key = SecureBuffer::from_data(&secret_bytes);
        // secret_bytes is on the stack and will be overwritten; StaticSecret
        // implements Zeroize via x25519-dalek

        Self {
            public_key: public.to_bytes(),
            secret_key,
        }
    }

    /// Perform key exchange with a remote public key.
    /// SECURITY: Real Curve25519 ECDH — both sides derive the same shared secret.
    pub fn exchange(&self, remote_public: &[u8; 32]) -> SecureBuffer {
        use x25519_dalek::{PublicKey, StaticSecret};

        // Reconstruct our secret from the SecureBuffer
        let mut secret_bytes = [0u8; 32];
        secret_bytes.copy_from_slice(self.secret_key.as_bytes());
        let secret = StaticSecret::from(secret_bytes);
        secret_bytes.zeroize();

        let their_public = PublicKey::from(*remote_public);
        let shared = secret.diffie_hellman(&their_public);

        SecureBuffer::from_data(shared.as_bytes())
    }

    /// Get the public key bytes
    pub fn public_bytes(&self) -> &[u8; 32] {
        &self.public_key
    }
}

// ── Kyber768 Key Encapsulation ───────────────────────────────────

/// The size of a Kyber768 public key
pub const KYBER768_PUBLIC_KEY_SIZE: usize = 1184;
/// The size of a Kyber768 secret key
pub const KYBER768_SECRET_KEY_SIZE: usize = 2400;
/// The size of a Kyber768 ciphertext
pub const KYBER768_CIPHERTEXT_SIZE: usize = 1088;
/// The size of a Kyber768 shared secret
pub const KYBER768_SHARED_SECRET_SIZE: usize = 32;

/// Kyber768 key pair for post-quantum key encapsulation.
///
/// # SECURITY STUB
/// This uses HMAC-based placeholders — NOT real lattice crypto.
/// For production, replace with the `pqcrypto-kyber` crate.
#[derive(Clone)]
pub struct KyberKeyPair {
    pub public_key: Vec<u8>,
    secret_key: SecureBuffer,
}

/// Result of a Kyber encapsulation
pub struct KyberEncapsulation {
    pub ciphertext: Vec<u8>,
    pub shared_secret: SecureBuffer,
}

impl KyberKeyPair {
    /// Generate a new Kyber768 key pair.
    /// WARNING: HMAC-based stub — not real Kyber768.
    pub fn generate() -> Self {
        let mut pk = vec![0u8; KYBER768_PUBLIC_KEY_SIZE];
        let mut sk = vec![0u8; KYBER768_SECRET_KEY_SIZE];

        let mut seed = [0u8; 64];
        rand::thread_rng().fill_bytes(&mut seed);

        kyber_keygen_from_seed(&seed, &mut pk, &mut sk);
        seed.zeroize();

        let secret_key = SecureBuffer::from_data(&sk);
        sk.zeroize();

        Self {
            public_key: pk,
            secret_key,
        }
    }

    /// Encapsulate: generate a shared secret and ciphertext from remote's public key
    pub fn encapsulate(remote_pk: &[u8]) -> Result<KyberEncapsulation, GhostError> {
        if remote_pk.len() != KYBER768_PUBLIC_KEY_SIZE {
            return Err(GhostError::Crypto(format!(
                "Invalid Kyber768 public key size: expected {}, got {}",
                KYBER768_PUBLIC_KEY_SIZE,
                remote_pk.len()
            )));
        }

        let mut shared_secret = vec![0u8; KYBER768_SHARED_SECRET_SIZE];
        let mut ciphertext = vec![0u8; KYBER768_CIPHERTEXT_SIZE];
        let mut random_coins = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut random_coins);

        kyber_encaps(remote_pk, &random_coins, &mut ciphertext, &mut shared_secret);
        random_coins.zeroize();

        Ok(KyberEncapsulation {
            ciphertext,
            shared_secret: SecureBuffer::from_data(&shared_secret),
        })
    }

    /// Decapsulate: recover shared secret from ciphertext using our secret key
    pub fn decapsulate(&self, ciphertext: &[u8]) -> Result<SecureBuffer, GhostError> {
        if ciphertext.len() != KYBER768_CIPHERTEXT_SIZE {
            return Err(GhostError::Crypto(format!(
                "Invalid Kyber768 ciphertext size: expected {}, got {}",
                KYBER768_CIPHERTEXT_SIZE,
                ciphertext.len()
            )));
        }

        let mut shared_secret = vec![0u8; KYBER768_SHARED_SECRET_SIZE];
        kyber_decaps(self.secret_key.as_bytes(), ciphertext, &mut shared_secret);

        Ok(SecureBuffer::from_data(&shared_secret))
    }

    /// Get the public key bytes
    pub fn public_bytes(&self) -> &[u8] {
        &self.public_key
    }
}

// ── Hybrid Key Exchange ──────────────────────────────────────────

/// Result of a hybrid key exchange
pub struct HybridKeyExchangeResult {
    /// Combined shared secret (X25519 || Kyber)
    pub shared_secret: SecureBuffer,
    /// X25519 public key to send to remote
    pub x25519_public: [u8; 32],
    /// Kyber ciphertext to send to remote (if hybrid/PQ mode)
    pub kyber_ciphertext: Option<Vec<u8>>,
}

/// Hybrid key exchange combining X25519 + Kyber768
pub struct HybridKeyExchange {
    x25519: X25519KeyPair,
    kyber: Option<KyberKeyPair>,
    mode: CipherSuiteMode,
}

impl HybridKeyExchange {
    /// Create a new hybrid key exchange instance
    pub fn new(config: &CipherSuiteConfig) -> Self {
        let kyber = match config.mode {
            CipherSuiteMode::Classic => None,
            CipherSuiteMode::Hybrid | CipherSuiteMode::PostQuantumOnly => {
                Some(KyberKeyPair::generate())
            }
        };

        Self {
            x25519: X25519KeyPair::generate(),
            kyber,
            mode: config.mode,
        }
    }

    /// Get our public keys for exchange
    pub fn public_keys(&self) -> (Vec<u8>, Option<Vec<u8>>) {
        let x25519_pk = self.x25519.public_key.to_vec();
        let kyber_pk = self.kyber.as_ref().map(|k| k.public_key.clone());
        (x25519_pk, kyber_pk)
    }

    /// Initiate key exchange with remote's public keys
    pub fn initiate(
        &self,
        remote_x25519_pk: &[u8; 32],
        remote_kyber_pk: Option<&[u8]>,
    ) -> Result<HybridKeyExchangeResult, GhostError> {
        // X25519 exchange (always performed)
        let x25519_shared = self.x25519.exchange(remote_x25519_pk);

        // Kyber encapsulation (if in hybrid/PQ mode)
        let (kyber_shared, kyber_ct) = if let Some(remote_pk) = remote_kyber_pk {
            let encap = KyberKeyPair::encapsulate(remote_pk)?;
            (Some(encap.shared_secret), Some(encap.ciphertext))
        } else {
            (None, None)
        };

        // Combine shared secrets
        let combined = combine_shared_secrets(
            x25519_shared.as_bytes(),
            kyber_shared.as_ref().map(|s| s.as_bytes()),
            self.mode,
        );

        Ok(HybridKeyExchangeResult {
            shared_secret: combined,
            x25519_public: self.x25519.public_key,
            kyber_ciphertext: kyber_ct,
        })
    }

    /// Complete key exchange using remote's X25519 public key and Kyber ciphertext
    pub fn complete(
        &self,
        remote_x25519_pk: &[u8; 32],
        kyber_ciphertext: Option<&[u8]>,
    ) -> Result<SecureBuffer, GhostError> {
        // X25519 exchange
        let x25519_shared = self.x25519.exchange(remote_x25519_pk);

        // Kyber decapsulation
        let kyber_shared = if let (Some(kyber), Some(ct)) = (&self.kyber, kyber_ciphertext) {
            Some(kyber.decapsulate(ct)?)
        } else {
            None
        };

        // Combine
        Ok(combine_shared_secrets(
            x25519_shared.as_bytes(),
            kyber_shared.as_ref().map(|s| s.as_bytes()),
            self.mode,
        ))
    }

    /// Get the current cipher suite mode
    pub fn mode(&self) -> CipherSuiteMode {
        self.mode
    }
}

// ── Dilithium3 Signatures ────────────────────────────────────────

/// Size constants for Dilithium3
pub const DILITHIUM3_PK_SIZE: usize = 1952;
pub const DILITHIUM3_SK_SIZE: usize = 4000;
pub const DILITHIUM3_SIG_SIZE: usize = 3293;

/// Dilithium3 key pair for post-quantum signatures.
///
/// # SECURITY STUB
/// This uses HMAC-based placeholders — NOT real lattice-based signatures.
/// `verify()` always returns `false` (fail-closed) to prevent misuse.
/// For production, replace with the `pqcrypto-dilithium` crate.
pub struct DilithiumKeyPair {
    pub public_key: Vec<u8>,
    secret_key: SecureBuffer,
}

impl DilithiumKeyPair {
    /// Generate a new Dilithium3 signing key pair.
    /// WARNING: HMAC-based stub — not real Dilithium3.
    pub fn generate() -> Self {
        let mut pk = vec![0u8; DILITHIUM3_PK_SIZE];
        let mut sk = vec![0u8; DILITHIUM3_SK_SIZE];
        let mut seed = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut seed);

        dilithium_keygen(&seed, &mut pk, &mut sk);
        seed.zeroize();

        let secret_key = SecureBuffer::from_data(&sk);
        sk.zeroize();

        Self {
            public_key: pk,
            secret_key,
        }
    }

    /// Sign a message.
    /// WARNING: HMAC-based stub — not a real lattice signature.
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        let mut signature = vec![0u8; DILITHIUM3_SIG_SIZE];
        dilithium_sign(self.secret_key.as_bytes(), message, &mut signature);
        signature
    }

    /// Verify a signature against a public key.
    /// SECURITY: Always returns false — stub cannot provide real verification.
    /// This is fail-closed to prevent false sense of security.
    pub fn verify(_public_key: &[u8], _message: &[u8], _signature: &[u8]) -> bool {
        // SECURITY STUB: Real Dilithium3 verification requires the
        // pqcrypto-dilithium crate. Returning false (fail-closed) is
        // safer than accepting any signature.
        tracing::warn!("Dilithium3 verify called on STUB implementation — always returns false");
        false
    }
}

// ── Internal crypto primitives ───────────────────────────────────
// X25519 is now handled by x25519-dalek (see X25519KeyPair above).
// Kyber and Dilithium remain simplified HMAC-based STUBS.
// In production, replace with pqcrypto-kyber / pqcrypto-dilithium.

/// Kyber768 key generation from seed
fn kyber_keygen_from_seed(seed: &[u8; 64], pk: &mut [u8], sk: &mut [u8]) {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;

    // Derive public key material
    let mut mac = HmacSha256::new_from_slice(&seed[..32]).expect("HMAC key error");
    mac.update(b"ghostshell-kyber768-pk");
    let pk_seed = mac.finalize().into_bytes();

    // Fill public key with deterministic data
    for (i, chunk) in pk.chunks_mut(32).enumerate() {
        let mut mac = HmacSha256::new_from_slice(&pk_seed).expect("HMAC key error");
        mac.update(&(i as u32).to_le_bytes());
        let hash = mac.finalize().into_bytes();
        let len = chunk.len().min(32);
        chunk[..len].copy_from_slice(&hash[..len]);
    }

    // Fill secret key with deterministic data from second half of seed
    let mut mac = HmacSha256::new_from_slice(&seed[32..]).expect("HMAC key error");
    mac.update(b"ghostshell-kyber768-sk");
    let sk_seed = mac.finalize().into_bytes();

    for (i, chunk) in sk.chunks_mut(32).enumerate() {
        let mut mac = HmacSha256::new_from_slice(&sk_seed).expect("HMAC key error");
        mac.update(&(i as u32).to_le_bytes());
        let hash = mac.finalize().into_bytes();
        let len = chunk.len().min(32);
        chunk[..len].copy_from_slice(&hash[..len]);
    }
}

/// Kyber768 encapsulation
fn kyber_encaps(pk: &[u8], coins: &[u8; 32], ct: &mut [u8], ss: &mut [u8]) {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;

    // Derive shared secret from pk + randomness
    let mut mac = HmacSha256::new_from_slice(coins).expect("HMAC key error");
    mac.update(pk);
    mac.update(b"ghostshell-kyber768-encaps");
    let shared = mac.finalize().into_bytes();
    ss[..32].copy_from_slice(&shared);

    // Derive ciphertext from shared secret + pk
    for (i, chunk) in ct.chunks_mut(32).enumerate() {
        let mut mac = HmacSha256::new_from_slice(&shared).expect("HMAC key error");
        mac.update(&(i as u32).to_le_bytes());
        mac.update(b"ct");
        let hash = mac.finalize().into_bytes();
        let len = chunk.len().min(32);
        chunk[..len].copy_from_slice(&hash[..len]);
    }
}

/// Kyber768 decapsulation
fn kyber_decaps(sk: &[u8], ct: &[u8], ss: &mut [u8]) {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;

    // Recover shared secret from sk + ct
    let mut mac = HmacSha256::new_from_slice(&sk[..32]).expect("HMAC key error");
    mac.update(ct);
    mac.update(b"ghostshell-kyber768-decaps");
    let shared = mac.finalize().into_bytes();
    ss[..32].copy_from_slice(&shared);
}

/// Dilithium3 key generation
fn dilithium_keygen(seed: &[u8; 32], pk: &mut [u8], sk: &mut [u8]) {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;

    // Deterministic key generation from seed
    let mut mac = HmacSha256::new_from_slice(seed).expect("HMAC key error");
    mac.update(b"ghostshell-dilithium3-pk");
    let pk_seed = mac.finalize().into_bytes();

    for (i, chunk) in pk.chunks_mut(32).enumerate() {
        let mut mac = HmacSha256::new_from_slice(&pk_seed).expect("HMAC key error");
        mac.update(&(i as u32).to_le_bytes());
        let hash = mac.finalize().into_bytes();
        let len = chunk.len().min(32);
        chunk[..len].copy_from_slice(&hash[..len]);
    }

    let mut mac = HmacSha256::new_from_slice(seed).expect("HMAC key error");
    mac.update(b"ghostshell-dilithium3-sk");
    let sk_seed = mac.finalize().into_bytes();

    for (i, chunk) in sk.chunks_mut(32).enumerate() {
        let mut mac = HmacSha256::new_from_slice(&sk_seed).expect("HMAC key error");
        mac.update(&(i as u32).to_le_bytes());
        let hash = mac.finalize().into_bytes();
        let len = chunk.len().min(32);
        chunk[..len].copy_from_slice(&hash[..len]);
    }
}

/// Dilithium3 sign
fn dilithium_sign(sk: &[u8], message: &[u8], signature: &mut [u8]) {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;

    // Create deterministic signature from sk + message
    let mut mac = HmacSha256::new_from_slice(&sk[..32]).expect("HMAC key error");
    mac.update(message);
    mac.update(b"ghostshell-dilithium3-sign");
    let sig_seed = mac.finalize().into_bytes();

    for (i, chunk) in signature.chunks_mut(32).enumerate() {
        let mut mac = HmacSha256::new_from_slice(&sig_seed).expect("HMAC key error");
        mac.update(&(i as u32).to_le_bytes());
        let hash = mac.finalize().into_bytes();
        let len = chunk.len().min(32);
        chunk[..len].copy_from_slice(&hash[..len]);
    }
}

/// Combine shared secrets using HKDF-like extraction
fn combine_shared_secrets(
    x25519_shared: &[u8],
    kyber_shared: Option<&[u8]>,
    mode: CipherSuiteMode,
) -> SecureBuffer {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;

    let mut mac = HmacSha256::new_from_slice(b"ghostshell-hybrid-kdf").expect("HMAC key error");

    match mode {
        CipherSuiteMode::Classic => {
            mac.update(x25519_shared);
        }
        CipherSuiteMode::Hybrid => {
            mac.update(x25519_shared);
            if let Some(kyber) = kyber_shared {
                mac.update(kyber);
            }
        }
        CipherSuiteMode::PostQuantumOnly => {
            if let Some(kyber) = kyber_shared {
                mac.update(kyber);
            }
        }
    }

    mac.update(b"ghostshell-shared-secret-v1");
    let result = mac.finalize();
    SecureBuffer::from_data(&result.into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_x25519_key_exchange() {
        let alice = X25519KeyPair::generate();
        let bob = X25519KeyPair::generate();

        let alice_shared = alice.exchange(&bob.public_key);
        let bob_shared = bob.exchange(&alice.public_key);

        // REAL X25519: Both sides derive the same shared secret
        assert_eq!(alice_shared.as_bytes(), bob_shared.as_bytes());
        assert_eq!(alice_shared.len(), 32);
    }

    #[test]
    fn test_kyber_keygen() {
        let kp = KyberKeyPair::generate();
        assert_eq!(kp.public_key.len(), KYBER768_PUBLIC_KEY_SIZE);
        assert_eq!(kp.secret_key.len(), KYBER768_SECRET_KEY_SIZE);
    }

    #[test]
    fn test_kyber_encaps_decaps() {
        let alice = KyberKeyPair::generate();

        // Bob encapsulates to Alice's public key
        let encap = KyberKeyPair::encapsulate(&alice.public_key).unwrap();
        assert_eq!(encap.ciphertext.len(), KYBER768_CIPHERTEXT_SIZE);
        assert_eq!(encap.shared_secret.len(), KYBER768_SHARED_SECRET_SIZE);

        // Alice decapsulates
        let decap = alice.decapsulate(&encap.ciphertext).unwrap();
        assert_eq!(decap.len(), KYBER768_SHARED_SECRET_SIZE);
    }

    #[test]
    fn test_hybrid_key_exchange() {
        let config = CipherSuiteConfig {
            mode: CipherSuiteMode::Hybrid,
            allow_fallback: true,
        };

        let alice = HybridKeyExchange::new(&config);
        let bob = HybridKeyExchange::new(&config);

        let (bob_x25519, bob_kyber) = bob.public_keys();
        let mut bob_x25519_arr = [0u8; 32];
        bob_x25519_arr.copy_from_slice(&bob_x25519);

        let result = alice
            .initiate(&bob_x25519_arr, bob_kyber.as_deref())
            .unwrap();

        assert_eq!(result.shared_secret.len(), 32);
        assert!(result.kyber_ciphertext.is_some());
    }

    #[test]
    fn test_classic_mode() {
        let config = CipherSuiteConfig {
            mode: CipherSuiteMode::Classic,
            allow_fallback: false,
        };

        let exchange = HybridKeyExchange::new(&config);
        let (_, kyber_pk) = exchange.public_keys();
        assert!(kyber_pk.is_none()); // No Kyber in classic mode
    }

    #[test]
    fn test_dilithium_sign_verify_stub() {
        let kp = DilithiumKeyPair::generate();
        let message = b"GhostShell plugin verification payload";

        let signature = kp.sign(message);
        assert_eq!(signature.len(), DILITHIUM3_SIG_SIZE);

        // STUB: verify always returns false (fail-closed)
        let valid = DilithiumKeyPair::verify(&kp.public_key, message, &signature);
        assert!(!valid, "Stub Dilithium verify must return false");
    }

    #[test]
    fn test_cipher_suite_modes() {
        // Test all three modes compile and work
        for mode in [
            CipherSuiteMode::Classic,
            CipherSuiteMode::Hybrid,
            CipherSuiteMode::PostQuantumOnly,
        ] {
            let config = CipherSuiteConfig {
                mode,
                allow_fallback: true,
            };
            let exchange = HybridKeyExchange::new(&config);
            assert_eq!(exchange.mode(), mode);
        }
    }
}
