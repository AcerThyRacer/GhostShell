// ╔══════════════════════════════════════════════════════════════════╗
// ║              GhostShell — Cipher Engine                          ║
// ║         ChaCha20-Poly1305 AEAD encryption                       ║
// ╚══════════════════════════════════════════════════════════════════╝

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use rand;
use zeroize::Zeroize;

/// AEAD tag size (Poly1305)
pub const TAG_SIZE: usize = 16;

/// Maximum messages before nonce space is exhausted.
/// For a 96-bit nonce with 32-bit random prefix + 64-bit counter,
/// we cap at 2^32 - 1 to ensure safety margin.
pub const MAX_MESSAGES: u64 = (1u64 << 32) - 1;

/// Encryption context for a session
pub struct CipherContext {
    cipher: ChaCha20Poly1305,
    nonce_counter: u64,
    /// Random 4-byte prefix for domain separation across sessions
    nonce_prefix: [u8; 4],
}

impl CipherContext {
    /// Create a new cipher context from a 256-bit key
    pub fn new(key: &[u8]) -> Result<Self, CipherError> {
        if key.len() != 32 {
            return Err(CipherError::InvalidKeySize);
        }

        let cipher = ChaCha20Poly1305::new_from_slice(key)
            .map_err(|_| CipherError::InvalidKeySize)?;

        // SECURITY: Generate a random 4-byte nonce prefix so that even if the
        // same key is reused across sessions, nonce collisions are avoided.
        let mut nonce_prefix = [0u8; 4];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce_prefix);

        Ok(Self {
            cipher,
            nonce_counter: 0,
            nonce_prefix,
        })
    }

    /// Encrypt data with optional associated data (AAD).
    /// Returns `CipherError::NonceExhausted` if the nonce counter has
    /// exceeded `MAX_MESSAGES` — caller must `rekey()` before continuing.
    pub fn encrypt(&mut self, plaintext: &[u8], aad: Option<&[u8]>) -> Result<EncryptedPacket, CipherError> {
        let nonce_bytes = self.next_nonce()?;
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = if let Some(aad_data) = aad {
            // Use AAD for authenticated associated data
            use chacha20poly1305::aead::Payload;
            self.cipher
                .encrypt(nonce, Payload { msg: plaintext, aad: aad_data })
                .map_err(|_| CipherError::EncryptionFailed)?
        } else {
            self.cipher
                .encrypt(nonce, plaintext)
                .map_err(|_| CipherError::EncryptionFailed)?
        };

        Ok(EncryptedPacket {
            nonce: nonce_bytes,
            ciphertext,
        })
    }

    /// Decrypt an encrypted packet
    pub fn decrypt(&self, packet: &EncryptedPacket, aad: Option<&[u8]>) -> Result<Vec<u8>, CipherError> {
        let nonce = Nonce::from_slice(&packet.nonce);

        let plaintext = if let Some(aad_data) = aad {
            use chacha20poly1305::aead::Payload;
            self.cipher
                .decrypt(nonce, Payload { msg: &packet.ciphertext, aad: aad_data })
                .map_err(|_| CipherError::DecryptionFailed)?
        } else {
            self.cipher
                .decrypt(nonce, packet.ciphertext.as_ref())
                .map_err(|_| CipherError::DecryptionFailed)?
        };

        Ok(plaintext)
    }

    /// Generate the next nonce (random prefix + counter to avoid collisions).
    /// Returns error if the nonce counter exceeds `MAX_MESSAGES`.
    fn next_nonce(&mut self) -> Result<[u8; 12], CipherError> {
        if self.nonce_counter >= MAX_MESSAGES {
            return Err(CipherError::NonceExhausted);
        }
        self.nonce_counter += 1;
        let mut nonce = [0u8; 12];
        nonce[..4].copy_from_slice(&self.nonce_prefix);
        nonce[4..12].copy_from_slice(&self.nonce_counter.to_le_bytes());
        Ok(nonce)
    }

    /// Rekey the cipher with a new 256-bit key, resetting the nonce counter
    /// and generating a fresh random nonce prefix.
    /// Use this when approaching nonce exhaustion or for periodic key rotation.
    pub fn rekey(&mut self, new_key: &[u8]) -> Result<(), CipherError> {
        if new_key.len() != 32 {
            return Err(CipherError::InvalidKeySize);
        }
        self.cipher = ChaCha20Poly1305::new_from_slice(new_key)
            .map_err(|_| CipherError::InvalidKeySize)?;
        self.nonce_counter = 0;
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut self.nonce_prefix);
        Ok(())
    }

    /// Returns how many more messages can be encrypted before nonce exhaustion.
    pub fn remaining_capacity(&self) -> u64 {
        MAX_MESSAGES.saturating_sub(self.nonce_counter)
    }

    /// Returns the current nonce counter value (for diagnostics).
    pub fn messages_encrypted(&self) -> u64 {
        self.nonce_counter
    }
}

/// An encrypted packet containing nonce + ciphertext + tag
#[derive(Debug, Clone)]
pub struct EncryptedPacket {
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>, // includes the Poly1305 tag
}

impl EncryptedPacket {
    /// Serialize to bytes: [nonce(12)][ciphertext_len(4)][ciphertext]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(12 + 4 + self.ciphertext.len());
        bytes.extend_from_slice(&self.nonce);
        bytes.extend_from_slice(&(self.ciphertext.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&self.ciphertext);
        bytes
    }

    /// Deserialize from bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self, CipherError> {
        if data.len() < 16 {
            return Err(CipherError::InvalidPacket);
        }

        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&data[..12]);

        let ct_len = u32::from_le_bytes([data[12], data[13], data[14], data[15]]) as usize;
        if data.len() < 16 + ct_len {
            return Err(CipherError::InvalidPacket);
        }

        let ciphertext = data[16..16 + ct_len].to_vec();

        Ok(Self { nonce, ciphertext })
    }
}

/// Cipher errors
#[derive(Debug, Clone)]
pub enum CipherError {
    InvalidKeySize,
    EncryptionFailed,
    DecryptionFailed,
    InvalidPacket,
    /// Nonce counter has exceeded `MAX_MESSAGES` — must rekey before encrypting
    NonceExhausted,
}

impl std::fmt::Display for CipherError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidKeySize => write!(f, "Invalid key size (must be 32 bytes)"),
            Self::EncryptionFailed => write!(f, "Encryption failed"),
            Self::DecryptionFailed => write!(f, "Decryption failed (wrong key or tampered data)"),
            Self::InvalidPacket => write!(f, "Invalid encrypted packet format"),
            Self::NonceExhausted => write!(f, "Nonce space exhausted — rekey required"),
        }
    }
}

impl std::error::Error for CipherError {}

/// One-shot encrypt helper
pub fn encrypt_once(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CipherError> {
    let mut ctx = CipherContext::new(key)?;
    let packet = ctx.encrypt(plaintext, None)?;
    Ok(packet.to_bytes())
}

/// One-shot decrypt helper
pub fn decrypt_once(key: &[u8], encrypted: &[u8]) -> Result<Vec<u8>, CipherError> {
    let ctx = CipherContext::new(key)?;
    let packet = EncryptedPacket::from_bytes(encrypted)?;
    ctx.decrypt(&packet, None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::generate_master_key;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = generate_master_key();
        let mut ctx = CipherContext::new(&key).unwrap();

        let plaintext = b"Hello, GhostShell! This is a secret message.";
        let packet = ctx.encrypt(plaintext, None).unwrap();

        let decrypted = ctx.decrypt(&packet, None).unwrap();
        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_with_aad() {
        let key = generate_master_key();
        let mut ctx = CipherContext::new(&key).unwrap();

        let plaintext = b"authenticated data";
        let aad = b"metadata";
        let packet = ctx.encrypt(plaintext, Some(aad)).unwrap();

        let decrypted = ctx.decrypt(&packet, Some(aad)).unwrap();
        assert_eq!(&decrypted, plaintext);

        // Tampered AAD should fail
        let result = ctx.decrypt(&packet, Some(b"wrong metadata"));
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_key_fails() {
        let key1 = generate_master_key();
        let key2 = generate_master_key();

        let mut ctx1 = CipherContext::new(&key1).unwrap();
        let ctx2 = CipherContext::new(&key2).unwrap();

        let plaintext = b"secret";
        let packet = ctx1.encrypt(plaintext, None).unwrap();

        let result = ctx2.decrypt(&packet, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_packet_serialization() {
        let key = generate_master_key();
        let mut ctx = CipherContext::new(&key).unwrap();

        let plaintext = b"serialize me";
        let packet = ctx.encrypt(plaintext, None).unwrap();

        let bytes = packet.to_bytes();
        let restored = EncryptedPacket::from_bytes(&bytes).unwrap();

        assert_eq!(packet.nonce, restored.nonce);
        assert_eq!(packet.ciphertext, restored.ciphertext);

        let decrypted = ctx.decrypt(&restored, None).unwrap();
        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn test_one_shot_helpers() {
        let key = generate_master_key();
        let plaintext = b"one-shot test";

        let encrypted = encrypt_once(&key, plaintext).unwrap();
        let decrypted = decrypt_once(&key, &encrypted).unwrap();
        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn test_nonce_exhaustion() {
        let key = generate_master_key();
        let mut ctx = CipherContext::new(&key).unwrap();

        // Simulate being near the limit
        ctx.nonce_counter = MAX_MESSAGES - 1;
        assert_eq!(ctx.remaining_capacity(), 1);

        // This should succeed (last allowed message)
        let result = ctx.encrypt(b"last message", None);
        assert!(result.is_ok());
        assert_eq!(ctx.remaining_capacity(), 0);

        // This should fail — nonce exhausted
        let result = ctx.encrypt(b"too many", None);
        assert!(matches!(result, Err(CipherError::NonceExhausted)));
    }

    #[test]
    fn test_rekey_resets_counter() {
        let key1 = generate_master_key();
        let key2 = generate_master_key();
        let mut ctx = CipherContext::new(&key1).unwrap();

        // Exhaust the nonce space
        ctx.nonce_counter = MAX_MESSAGES;
        assert_eq!(ctx.remaining_capacity(), 0);

        // Rekey should reset
        ctx.rekey(&key2).unwrap();
        assert_eq!(ctx.messages_encrypted(), 0);
        assert_eq!(ctx.remaining_capacity(), MAX_MESSAGES);

        // Should be able to encrypt again
        let result = ctx.encrypt(b"fresh start", None);
        assert!(result.is_ok());
    }

    #[test]
    fn test_remaining_capacity() {
        let key = generate_master_key();
        let mut ctx = CipherContext::new(&key).unwrap();

        assert_eq!(ctx.remaining_capacity(), MAX_MESSAGES);
        assert_eq!(ctx.messages_encrypted(), 0);

        ctx.encrypt(b"msg1", None).unwrap();
        assert_eq!(ctx.messages_encrypted(), 1);
        assert_eq!(ctx.remaining_capacity(), MAX_MESSAGES - 1);
    }
}
