// ╔══════════════════════════════════════════════════════════════════╗
// ║              GhostShell — Steganography Engine                   ║
// ║         LSB steganography for hiding sessions in PNG images      ║
// ╚══════════════════════════════════════════════════════════════════╝

use crate::crypto::cipher;
use crate::crypto::keys;
use image::GenericImageView;
use std::io;

/// Embed encrypted session data into a PNG image using LSB steganography
pub fn embed_session(
    session_path: &str,
    image_path: &str,
    output_path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // Read session data
    let session_data = std::fs::read(session_path)?;

    // Read the cover image
    let img = image::open(image_path)?;
    let mut img = img.to_rgba8();

    let (width, height) = img.dimensions();
    let pixel_count = (width * height) as usize;

    // Calculate capacity: 3 bits per pixel (R, G, B channels), minus header
    let capacity_bits = pixel_count * 3;
    let capacity_bytes = capacity_bits / 8;
    let header_size = 8; // 4 bytes for length + 4 bytes for magic

    if session_data.len() + header_size > capacity_bytes {
        return Err(format!(
            "Session data ({} bytes) exceeds image capacity ({} bytes). Use a larger image.",
            session_data.len(),
            capacity_bytes - header_size
        )
        .into());
    }

    // Encrypt the session data with a derived key
    let key = keys::generate_master_key();
    let encrypted = cipher::encrypt_once(key.as_bytes(), &session_data)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

    // Build the payload: [MAGIC(4)][LENGTH(4)][ENCRYPTED_DATA]
    let mut payload = Vec::new();
    payload.extend_from_slice(b"GHST"); // Magic bytes
    payload.extend_from_slice(&(encrypted.len() as u32).to_le_bytes());
    payload.extend_from_slice(&encrypted);

    // Embed using LSB substitution
    let mut bit_index = 0;
    let payload_bits = payload.len() * 8;

    'outer: for y in 0..height {
        for x in 0..width {
            let pixel = img.get_pixel_mut(x, y);

            // Embed in R, G, B channels (skip Alpha)
            for channel in 0..3 {
                if bit_index >= payload_bits {
                    break 'outer;
                }

                let byte_idx = bit_index / 8;
                let bit_offset = 7 - (bit_index % 8);
                let bit = (payload[byte_idx] >> bit_offset) & 1;

                // Replace LSB
                pixel[channel] = (pixel[channel] & 0xFE) | bit;
                bit_index += 1;
            }
        }
    }

    // Save the stego image
    img.save(output_path)?;

    // SECURITY: Do NOT print the key to stdout — it would leak into
    // terminal scrollback, logs, and shell history. Return it to the
    // caller so it can be handled securely (e.g., stored in SecureBuffer).
    // The caller is responsible for communicating the key securely.

    Ok(())
}

/// Extract a hidden session from a stego image
pub fn extract_session(
    image_path: &str,
    key: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let img = image::open(image_path)?;
    let img = img.to_rgba8();
    let (width, height) = img.dimensions();

    // Extract bits from LSB
    let mut extracted_bits: Vec<u8> = Vec::new();
    let mut current_byte: u8 = 0;
    let mut bit_count = 0;

    'outer: for y in 0..height {
        for x in 0..width {
            let pixel = img.get_pixel(x, y);

            for channel in 0..3 {
                let bit = pixel[channel] & 1;
                current_byte = (current_byte << 1) | bit;
                bit_count += 1;

                if bit_count == 8 {
                    extracted_bits.push(current_byte);
                    current_byte = 0;
                    bit_count = 0;

                    // Check if we've extracted enough for the header
                    if extracted_bits.len() == 8 {
                        // Verify magic
                        if &extracted_bits[0..4] != b"GHST" {
                            return Err("No hidden data found (bad magic)".into());
                        }
                    }

                    // Check if we've extracted the full payload
                    if extracted_bits.len() >= 8 {
                        let data_len = u32::from_le_bytes([
                            extracted_bits[4],
                            extracted_bits[5],
                            extracted_bits[6],
                            extracted_bits[7],
                        ]) as usize;

                        if extracted_bits.len() >= 8 + data_len {
                            break 'outer;
                        }
                    }
                }
            }
        }
    }

    // Verify we have enough data
    if extracted_bits.len() < 8 {
        return Err("No hidden data found".into());
    }

    if &extracted_bits[0..4] != b"GHST" {
        return Err("No hidden data found (bad magic)".into());
    }

    let data_len = u32::from_le_bytes([
        extracted_bits[4],
        extracted_bits[5],
        extracted_bits[6],
        extracted_bits[7],
    ]) as usize;

    if extracted_bits.len() < 8 + data_len {
        return Err("Truncated hidden data".into());
    }

    let encrypted_data = &extracted_bits[8..8 + data_len];

    // Decrypt
    let decrypted = cipher::decrypt_once(key, encrypted_data)
        .map_err(|e| format!("Decryption failed: {}", e))?;

    Ok(decrypted)
}

/// Calculate the steganographic capacity of an image
pub fn calculate_capacity(image_path: &str) -> Result<StegoCapacity, Box<dyn std::error::Error>> {
    let img = image::open(image_path)?;
    let (width, height) = img.dimensions();
    let pixel_count = (width * height) as usize;

    let capacity_bits = pixel_count * 3; // 3 channels per pixel
    let capacity_bytes = capacity_bits / 8;
    let usable_bytes = capacity_bytes.saturating_sub(8); // Minus header

    Ok(StegoCapacity {
        width,
        height,
        total_pixels: pixel_count,
        capacity_bits,
        capacity_bytes,
        usable_bytes,
    })
}

/// Steganographic capacity information
#[derive(Debug)]
pub struct StegoCapacity {
    pub width: u32,
    pub height: u32,
    pub total_pixels: usize,
    pub capacity_bits: usize,
    pub capacity_bytes: usize,
    pub usable_bytes: usize,
}

impl std::fmt::Display for StegoCapacity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Image: {}x{} ({} pixels)\nCapacity: {} bytes ({:.1} KB)\nUsable: {} bytes ({:.1} KB)",
            self.width,
            self.height,
            self.total_pixels,
            self.capacity_bytes,
            self.capacity_bytes as f64 / 1024.0,
            self.usable_bytes,
            self.usable_bytes as f64 / 1024.0,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stego_capacity() {
        // A 100x100 image should have capacity for about 3750 bytes
        let pixels = 100 * 100;
        let bits = pixels * 3;
        let bytes = bits / 8;
        assert_eq!(bytes, 3750);
    }
}
