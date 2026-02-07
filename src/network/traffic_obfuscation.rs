// ╔══════════════════════════════════════════════════════════════════╗
// ║              GhostShell — Traffic Obfuscation                    ║
// ║         Make encrypted traffic look like normal HTTPS            ║
// ╚══════════════════════════════════════════════════════════════════╝

use rand::RngCore;

/// Obfuscation mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObfuscationMode {
    /// No obfuscation
    None,
    /// Wrap in TLS-like headers
    FakeHttps,
    /// Add random padding to messages
    Padded,
    /// Both TLS wrapping and padding
    Full,
}

/// Traffic obfuscator
pub struct TrafficObfuscator {
    mode: ObfuscationMode,
    /// Fake SNI hostname for TLS-like wrapping
    fake_sni: String,
    /// Padding alignment (in bytes)
    padding_alignment: usize,
}

impl TrafficObfuscator {
    pub fn new(mode: ObfuscationMode) -> Self {
        Self {
            mode,
            fake_sni: "cdn.cloudflare.com".to_string(),
            padding_alignment: 256,
        }
    }

    /// Set the fake SNI hostname
    pub fn set_fake_sni(&mut self, sni: &str) {
        self.fake_sni = sni.to_string();
    }

    /// Wrap outgoing data with obfuscation
    pub fn wrap(&self, data: &[u8]) -> Vec<u8> {
        match self.mode {
            ObfuscationMode::None => data.to_vec(),
            ObfuscationMode::FakeHttps => self.wrap_tls(data),
            ObfuscationMode::Padded => self.wrap_padded(data),
            ObfuscationMode::Full => {
                let padded = self.wrap_padded(data);
                self.wrap_tls(&padded)
            }
        }
    }

    /// Unwrap incoming obfuscated data
    pub fn unwrap(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        match self.mode {
            ObfuscationMode::None => Ok(data.to_vec()),
            ObfuscationMode::FakeHttps => self.unwrap_tls(data),
            ObfuscationMode::Padded => self.unwrap_padded(data),
            ObfuscationMode::Full => {
                let tls_unwrapped = self.unwrap_tls(data)?;
                self.unwrap_padded(&tls_unwrapped)
            }
        }
    }

    /// Wrap data to look like a TLS Application Data record
    fn wrap_tls(&self, data: &[u8]) -> Vec<u8> {
        let mut frame = Vec::new();

        // TLS 1.2 Application Data record header
        frame.push(0x17); // Content type: Application Data
        frame.push(0x03); // Version: TLS 1.2
        frame.push(0x03);
        // SECURITY: Reject data larger than u16::MAX to prevent silent
        // truncation that would corrupt/lose payload bytes.
        let len: u16 = data.len().try_into()
            .expect("TLS frame payload exceeds 65535 bytes — split before wrapping");
        frame.push((len >> 8) as u8);
        frame.push((len & 0xFF) as u8);
        frame.extend_from_slice(data);

        frame
    }

    /// Unwrap TLS-like framing
    fn unwrap_tls(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        if data.len() < 5 {
            return Err("Frame too short for TLS header".to_string());
        }

        // Verify TLS header
        if data[0] != 0x17 || data[1] != 0x03 || data[2] != 0x03 {
            return Err("Invalid TLS header".to_string());
        }

        let len = ((data[3] as usize) << 8) | (data[4] as usize);
        if data.len() < 5 + len {
            return Err("Truncated TLS frame".to_string());
        }

        Ok(data[5..5 + len].to_vec())
    }

    /// Add random padding to defeat traffic analysis
    fn wrap_padded(&self, data: &[u8]) -> Vec<u8> {
        let data_len = data.len();
        let padded_len = ((data_len / self.padding_alignment) + 1) * self.padding_alignment;
        let padding_len = padded_len - data_len;

        let mut frame = Vec::with_capacity(4 + padded_len);

        // Store original data length
        frame.extend_from_slice(&(data_len as u32).to_le_bytes());
        frame.extend_from_slice(data);

        // Add random padding
        let mut padding = vec![0u8; padding_len];
        rand::thread_rng().fill_bytes(&mut padding);
        frame.extend_from_slice(&padding);

        frame
    }

    /// Remove padding
    fn unwrap_padded(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        if data.len() < 4 {
            return Err("Frame too short for padding header".to_string());
        }

        let original_len = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
        if data.len() < 4 + original_len {
            return Err("Truncated padded frame".to_string());
        }

        Ok(data[4..4 + original_len].to_vec())
    }
}

impl Default for TrafficObfuscator {
    fn default() -> Self {
        Self::new(ObfuscationMode::None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_no_obfuscation() {
        let obf = TrafficObfuscator::new(ObfuscationMode::None);
        let data = b"hello world";
        let wrapped = obf.wrap(data);
        let unwrapped = obf.unwrap(&wrapped).unwrap();
        assert_eq!(&unwrapped, data);
    }

    #[test]
    fn test_tls_wrapping() {
        let obf = TrafficObfuscator::new(ObfuscationMode::FakeHttps);
        let data = b"encrypted data here";
        let wrapped = obf.wrap(data);

        // Should have TLS header
        assert_eq!(wrapped[0], 0x17);
        assert_eq!(wrapped[1], 0x03);
        assert_eq!(wrapped[2], 0x03);

        let unwrapped = obf.unwrap(&wrapped).unwrap();
        assert_eq!(&unwrapped, data);
    }

    #[test]
    fn test_padding() {
        let obf = TrafficObfuscator::new(ObfuscationMode::Padded);
        let data = b"short";
        let wrapped = obf.wrap(data);

        // Should be aligned to padding_alignment
        assert!(wrapped.len() >= 256 + 4);

        let unwrapped = obf.unwrap(&wrapped).unwrap();
        assert_eq!(&unwrapped, data);
    }

    #[test]
    fn test_full_obfuscation() {
        let obf = TrafficObfuscator::new(ObfuscationMode::Full);
        let data = b"top secret message";
        let wrapped = obf.wrap(data);
        let unwrapped = obf.unwrap(&wrapped).unwrap();
        assert_eq!(&unwrapped, data);
    }
}
