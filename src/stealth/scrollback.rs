// ╔══════════════════════════════════════════════════════════════════╗
// ║              GhostShell — Scrollback Wiper                       ║
// ║         Secure ring buffer with auto-wipe on rotation            ║
// ╚══════════════════════════════════════════════════════════════════╝

use crate::crypto::secure_mem;
use zeroize::Zeroize;

/// A secure scrollback buffer that auto-wipes rotated lines
pub struct SecureScrollback {
    /// Ring buffer of lines
    lines: Vec<ScrollbackLine>,
    /// Maximum number of lines
    capacity: usize,
    /// Current write position in the ring
    write_pos: usize,
    /// Total lines written (may exceed capacity)
    total_written: usize,
    /// Number of wipe passes for secure deletion
    wipe_passes: u32,
    /// Whether auto-wipe is enabled on rotation
    auto_wipe: bool,
}

/// A single scrollback line with secure storage
struct ScrollbackLine {
    content: Vec<u8>,
    timestamp: u64,
}

impl ScrollbackLine {
    fn new() -> Self {
        Self {
            content: Vec::new(),
            timestamp: 0,
        }
    }

    /// Securely wipe this line
    fn wipe(&mut self) {
        self.content.zeroize();
        self.content.clear();
        self.timestamp = 0;
    }
}

impl SecureScrollback {
    /// Create a new secure scrollback buffer
    pub fn new(capacity: usize) -> Self {
        let mut lines = Vec::with_capacity(capacity);
        for _ in 0..capacity {
            lines.push(ScrollbackLine::new());
        }

        Self {
            lines,
            capacity,
            write_pos: 0,
            total_written: 0,
            wipe_passes: 3,
            auto_wipe: true,
        }
    }

    /// Set the number of wipe passes
    pub fn set_wipe_passes(&mut self, passes: u32) {
        self.wipe_passes = passes;
    }

    /// Push a new line into the scrollback
    pub fn push_line(&mut self, content: &[u8]) {
        // If we're overwriting an existing line, wipe it first
        if self.total_written >= self.capacity && self.auto_wipe {
            self.secure_wipe_line(self.write_pos);
        }

        self.lines[self.write_pos].content = content.to_vec();
        self.lines[self.write_pos].timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        self.write_pos = (self.write_pos + 1) % self.capacity;
        self.total_written += 1;
    }

    /// Get all visible lines in order
    pub fn visible_lines(&self) -> Vec<&[u8]> {
        let count = self.total_written.min(self.capacity);
        let mut result = Vec::with_capacity(count);

        if self.total_written <= self.capacity {
            // Buffer hasn't wrapped yet
            for i in 0..self.total_written {
                result.push(self.lines[i].content.as_slice());
            }
        } else {
            // Buffer has wrapped — start from write_pos
            for i in 0..self.capacity {
                let idx = (self.write_pos + i) % self.capacity;
                result.push(self.lines[idx].content.as_slice());
            }
        }

        result
    }

    /// Get the number of lines currently stored
    pub fn len(&self) -> usize {
        self.total_written.min(self.capacity)
    }

    /// Check if the buffer is empty
    pub fn is_empty(&self) -> bool {
        self.total_written == 0
    }

    /// Immediately wipe ALL scrollback data
    pub fn wipe_now(&mut self) {
        for line in &mut self.lines {
            if !line.content.is_empty() {
                // Multi-pass wipe
                secure_mem::secure_wipe(&mut line.content, self.wipe_passes);
                line.wipe();
            }
        }
        self.write_pos = 0;
        self.total_written = 0;
    }

    /// Wipe a specific line index
    fn secure_wipe_line(&mut self, idx: usize) {
        if idx < self.lines.len() && !self.lines[idx].content.is_empty() {
            secure_mem::secure_wipe(&mut self.lines[idx].content, self.wipe_passes);
            self.lines[idx].wipe();
        }
    }

    /// Wipe lines older than N seconds
    pub fn wipe_older_than(&mut self, max_age_secs: u64) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        for line in &mut self.lines {
            if line.timestamp > 0 && (now - line.timestamp) > max_age_secs {
                secure_mem::secure_wipe(&mut line.content, self.wipe_passes);
                line.wipe();
            }
        }
    }

    /// Search scrollback for a pattern (returns line indices)
    pub fn search(&self, pattern: &[u8]) -> Vec<usize> {
        let mut results = Vec::new();
        let lines = self.visible_lines();

        for (i, line) in lines.iter().enumerate() {
            if line
                .windows(pattern.len())
                .any(|window| window == pattern)
            {
                results.push(i);
            }
        }

        results
    }
}

impl Drop for SecureScrollback {
    fn drop(&mut self) {
        self.wipe_now();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_push_and_read() {
        let mut sb = SecureScrollback::new(5);
        sb.push_line(b"line 1");
        sb.push_line(b"line 2");
        sb.push_line(b"line 3");

        assert_eq!(sb.len(), 3);
        let lines = sb.visible_lines();
        assert_eq!(lines[0], b"line 1");
        assert_eq!(lines[2], b"line 3");
    }

    #[test]
    fn test_ring_buffer_wrap() {
        let mut sb = SecureScrollback::new(3);
        sb.push_line(b"a");
        sb.push_line(b"b");
        sb.push_line(b"c");
        sb.push_line(b"d"); // Overwrites "a"

        assert_eq!(sb.len(), 3);
        let lines = sb.visible_lines();
        assert_eq!(lines[0], b"b");
        assert_eq!(lines[1], b"c");
        assert_eq!(lines[2], b"d");
    }

    #[test]
    fn test_wipe_now() {
        let mut sb = SecureScrollback::new(10);
        sb.push_line(b"secret data");
        sb.push_line(b"more secrets");

        sb.wipe_now();
        assert_eq!(sb.len(), 0);
        assert!(sb.is_empty());
    }

    #[test]
    fn test_search() {
        let mut sb = SecureScrollback::new(10);
        sb.push_line(b"hello world");
        sb.push_line(b"foo bar");
        sb.push_line(b"hello again");

        let results = sb.search(b"hello");
        assert_eq!(results.len(), 2);
        assert_eq!(results[0], 0);
        assert_eq!(results[1], 2);
    }
}
