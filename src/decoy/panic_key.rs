// ╔══════════════════════════════════════════════════════════════════╗
// ║              GhostShell — Panic Key                              ║
// ║         Instant decoy switching with memory wipe                 ║
// ╚══════════════════════════════════════════════════════════════════╝

use std::time::Instant;

/// Panic key sequence detector
pub struct PanicKeyDetector {
    /// Key sequence required (e.g., 3 for triple-press)
    required_presses: u8,
    /// Current press count
    current_count: u8,
    /// Time window for the sequence (ms)
    time_window_ms: u64,
    /// When the sequence started
    sequence_start: Option<Instant>,
}

impl PanicKeyDetector {
    pub fn new(required_presses: u8, time_window_ms: u64) -> Self {
        Self {
            required_presses,
            current_count: 0,
            time_window_ms,
            sequence_start: None,
        }
    }

    /// Register a key press, returns true if panic triggered
    pub fn key_pressed(&mut self) -> bool {
        let now = Instant::now();

        // Check if we're within the time window
        if let Some(start) = self.sequence_start {
            if now.duration_since(start).as_millis() > self.time_window_ms as u128 {
                // Window expired, restart
                self.current_count = 0;
                self.sequence_start = None;
            }
        }

        if self.sequence_start.is_none() {
            self.sequence_start = Some(now);
        }

        self.current_count += 1;

        if self.current_count >= self.required_presses {
            self.reset();
            return true;
        }

        false
    }

    /// Reset the detector
    pub fn reset(&mut self) {
        self.current_count = 0;
        self.sequence_start = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_panic_detection() {
        let mut detector = PanicKeyDetector::new(3, 2000);
        assert!(!detector.key_pressed());
        assert!(!detector.key_pressed());
        assert!(detector.key_pressed()); // Third press triggers
    }

    #[test]
    fn test_reset() {
        let mut detector = PanicKeyDetector::new(3, 2000);
        detector.key_pressed();
        detector.key_pressed();
        detector.reset();
        assert!(!detector.key_pressed()); // Restarted, only 1 press
    }
}
