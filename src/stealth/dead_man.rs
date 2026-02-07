// ╔══════════════════════════════════════════════════════════════════╗
// ║              GhostShell — Dead Man's Switch                      ║
// ║         Inactivity-triggered escalating security response        ║
// ╚══════════════════════════════════════════════════════════════════╝

use std::time::{Duration, Instant};

/// Escalating response stages
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DeadManStage {
    /// Normal operation
    Active,
    /// Warning — approaching timeout
    Warning,
    /// First response — lock session
    Lock,
    /// Second response — wipe scrollback
    WipeScrollback,
    /// Third response — wipe recordings
    WipeRecordings,
    /// Final response — exit application
    Exit,
}

/// Dead man's switch that triggers on inactivity
pub struct DeadManSwitch {
    /// Base timeout before first trigger
    timeout: Duration,
    /// Action on trigger
    action: String,
    /// Whether the switch is armed
    armed: bool,
    /// Last reset time
    last_reset: Instant,
    /// Current escalation stage
    stage: DeadManStage,
    /// Warning threshold (percentage of timeout)
    warning_threshold: f64,
}

impl DeadManSwitch {
    /// Create a new dead man's switch
    pub fn new(timeout_seconds: u64, action: &str) -> Self {
        let timeout = if timeout_seconds > 0 {
            Duration::from_secs(timeout_seconds)
        } else {
            Duration::from_secs(u64::MAX) // Effectively disabled
        };

        Self {
            timeout,
            action: action.to_string(),
            armed: timeout_seconds > 0,
            last_reset: Instant::now(),
            stage: DeadManStage::Active,
            warning_threshold: 0.8,
        }
    }

    /// Reset the switch (called on any user activity)
    pub fn reset(&mut self) {
        self.last_reset = Instant::now();
        self.stage = DeadManStage::Active;
    }

    /// Check if the switch has been triggered
    pub fn is_triggered(&self, last_activity: Instant) -> bool {
        if !self.armed {
            return false;
        }
        last_activity.elapsed() > self.timeout
    }

    /// Get the current stage based on elapsed time
    pub fn current_stage(&self, last_activity: Instant) -> DeadManStage {
        if !self.armed {
            return DeadManStage::Active;
        }

        let elapsed = last_activity.elapsed();
        let timeout_secs = self.timeout.as_secs_f64();

        if elapsed.as_secs_f64() < timeout_secs * self.warning_threshold {
            DeadManStage::Active
        } else if elapsed.as_secs_f64() < timeout_secs {
            DeadManStage::Warning
        } else if elapsed.as_secs_f64() < timeout_secs * 1.5 {
            DeadManStage::Lock
        } else if elapsed.as_secs_f64() < timeout_secs * 2.0 {
            DeadManStage::WipeScrollback
        } else if elapsed.as_secs_f64() < timeout_secs * 2.5 {
            DeadManStage::WipeRecordings
        } else {
            DeadManStage::Exit
        }
    }

    /// Get the configured action
    pub fn action(&self) -> &str {
        &self.action
    }

    /// Check if the switch is armed
    pub fn is_armed(&self) -> bool {
        self.armed
    }

    /// Arm or disarm the switch
    pub fn set_armed(&mut self, armed: bool) {
        self.armed = armed;
        if armed {
            self.reset();
        }
    }

    /// Get remaining time before trigger (in seconds)
    pub fn remaining_seconds(&self, last_activity: Instant) -> u64 {
        if !self.armed {
            return u64::MAX;
        }

        let elapsed = last_activity.elapsed();
        if elapsed > self.timeout {
            0
        } else {
            (self.timeout - elapsed).as_secs()
        }
    }

    /// Get a human-readable status string
    pub fn status_string(&self, last_activity: Instant) -> String {
        if !self.armed {
            return "DISABLED".to_string();
        }

        let remaining = self.remaining_seconds(last_activity);
        let stage = self.current_stage(last_activity);

        match stage {
            DeadManStage::Active => format!("ARMED ({}s)", remaining),
            DeadManStage::Warning => format!("⚠ WARNING ({}s)", remaining),
            DeadManStage::Lock => "🔒 LOCKING".to_string(),
            DeadManStage::WipeScrollback => "🗑 WIPING SCROLLBACK".to_string(),
            DeadManStage::WipeRecordings => "💀 WIPING RECORDINGS".to_string(),
            DeadManStage::Exit => "☠ EXITING".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread::sleep;

    #[test]
    fn test_dead_man_not_triggered_initially() {
        let dms = DeadManSwitch::new(60, "lock");
        let now = Instant::now();
        assert!(!dms.is_triggered(now));
        assert_eq!(dms.current_stage(now), DeadManStage::Active);
    }

    #[test]
    fn test_dead_man_disabled() {
        let dms = DeadManSwitch::new(0, "lock");
        assert!(!dms.is_armed());
        assert!(!dms.is_triggered(Instant::now()));
    }

    #[test]
    fn test_dead_man_remaining() {
        let dms = DeadManSwitch::new(60, "lock");
        let now = Instant::now();
        let remaining = dms.remaining_seconds(now);
        assert!(remaining <= 60);
        assert!(remaining >= 59);
    }

    #[test]
    fn test_dead_man_status_string() {
        let dms = DeadManSwitch::new(60, "lock");
        let status = dms.status_string(Instant::now());
        assert!(status.contains("ARMED"));
    }

    #[test]
    fn test_dead_man_reset() {
        let mut dms = DeadManSwitch::new(60, "lock");
        let old_time = Instant::now() - Duration::from_secs(30);
        dms.reset();
        // After reset, remaining should be close to full timeout
        let remaining = dms.remaining_seconds(Instant::now());
        assert!(remaining >= 59);
    }
}
