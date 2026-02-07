// ╔══════════════════════════════════════════════════════════════════╗
// ║         GhostShell — Biometric Authentication Engine             ║
// ║    Continuous auth, profile persistence, multi-user detection    ║
// ╚══════════════════════════════════════════════════════════════════╝

use crate::ids::biometrics::{BiometricProfile, BiometricSample};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Instant;

// ── Actions on biometric mismatch ────────────────────────────────

/// What happens when biometric confidence drops too low
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BiometricAction {
    /// Just log a warning
    Warn,
    /// Lock the session, require re-authentication
    Lock,
    /// Trigger full panic mode
    Panic,
}

impl Default for BiometricAction {
    fn default() -> Self {
        Self::Warn
    }
}

// ── Continuous Authentication ────────────────────────────────────

/// Authentication state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthState {
    /// Learning phase — not enough samples yet
    Training,
    /// Authenticated — confidence above threshold
    Authenticated,
    /// Suspicious — confidence dropping
    Suspicious,
    /// Locked — confidence below threshold
    Locked,
}

/// Continuous biometric authentication engine
pub struct BiometricAuthenticator {
    /// The authenticated user's profile
    profile: BiometricProfile,
    /// Confidence threshold (0.0 - 1.0)
    threshold: f64,
    /// Sliding window of recent samples
    sample_window: Vec<BiometricSample>,
    /// Max samples in sliding window
    window_size: usize,
    /// Current authentication state
    state: AuthState,
    /// Current confidence score
    confidence: f64,
    /// Action to take on mismatch
    action: BiometricAction,
    /// Number of consecutive low-confidence checks
    consecutive_failures: u32,
    /// Minimum samples before enforcement begins
    min_training_samples: usize,
    /// Total samples collected
    total_samples: usize,
}

impl BiometricAuthenticator {
    pub fn new(threshold: f64, action: BiometricAction) -> Self {
        Self {
            profile: BiometricProfile::new(),
            threshold: threshold.clamp(0.1, 1.0),
            sample_window: Vec::new(),
            window_size: 20,
            state: AuthState::Training,
            confidence: 1.0,
            action,
            consecutive_failures: 0,
            min_training_samples: 50,
            total_samples: 0,
        }
    }

    /// Submit a new biometric sample for continuous authentication
    pub fn submit_sample(&mut self, sample: BiometricSample) -> AuthState {
        self.total_samples += 1;

        // Always train the profile during initial phase
        if self.state == AuthState::Training {
            self.train_from_sample(&sample);
            if self.total_samples >= self.min_training_samples {
                self.state = AuthState::Authenticated;
            }
            return self.state;
        }

        // Check confidence against profile
        self.confidence = self.profile.match_confidence(&sample);

        // Update sliding window
        self.sample_window.push(sample);
        if self.sample_window.len() > self.window_size {
            self.sample_window.remove(0);
        }

        // Determine state based on confidence
        if self.confidence >= self.threshold {
            self.consecutive_failures = 0;
            self.state = AuthState::Authenticated;
        } else if self.confidence >= self.threshold * 0.7 {
            self.consecutive_failures += 1;
            self.state = AuthState::Suspicious;
        } else {
            self.consecutive_failures += 1;
            if self.consecutive_failures >= 3 {
                self.state = AuthState::Locked;
            } else {
                self.state = AuthState::Suspicious;
            }
        }

        self.state
    }

    /// Train the profile from a sample
    fn train_from_sample(&mut self, sample: &BiometricSample) {
        // Record flight times
        for (digraph, times) in &sample.flight_times {
            // Parse digraph key (e.g. "a->b") to extract from/to chars
            let chars: Vec<char> = digraph.chars().collect();
            if chars.len() >= 4 {
                let from = chars[0];
                let to = chars[chars.len() - 1];
                for &t in times {
                    self.profile.record_flight_time(from, to, t);
                }
            }
        }

        // Record typing speed
        if sample.typing_speed > 0.0 {
            self.profile.record_typing_speed(sample.typing_speed);
        }
    }

    /// Get current confidence score (0.0 - 1.0)
    pub fn confidence(&self) -> f64 {
        self.confidence
    }

    /// Get current authentication state
    pub fn state(&self) -> AuthState {
        self.state
    }

    /// Get the action that should be taken (if state is Locked)
    pub fn required_action(&self) -> Option<BiometricAction> {
        if self.state == AuthState::Locked {
            Some(self.action)
        } else {
            None
        }
    }

    /// Reset authentication state (e.g. after re-login)
    pub fn reset(&mut self) {
        self.state = AuthState::Authenticated;
        self.confidence = 1.0;
        self.consecutive_failures = 0;
        self.sample_window.clear();
    }

    /// Check if the engine is still in training mode
    pub fn is_training(&self) -> bool {
        self.state == AuthState::Training
    }

    /// Get total samples collected
    pub fn total_samples(&self) -> usize {
        self.total_samples
    }

    /// Get training progress as percentage (0.0 - 1.0)
    pub fn training_progress(&self) -> f64 {
        if self.total_samples >= self.min_training_samples {
            1.0
        } else {
            self.total_samples as f64 / self.min_training_samples as f64
        }
    }

    /// Get the threshold
    pub fn threshold(&self) -> f64 {
        self.threshold
    }
}

// ── Profile Store ────────────────────────────────────────────────

/// Manages multiple biometric profiles (multi-user support)
pub struct BiometricProfileStore {
    /// Profiles keyed by user identifier
    profiles: HashMap<String, StoredProfile>,
    /// Currently active user
    active_user: Option<String>,
}

/// A stored biometric profile with metadata
pub struct StoredProfile {
    /// User identifier
    pub user_id: String,
    /// The biometric profile
    pub profile: BiometricProfile,
    /// When the profile was created
    pub created_at: Instant,
    /// Number of training samples
    pub sample_count: usize,
    /// Whether the profile is fully trained
    pub trained: bool,
}

impl BiometricProfileStore {
    pub fn new() -> Self {
        Self {
            profiles: HashMap::new(),
            active_user: None,
        }
    }

    /// Register a new user profile
    pub fn register_user(&mut self, user_id: &str) {
        if !self.profiles.contains_key(user_id) {
            self.profiles.insert(
                user_id.to_string(),
                StoredProfile {
                    user_id: user_id.to_string(),
                    profile: BiometricProfile::new(),
                    created_at: Instant::now(),
                    sample_count: 0,
                    trained: false,
                },
            );
        }
    }

    /// Set the active user
    pub fn set_active_user(&mut self, user_id: &str) -> bool {
        if self.profiles.contains_key(user_id) {
            self.active_user = Some(user_id.to_string());
            true
        } else {
            false
        }
    }

    /// Get the active user's profile
    pub fn active_profile(&self) -> Option<&StoredProfile> {
        self.active_user
            .as_ref()
            .and_then(|uid| self.profiles.get(uid))
    }

    /// Get a mutable reference to the active user's profile
    pub fn active_profile_mut(&mut self) -> Option<&mut StoredProfile> {
        let uid = self.active_user.clone()?;
        self.profiles.get_mut(&uid)
    }

    /// Detect if typing patterns suggest a different user
    pub fn detect_user_switch(&self, sample: &BiometricSample) -> Option<String> {
        let mut best_match: Option<(String, f64)> = None;

        for (uid, stored) in &self.profiles {
            if !stored.trained {
                continue;
            }
            let conf = stored.profile.match_confidence(sample);
            if let Some((_, best_conf)) = &best_match {
                if conf > *best_conf {
                    best_match = Some((uid.clone(), conf));
                }
            } else {
                best_match = Some((uid.clone(), conf));
            }
        }

        // Return the best match if it's different from active user
        best_match.and_then(|(uid, conf)| {
            if conf > 0.5 && self.active_user.as_ref() != Some(&uid) {
                Some(uid)
            } else {
                None
            }
        })
    }

    /// Get the number of registered users
    pub fn user_count(&self) -> usize {
        self.profiles.len()
    }

    /// List all user IDs
    pub fn user_ids(&self) -> Vec<&str> {
        self.profiles.keys().map(|s| s.as_str()).collect()
    }
}

impl Default for BiometricProfileStore {
    fn default() -> Self {
        Self::new()
    }
}

// ── Typing DNA Features ──────────────────────────────────────────

/// Enhanced typing DNA features for improved biometric accuracy
pub struct TypingDna {
    /// Hold-time variance per key
    hold_variance: HashMap<char, RollingVariance>,
    /// Specific digraph timing signatures
    digraph_timings: HashMap<(char, char), RollingVariance>,
    /// N-graph patterns (trigraph, etc.)
    ngraph_timings: HashMap<String, RollingVariance>,
}

/// Simple rolling variance tracker
pub struct RollingVariance {
    values: Vec<f64>,
    max_samples: usize,
}

impl RollingVariance {
    pub fn new(max_samples: usize) -> Self {
        Self {
            values: Vec::new(),
            max_samples,
        }
    }

    pub fn push(&mut self, value: f64) {
        self.values.push(value);
        if self.values.len() > self.max_samples {
            self.values.remove(0);
        }
    }

    pub fn mean(&self) -> f64 {
        if self.values.is_empty() {
            return 0.0;
        }
        self.values.iter().sum::<f64>() / self.values.len() as f64
    }

    pub fn variance(&self) -> f64 {
        if self.values.len() < 2 {
            return 0.0;
        }
        let m = self.mean();
        self.values.iter().map(|v| (v - m).powi(2)).sum::<f64>() / (self.values.len() - 1) as f64
    }

    pub fn count(&self) -> usize {
        self.values.len()
    }
}

impl TypingDna {
    pub fn new() -> Self {
        Self {
            hold_variance: HashMap::new(),
            digraph_timings: HashMap::new(),
            ngraph_timings: HashMap::new(),
        }
    }

    /// Record a key hold time
    pub fn record_hold_time(&mut self, key: char, hold_ms: f64) {
        self.hold_variance
            .entry(key)
            .or_insert_with(|| RollingVariance::new(100))
            .push(hold_ms);
    }

    /// Record a digraph timing (two consecutive keys)
    pub fn record_digraph(&mut self, from: char, to: char, interval_ms: f64) {
        self.digraph_timings
            .entry((from, to))
            .or_insert_with(|| RollingVariance::new(50))
            .push(interval_ms);
    }

    /// Record a trigraph timing (three consecutive keys)
    pub fn record_trigraph(&mut self, keys: &str, interval_ms: f64) {
        if keys.len() == 3 {
            self.ngraph_timings
                .entry(keys.to_string())
                .or_insert_with(|| RollingVariance::new(30))
                .push(interval_ms);
        }
    }

    /// Get the hold-time consistency score for a key (lower variance = more consistent)
    pub fn hold_consistency(&self, key: char) -> Option<f64> {
        self.hold_variance.get(&key).map(|rv| {
            if rv.mean() < 0.001 {
                0.0
            } else {
                1.0 - (rv.variance().sqrt() / rv.mean()).min(1.0)
            }
        })
    }

    /// Get number of tracked digraphs
    pub fn digraph_count(&self) -> usize {
        self.digraph_timings.len()
    }

    /// Get number of tracked keys
    pub fn key_count(&self) -> usize {
        self.hold_variance.len()
    }
}

impl Default for TypingDna {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_sample(speed: f64) -> BiometricSample {
        BiometricSample {
            flight_times: HashMap::new(),
            typing_speed: speed,
        }
    }

    #[test]
    fn test_authenticator_training_phase() {
        let mut auth = BiometricAuthenticator::new(0.6, BiometricAction::Warn);
        assert!(auth.is_training());
        assert_eq!(auth.state(), AuthState::Training);

        // Submit samples during training
        for _ in 0..50 {
            auth.submit_sample(make_sample(80.0));
        }
        assert!(!auth.is_training());
        assert_eq!(auth.state(), AuthState::Authenticated);
    }

    #[test]
    fn test_authenticator_training_progress() {
        let mut auth = BiometricAuthenticator::new(0.6, BiometricAction::Lock);
        assert_eq!(auth.training_progress(), 0.0);

        for _ in 0..25 {
            auth.submit_sample(make_sample(80.0));
        }
        assert!((auth.training_progress() - 0.5).abs() < 0.01);

        for _ in 0..25 {
            auth.submit_sample(make_sample(80.0));
        }
        assert_eq!(auth.training_progress(), 1.0);
    }

    #[test]
    fn test_authenticator_reset() {
        let mut auth = BiometricAuthenticator::new(0.6, BiometricAction::Lock);
        // Skip training
        for _ in 0..50 {
            auth.submit_sample(make_sample(80.0));
        }
        auth.state = AuthState::Locked;
        auth.reset();
        assert_eq!(auth.state(), AuthState::Authenticated);
        assert_eq!(auth.confidence(), 1.0);
    }

    #[test]
    fn test_biometric_action_on_lock() {
        let mut auth = BiometricAuthenticator::new(0.6, BiometricAction::Panic);
        auth.state = AuthState::Locked;
        assert_eq!(auth.required_action(), Some(BiometricAction::Panic));

        auth.state = AuthState::Authenticated;
        assert_eq!(auth.required_action(), None);
    }

    #[test]
    fn test_profile_store_register_user() {
        let mut store = BiometricProfileStore::new();
        store.register_user("alice");
        store.register_user("bob");
        assert_eq!(store.user_count(), 2);
        assert!(store.user_ids().contains(&"alice"));
    }

    #[test]
    fn test_profile_store_active_user() {
        let mut store = BiometricProfileStore::new();
        store.register_user("alice");
        assert!(store.set_active_user("alice"));
        assert!(store.active_profile().is_some());
        assert!(!store.set_active_user("unknown"));
    }

    #[test]
    fn test_typing_dna_hold_time() {
        let mut dna = TypingDna::new();
        dna.record_hold_time('a', 50.0);
        dna.record_hold_time('a', 52.0);
        dna.record_hold_time('a', 48.0);
        assert!(dna.hold_consistency('a').unwrap() > 0.8);
        assert_eq!(dna.key_count(), 1);
    }

    #[test]
    fn test_typing_dna_digraph() {
        let mut dna = TypingDna::new();
        dna.record_digraph('t', 'h', 120.0);
        dna.record_digraph('t', 'h', 115.0);
        assert_eq!(dna.digraph_count(), 1);
    }

    #[test]
    fn test_rolling_variance() {
        let mut rv = RollingVariance::new(10);
        rv.push(10.0);
        rv.push(10.0);
        rv.push(10.0);
        assert_eq!(rv.mean(), 10.0);
        assert!(rv.variance() < 0.001); // Perfect consistency
        assert_eq!(rv.count(), 3);
    }
}
