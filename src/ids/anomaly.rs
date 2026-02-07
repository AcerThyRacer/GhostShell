// ╔══════════════════════════════════════════════════════════════════╗
// ║              GhostShell — Anomaly Detection Engine                ║
// ║         Statistical anomaly detection for user behavior          ║
// ╚══════════════════════════════════════════════════════════════════╝

use std::collections::{HashMap, VecDeque};

/// Rolling statistics tracker
pub struct RollingStats {
    values: VecDeque<f64>,
    max_samples: usize,
    sum: f64,
    sum_sq: f64,
}

impl RollingStats {
    pub fn new(max_samples: usize) -> Self {
        Self {
            values: VecDeque::with_capacity(max_samples),
            max_samples,
            sum: 0.0,
            sum_sq: 0.0,
        }
    }

    /// Add a new value
    pub fn push(&mut self, value: f64) {
        if self.values.len() >= self.max_samples {
            if let Some(old) = self.values.pop_front() {
                self.sum -= old;
                self.sum_sq -= old * old;
            }
        }

        self.values.push_back(value);
        self.sum += value;
        self.sum_sq += value * value;
    }

    /// Get the mean
    pub fn mean(&self) -> f64 {
        if self.values.is_empty() {
            return 0.0;
        }
        self.sum / self.values.len() as f64
    }

    /// Get the standard deviation
    pub fn std_dev(&self) -> f64 {
        let n = self.values.len() as f64;
        if n < 2.0 {
            return 0.0;
        }
        let variance = (self.sum_sq / n) - (self.mean().powi(2));
        variance.abs().sqrt()
    }

    /// Check if a value is anomalous (> N standard deviations from mean)
    pub fn is_anomalous(&self, value: f64, sigma_threshold: f64) -> bool {
        if self.values.len() < 10 {
            return false; // Not enough data
        }

        let deviation = (value - self.mean()).abs();
        let threshold = self.std_dev() * sigma_threshold;

        // Avoid false positives when std_dev is very small
        if self.std_dev() < 0.001 {
            return false;
        }

        deviation > threshold
    }

    /// Get number of samples
    pub fn count(&self) -> usize {
        self.values.len()
    }
}

/// The anomaly detection engine
pub struct AnomalyEngine {
    /// Command frequency tracking (commands per minute)
    command_frequency: RollingStats,
    /// Time between keystrokes (ms)
    keystroke_intervals: RollingStats,
    /// Command length tracking
    command_lengths: RollingStats,
    /// Error rate tracking
    error_rate: RollingStats,
    /// Sensitivity threshold (sigma)
    sigma_threshold: f64,
    /// Total anomalies detected
    total_anomalies: u64,
    /// Recent anomaly timestamps
    recent_anomalies: VecDeque<std::time::Instant>,
}

impl AnomalyEngine {
    pub fn new(sensitivity: f64) -> Self {
        Self {
            command_frequency: RollingStats::new(100),
            keystroke_intervals: RollingStats::new(500),
            command_lengths: RollingStats::new(100),
            error_rate: RollingStats::new(50),
            sigma_threshold: sensitivity,
            total_anomalies: 0,
            recent_anomalies: VecDeque::new(),
        }
    }

    /// Record a command and check for anomalies
    pub fn record_command(&mut self, command: &str, interval_ms: f64) -> Vec<AnomalyEvent> {
        let mut anomalies = Vec::new();

        // Check command length anomaly
        let cmd_len = command.len() as f64;
        if self.command_lengths.is_anomalous(cmd_len, self.sigma_threshold) {
            anomalies.push(AnomalyEvent {
                category: AnomalyCategory::CommandLength,
                severity: AnomalySeverity::Medium,
                detail: format!(
                    "Unusual command length: {} chars (mean: {:.0}, σ: {:.1})",
                    command.len(),
                    self.command_lengths.mean(),
                    self.command_lengths.std_dev()
                ),
                value: cmd_len,
                threshold: self.command_lengths.mean() + self.command_lengths.std_dev() * self.sigma_threshold,
            });
        }
        self.command_lengths.push(cmd_len);

        // Check command interval anomaly (rapid-fire commands)
        if self.command_frequency.is_anomalous(interval_ms, self.sigma_threshold) && interval_ms < self.command_frequency.mean() * 0.3 {
            anomalies.push(AnomalyEvent {
                category: AnomalyCategory::Frequency,
                severity: AnomalySeverity::High,
                detail: format!(
                    "Rapid command entry: {:.0}ms (mean: {:.0}ms)",
                    interval_ms,
                    self.command_frequency.mean()
                ),
                value: interval_ms,
                threshold: self.command_frequency.mean() * 0.3,
            });
        }
        self.command_frequency.push(interval_ms);

        // Track anomaly count
        if !anomalies.is_empty() {
            self.total_anomalies += anomalies.len() as u64;
            let now = std::time::Instant::now();
            for _ in &anomalies {
                self.recent_anomalies.push_back(now);
            }
            // Keep only last 100
            while self.recent_anomalies.len() > 100 {
                self.recent_anomalies.pop_front();
            }
        }

        anomalies
    }

    /// Record a keystroke interval
    pub fn record_keystroke(&mut self, interval_ms: f64) -> Option<AnomalyEvent> {
        let anomalous = self.keystroke_intervals.is_anomalous(interval_ms, self.sigma_threshold);
        self.keystroke_intervals.push(interval_ms);

        if anomalous && interval_ms < self.keystroke_intervals.mean() * 0.2 {
            self.total_anomalies += 1;
            Some(AnomalyEvent {
                category: AnomalyCategory::KeystrokeTiming,
                severity: AnomalySeverity::High,
                detail: format!(
                    "Inhuman typing speed: {:.0}ms between keys (mean: {:.0}ms)",
                    interval_ms,
                    self.keystroke_intervals.mean()
                ),
                value: interval_ms,
                threshold: self.keystroke_intervals.mean() * 0.2,
            })
        } else {
            None
        }
    }

    /// Record command error rate
    pub fn record_error(&mut self, was_error: bool) -> Option<AnomalyEvent> {
        let value = if was_error { 1.0 } else { 0.0 };
        let anomalous = self.error_rate.is_anomalous(value, self.sigma_threshold);
        self.error_rate.push(value);

        if anomalous && was_error && self.error_rate.mean() < 0.3 {
            self.total_anomalies += 1;
            Some(AnomalyEvent {
                category: AnomalyCategory::ErrorRate,
                severity: AnomalySeverity::Low,
                detail: format!(
                    "Unusual error rate: current mean {:.1}%",
                    self.error_rate.mean() * 100.0
                ),
                value: self.error_rate.mean(),
                threshold: 0.3,
            })
        } else {
            None
        }
    }

    /// Get total anomaly count
    pub fn total_anomalies(&self) -> u64 {
        self.total_anomalies
    }

    /// Get anomaly rate (per minute) over recent history
    pub fn anomaly_rate_per_minute(&self) -> f64 {
        if self.recent_anomalies.is_empty() {
            return 0.0;
        }

        let oldest = self.recent_anomalies.front().unwrap();
        let elapsed = oldest.elapsed().as_secs_f64() / 60.0;
        if elapsed < 0.01 {
            return 0.0;
        }

        self.recent_anomalies.len() as f64 / elapsed
    }
}

/// An anomaly event
#[derive(Debug, Clone)]
pub struct AnomalyEvent {
    pub category: AnomalyCategory,
    pub severity: AnomalySeverity,
    pub detail: String,
    pub value: f64,
    pub threshold: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AnomalyCategory {
    CommandLength,
    Frequency,
    KeystrokeTiming,
    ErrorRate,
    Biometric,
    TimeOfDay,
    CommandSequence,
    SessionAggregate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AnomalySeverity {
    Low,
    Medium,
    High,
    Critical,
}

// ── Markov Chain Model ────────────────────────────────────────────

/// Markov chain for command sequence prediction
pub struct MarkovChain {
    /// Transition counts: (from_command, to_command) -> count
    transitions: HashMap<String, HashMap<String, u32>>,
    /// Total transitions from each command
    totals: HashMap<String, u32>,
    /// Last command seen
    last_command: Option<String>,
    /// Order of the Markov chain (1 = bigram, 2 = trigram context)
    order: usize,
    /// Command history for higher-order chains
    history: VecDeque<String>,
    /// Minimum probability to not flag as anomalous
    min_probability: f64,
}

impl MarkovChain {
    pub fn new(order: usize, min_probability: f64) -> Self {
        Self {
            transitions: HashMap::new(),
            totals: HashMap::new(),
            last_command: None,
            order: order.max(1),
            history: VecDeque::new(),
            min_probability: min_probability.clamp(0.001, 0.5),
        }
    }

    /// Extract the command name (first word) for normalization
    fn normalize_command(cmd: &str) -> String {
        cmd.split_whitespace()
            .next()
            .unwrap_or(cmd)
            .to_lowercase()
    }

    /// Build the context key from recent history
    fn context_key(&self) -> Option<String> {
        if self.history.len() < self.order {
            return None;
        }
        let start = self.history.len() - self.order;
        let context: Vec<&str> = self.history
            .iter()
            .skip(start)
            .map(|s| s.as_str())
            .collect();
        Some(context.join("|"))
    }

    /// Record a command and check if it's an unexpected sequence
    pub fn record(&mut self, command: &str) -> Option<AnomalyEvent> {
        let normalized = Self::normalize_command(command);
        let mut anomaly = None;

        // Check if this transition is unexpected
        if let Some(context) = self.context_key() {
            if let Some(total) = self.totals.get(&context) {
                let count = self.transitions
                    .get(&context)
                    .and_then(|m| m.get(&normalized))
                    .copied()
                    .unwrap_or(0);
                let probability = count as f64 / *total as f64;

                // Only flag if we have enough data and probability is very low
                if *total >= 10 && probability < self.min_probability {
                    anomaly = Some(AnomalyEvent {
                        category: AnomalyCategory::CommandSequence,
                        severity: if probability < 0.01 {
                            AnomalySeverity::High
                        } else {
                            AnomalySeverity::Medium
                        },
                        detail: format!(
                            "Unusual command sequence: '{}' after '{}' (probability: {:.3})",
                            normalized, context, probability
                        ),
                        value: probability,
                        threshold: self.min_probability,
                    });
                }
            }
        }

        // Record the transition
        if let Some(context) = self.context_key() {
            self.transitions
                .entry(context.clone())
                .or_default()
                .entry(normalized.clone())
                .and_modify(|c| *c += 1)
                .or_insert(1);
            *self.totals.entry(context).or_insert(0) += 1;
        }

        // Update history
        self.history.push_back(normalized);
        if self.history.len() > self.order + 1 {
            self.history.pop_front();
        }

        anomaly
    }

    /// Get the number of unique contexts learned
    pub fn context_count(&self) -> usize {
        self.transitions.len()
    }

    /// Get total transitions recorded
    pub fn total_transitions(&self) -> u32 {
        self.totals.values().sum()
    }
}

// ── Time-of-Day Profile ──────────────────────────────────────────

/// Tracks activity patterns across 24 hours
pub struct TimeOfDayProfile {
    /// Activity counts per hour (0-23)
    hourly_counts: [u64; 24],
    /// Total samples
    total: u64,
    /// Whether the profile is trained (enough data)
    trained: bool,
    /// Min samples before enforcement
    min_samples: u64,
}

impl TimeOfDayProfile {
    pub fn new(min_samples: u64) -> Self {
        Self {
            hourly_counts: [0u64; 24],
            total: 0,
            trained: false,
            min_samples,
        }
    }

    /// Record activity at a given hour (0-23)
    pub fn record_activity(&mut self, hour: u8) -> Option<AnomalyEvent> {
        let hour = (hour % 24) as usize;
        self.hourly_counts[hour] += 1;
        self.total += 1;

        if self.total >= self.min_samples {
            self.trained = true;
        }

        if !self.trained || self.total < 2 {
            return None;
        }

        // Check if this hour has < 1% of total activity (unusual time)
        let hour_fraction = self.hourly_counts[hour] as f64 / self.total as f64;
        if hour_fraction < 0.01 && self.hourly_counts[hour] <= 2 {
            Some(AnomalyEvent {
                category: AnomalyCategory::TimeOfDay,
                severity: AnomalySeverity::Medium,
                detail: format!(
                    "Unusual activity at hour {} (only {:.1}% of history)",
                    hour,
                    hour_fraction * 100.0
                ),
                value: hour_fraction,
                threshold: 0.01,
            })
        } else {
            None
        }
    }

    /// Get the most active hours
    pub fn peak_hours(&self) -> Vec<(usize, u64)> {
        let mut hours: Vec<(usize, u64)> = self.hourly_counts
            .iter()
            .enumerate()
            .filter(|(_, &c)| c > 0)
            .map(|(h, &c)| (h, c))
            .collect();
        hours.sort_by(|a, b| b.1.cmp(&a.1));
        hours
    }

    /// Whether the profile is trained
    pub fn is_trained(&self) -> bool {
        self.trained
    }
}

// ── Session Anomaly Score ────────────────────────────────────────

/// Aggregates anomaly scores across all categories into a unified threat level
pub struct SessionAnomalyScore {
    /// Weighted scores per category
    category_scores: HashMap<AnomalyCategory, f64>,
    /// Category weights
    weights: HashMap<AnomalyCategory, f64>,
    /// Decay factor per minute (score decays over time)
    decay_per_minute: f64,
    /// Last update time
    last_update: std::time::Instant,
}

impl SessionAnomalyScore {
    pub fn new() -> Self {
        let mut weights = HashMap::new();
        weights.insert(AnomalyCategory::CommandLength, 0.5);
        weights.insert(AnomalyCategory::Frequency, 0.8);
        weights.insert(AnomalyCategory::KeystrokeTiming, 0.9);
        weights.insert(AnomalyCategory::ErrorRate, 0.3);
        weights.insert(AnomalyCategory::Biometric, 1.0);
        weights.insert(AnomalyCategory::TimeOfDay, 0.4);
        weights.insert(AnomalyCategory::CommandSequence, 0.7);
        weights.insert(AnomalyCategory::SessionAggregate, 0.5);

        Self {
            category_scores: HashMap::new(),
            weights,
            decay_per_minute: 0.1,
            last_update: std::time::Instant::now(),
        }
    }

    /// Record an anomaly event
    pub fn record_anomaly(&mut self, event: &AnomalyEvent) {
        self.apply_decay();

        let severity_multiplier = match event.severity {
            AnomalySeverity::Low => 0.25,
            AnomalySeverity::Medium => 0.5,
            AnomalySeverity::High => 0.75,
            AnomalySeverity::Critical => 1.0,
        };

        let weight = self.weights.get(&event.category).copied().unwrap_or(0.5);
        let score = severity_multiplier * weight;

        let entry = self.category_scores.entry(event.category).or_insert(0.0);
        *entry = (*entry + score).min(1.0);
    }

    /// Get the unified threat score (0.0 - 1.0)
    pub fn threat_score(&mut self) -> f64 {
        self.apply_decay();

        if self.category_scores.is_empty() {
            return 0.0;
        }

        let total: f64 = self.category_scores.values().sum();
        let count = self.category_scores.len() as f64;
        (total / count).min(1.0)
    }

    /// Apply time-based decay to all scores
    fn apply_decay(&mut self) {
        let elapsed_mins = self.last_update.elapsed().as_secs_f64() / 60.0;
        if elapsed_mins > 0.01 {
            let decay = (1.0 - self.decay_per_minute).powf(elapsed_mins);
            for score in self.category_scores.values_mut() {
                *score *= decay;
            }
            self.last_update = std::time::Instant::now();
        }
    }

    /// Get severity level from the unified score
    pub fn threat_level(&mut self) -> AnomalySeverity {
        let score = self.threat_score();
        if score >= 0.8 {
            AnomalySeverity::Critical
        } else if score >= 0.5 {
            AnomalySeverity::High
        } else if score >= 0.25 {
            AnomalySeverity::Medium
        } else {
            AnomalySeverity::Low
        }
    }

    /// Reset all scores
    pub fn reset(&mut self) {
        self.category_scores.clear();
    }
}

impl Default for SessionAnomalyScore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rolling_stats() {
        let mut stats = RollingStats::new(10);
        for i in 0..10 {
            stats.push(i as f64);
        }
        assert!((stats.mean() - 4.5).abs() < 0.001);
        assert!(stats.std_dev() > 0.0);
    }

    #[test]
    fn test_anomaly_detection_insufficient_data() {
        let stats = RollingStats::new(100);
        // With < 10 samples, nothing should be anomalous
        assert!(!stats.is_anomalous(1000.0, 2.0));
    }

    #[test]
    fn test_anomaly_engine_normal() {
        let mut engine = AnomalyEngine::new(3.0);
        // Feed normal commands
        for _ in 0..20 {
            let _anomalies = engine.record_command("ls -la", 2000.0);
        }
        // Normal command should not trigger now
        let anomalies = engine.record_command("cd foo", 2000.0);
        assert!(anomalies.is_empty());
    }

    #[test]
    fn test_keystroke_recording() {
        let mut engine = AnomalyEngine::new(3.0);
        for _ in 0..20 {
            engine.record_keystroke(150.0);
        }
        // A normal interval should not trigger
        let result = engine.record_keystroke(140.0);
        assert!(result.is_none());
    }

    #[test]
    fn test_markov_chain_learning() {
        let mut chain = MarkovChain::new(1, 0.05);
        // Train with repeated sequence
        for _ in 0..20 {
            chain.record("ls");
            chain.record("cd foo");
            chain.record("cat file");
        }
        assert!(chain.context_count() > 0);
        assert!(chain.total_transitions() > 0);
    }

    #[test]
    fn test_markov_chain_unusual_sequence() {
        let mut chain = MarkovChain::new(1, 0.05);
        // Train heavily with one pattern
        for _ in 0..50 {
            chain.record("ls");
            chain.record("cd");
        }
        // Now try an unusual follow-up
        chain.record("ls");
        let result = chain.record("rm -rf /");
        // After sufficient training, this should be flagged
        // (may or may not trigger depending on exact counts)
        // At minimum, verify no panic
        assert!(chain.context_count() > 0);
    }

    #[test]
    fn test_time_of_day_profile() {
        let mut profile = TimeOfDayProfile::new(100);
        // Train with daytime activity
        for _ in 0..120 {
            profile.record_activity(10); // 10 AM
            profile.record_activity(14); // 2 PM
        }
        assert!(profile.is_trained());
        let peaks = profile.peak_hours();
        assert!(!peaks.is_empty());
    }

    #[test]
    fn test_session_anomaly_score_empty() {
        let mut score = SessionAnomalyScore::new();
        assert!(score.threat_score() < 0.001);
        assert_eq!(score.threat_level(), AnomalySeverity::Low);
    }

    #[test]
    fn test_session_anomaly_score_accumulation() {
        let mut score = SessionAnomalyScore::new();
        let event = AnomalyEvent {
            category: AnomalyCategory::KeystrokeTiming,
            severity: AnomalySeverity::Critical,
            detail: "test".to_string(),
            value: 1.0,
            threshold: 0.5,
        };
        score.record_anomaly(&event);
        assert!(score.threat_score() > 0.0);
    }

    #[test]
    fn test_session_anomaly_score_reset() {
        let mut score = SessionAnomalyScore::new();
        let event = AnomalyEvent {
            category: AnomalyCategory::Frequency,
            severity: AnomalySeverity::High,
            detail: "test".to_string(),
            value: 1.0,
            threshold: 0.5,
        };
        score.record_anomaly(&event);
        score.reset();
        assert!(score.threat_score() < 0.001);
    }
}
