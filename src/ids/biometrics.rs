// ╔══════════════════════════════════════════════════════════════════╗
// ║              GhostShell — Keystroke Biometrics                   ║
// ║         User identity verification via typing patterns           ║
// ╚══════════════════════════════════════════════════════════════════╝

use std::collections::HashMap;
use std::time::Instant;

/// Keystroke biometric profile
pub struct BiometricProfile {
    /// Flight times (key-up to next key-down) in ms, per digraph
    flight_times: HashMap<String, Vec<f64>>,
    /// Dwell times (key-down to key-up) in ms, per key
    dwell_times: HashMap<char, Vec<f64>>,
    /// Overall typing speed (WPM)
    typing_speeds: Vec<f64>,
    /// Max samples per feature
    max_samples: usize,
    /// Whether the profile is trained (has enough data)
    pub trained: bool,
    /// Minimum samples for training
    min_training_samples: usize,
}

impl BiometricProfile {
    pub fn new() -> Self {
        Self {
            flight_times: HashMap::new(),
            dwell_times: HashMap::new(),
            typing_speeds: Vec::new(),
            max_samples: 200,
            trained: false,
            min_training_samples: 50,
        }
    }

    /// Record a flight time (time between consecutive key events)
    pub fn record_flight_time(&mut self, from_key: char, to_key: char, time_ms: f64) {
        let digraph = format!("{}{}", from_key, to_key);
        let entry = self.flight_times.entry(digraph).or_insert_with(Vec::new);

        if entry.len() >= self.max_samples {
            entry.remove(0);
        }
        entry.push(time_ms);

        self.check_trained();
    }

    /// Record a dwell time (how long a key is held)
    pub fn record_dwell_time(&mut self, key: char, time_ms: f64) {
        let entry = self.dwell_times.entry(key).or_insert_with(Vec::new);

        if entry.len() >= self.max_samples {
            entry.remove(0);
        }
        entry.push(time_ms);
    }

    /// Record overall typing speed
    pub fn record_typing_speed(&mut self, wpm: f64) {
        if self.typing_speeds.len() >= self.max_samples {
            self.typing_speeds.remove(0);
        }
        self.typing_speeds.push(wpm);
    }

    /// Check if input matches this profile (returns confidence 0.0 - 1.0)
    pub fn match_confidence(&self, sample: &BiometricSample) -> f64 {
        if !self.trained {
            return 1.0; // Not enough data to judge
        }

        let mut total_score = 0.0;
        let mut total_weight = 0.0;

        // Compare flight times
        for (digraph, sample_times) in &sample.flight_times {
            if let Some(profile_times) = self.flight_times.get(digraph) {
                if profile_times.len() >= 5 && !sample_times.is_empty() {
                    let profile_mean = mean(profile_times);
                    let profile_std = std_dev(profile_times);
                    let sample_mean = mean(sample_times);

                    if profile_std > 0.001 {
                        let z_score = ((sample_mean - profile_mean) / profile_std).abs();
                        let score = (-z_score / 3.0).exp(); // Gaussian-like scoring
                        total_score += score;
                        total_weight += 1.0;
                    }
                }
            }
        }

        // Compare typing speed
        if !self.typing_speeds.is_empty() && sample.typing_speed > 0.0 {
            let speed_mean = mean(&self.typing_speeds);
            let speed_std = std_dev(&self.typing_speeds);

            if speed_std > 0.001 {
                let z = ((sample.typing_speed - speed_mean) / speed_std).abs();
                let score = (-z / 3.0).exp();
                total_score += score * 2.0; // Weight typing speed more
                total_weight += 2.0;
            }
        }

        if total_weight < 0.001 {
            return 1.0;
        }

        total_score / total_weight
    }

    fn check_trained(&mut self) {
        let total_samples: usize = self.flight_times.values().map(|v| v.len()).sum();
        self.trained = total_samples >= self.min_training_samples;
    }

    /// Export the profile for storage
    pub fn export(&self) -> BiometricExport {
        BiometricExport {
            flight_means: self.flight_times.iter()
                .filter(|(_, v)| v.len() >= 5)
                .map(|(k, v)| (k.clone(), mean(v)))
                .collect(),
            flight_stds: self.flight_times.iter()
                .filter(|(_, v)| v.len() >= 5)
                .map(|(k, v)| (k.clone(), std_dev(v)))
                .collect(),
            typing_speed_mean: mean(&self.typing_speeds),
            typing_speed_std: std_dev(&self.typing_speeds),
            total_samples: self.flight_times.values().map(|v| v.len()).sum(),
        }
    }
}

impl Default for BiometricProfile {
    fn default() -> Self {
        Self::new()
    }
}

/// A biometric sample to compare against a profile
pub struct BiometricSample {
    pub flight_times: HashMap<String, Vec<f64>>,
    pub typing_speed: f64,
}

/// Exported biometric data for storage
#[derive(Debug, Clone)]
pub struct BiometricExport {
    pub flight_means: HashMap<String, f64>,
    pub flight_stds: HashMap<String, f64>,
    pub typing_speed_mean: f64,
    pub typing_speed_std: f64,
    pub total_samples: usize,
}

/// Helper: compute mean
fn mean(values: &[f64]) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    values.iter().sum::<f64>() / values.len() as f64
}

/// Helper: compute standard deviation
fn std_dev(values: &[f64]) -> f64 {
    if values.len() < 2 {
        return 0.0;
    }
    let m = mean(values);
    let variance = values.iter().map(|v| (v - m).powi(2)).sum::<f64>() / values.len() as f64;
    variance.sqrt()
}

/// Keystroke event tracker
pub struct KeystrokeTracker {
    last_key: Option<char>,
    last_key_down: Option<Instant>,
    last_key_up: Option<Instant>,
    pub profile: BiometricProfile,
}

impl KeystrokeTracker {
    pub fn new() -> Self {
        Self {
            last_key: None,
            last_key_down: None,
            last_key_up: None,
            profile: BiometricProfile::new(),
        }
    }

    /// Record a key press event
    pub fn key_down(&mut self, key: char) {
        let now = Instant::now();

        // Flight time = time from last key-up to this key-down
        if let (Some(last_char), Some(last_up)) = (self.last_key, self.last_key_up) {
            let flight_ms = now.duration_since(last_up).as_secs_f64() * 1000.0;
            self.profile.record_flight_time(last_char, key, flight_ms);
        }

        self.last_key = Some(key);
        self.last_key_down = Some(now);
    }

    /// Record a key release event
    pub fn key_up(&mut self, key: char) {
        let now = Instant::now();

        // Dwell time = time from key-down to key-up
        if let Some(down) = self.last_key_down {
            let dwell_ms = now.duration_since(down).as_secs_f64() * 1000.0;
            self.profile.record_dwell_time(key, dwell_ms);
        }

        self.last_key_up = Some(now);
    }
}

impl Default for KeystrokeTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_biometric_profile_untrained() {
        let profile = BiometricProfile::new();
        assert!(!profile.trained);

        let sample = BiometricSample {
            flight_times: HashMap::new(),
            typing_speed: 60.0,
        };

        // Untrained profile should return 1.0 confidence
        assert_eq!(profile.match_confidence(&sample), 1.0);
    }

    #[test]
    fn test_flight_time_recording() {
        let mut profile = BiometricProfile::new();
        for _ in 0..60 {
            profile.record_flight_time('a', 'b', 100.0);
        }
        assert!(profile.trained);
    }

    #[test]
    fn test_mean_std() {
        let values = vec![1.0, 2.0, 3.0, 4.0, 5.0];
        assert!((mean(&values) - 3.0).abs() < 0.001);
        assert!(std_dev(&values) > 0.0);
    }
}
