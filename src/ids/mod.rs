// ╔══════════════════════════════════════════════════════════════════╗
// ║              GhostShell — IDS (Intrusion Detection System)       ║
// ╚══════════════════════════════════════════════════════════════════╝

pub mod alerts;
pub mod alert_correlation;
pub mod anomaly;
pub mod biometric_auth;
pub mod biometrics;
pub mod command_analyzer;
pub mod network_monitor;
pub mod signatures;

use crate::ids::alerts::{Alert, AlertAction, AlertSeverity};
use crate::ids::alert_correlation::AlertCorrelationEngine;
use crate::ids::network_monitor::NetworkMonitor;
use crate::config::IdsConfig;
use crossterm::event::KeyEvent;
use std::time::Instant;


/// Central IDS engine that ties anomaly detection, biometrics,
/// command analysis, alerting, correlation, and network monitoring together
pub struct IdsEngine {
    anomaly: anomaly::AnomalyEngine,
    biometrics: biometrics::KeystrokeTracker,
    analyzer: command_analyzer::CommandAnalyzer,
    last_command_time: Instant,
    enabled: bool,
    biometrics_enabled: bool,
    alert_id_counter: u64,
    /// Alert correlation engine
    correlation: AlertCorrelationEngine,
    /// Network threat monitor
    network: NetworkMonitor,
    /// Command chain analyzer for multi-step attack detection
    chain_analyzer: command_analyzer::CommandChainAnalyzer,
}

impl IdsEngine {
    pub fn new(config: &IdsConfig) -> Self {
        Self {
            anomaly: anomaly::AnomalyEngine::new(config.anomaly_threshold),
            biometrics: biometrics::KeystrokeTracker::new(),
            analyzer: command_analyzer::CommandAnalyzer::new(),
            last_command_time: Instant::now(),
            enabled: config.enabled,
            biometrics_enabled: config.biometrics_enabled,
            alert_id_counter: 0,
            correlation: AlertCorrelationEngine::default(),
            network: NetworkMonitor::new(config.enabled),
            chain_analyzer: command_analyzer::CommandChainAnalyzer::new(),
        }
    }

    fn next_alert_id(&mut self) -> u64 {
        self.alert_id_counter += 1;
        self.alert_id_counter
    }

    /// Record a keystroke for biometrics and anomaly detection
    pub fn record_keystroke(&mut self, key: &KeyEvent) {
        if !self.enabled {
            return;
        }

        if let crossterm::event::KeyCode::Char(c) = key.code {
            self.biometrics.key_down(c);
        }
    }

    /// Analyze a command string for threats and anomalies
    pub fn analyze_command(&mut self, cmd: &str) -> Option<Alert> {
        if !self.enabled || cmd.trim().is_empty() {
            return None;
        }

        // Check against attack signatures
        let risk = self.analyzer.analyze(cmd);
        if risk.risk_level >= command_analyzer::RiskLevel::High {
            // Feed risk categories into chain analyzer
            for pattern in &risk.matched_patterns {
                let chains = self.chain_analyzer.record_category(&pattern.category);
                if !chains.is_empty() {
                    // Multi-step attack chain detected — Critical alert
                    let alert = Alert {
                        id: self.next_alert_id(),
                        severity: AlertSeverity::Critical,
                        source: "IDS/ChainAnalyzer".to_string(),
                        message: format!(
                            "Multi-step attack chain detected: {} (commands: {})",
                            chains.join(", "),
                            cmd
                        ),
                        timestamp: Instant::now(),
                        acknowledged: false,
                        action: AlertAction::LockSession,
                    };
                    self.correlation.process_alert(&alert);
                    return Some(alert);
                }
            }

            let alert = Alert {
                id: self.next_alert_id(),
                severity: AlertSeverity::Critical,
                source: "IDS/CommandAnalyzer".to_string(),
                message: format!(
                    "High-risk command detected: {} (score: {:.1}, patterns: {})",
                    cmd,
                    risk.score,
                    risk.matched_patterns
                        .iter()
                        .map(|p| p.name.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
                timestamp: Instant::now(),
                acknowledged: false,
                action: AlertAction::StatusBar,
            };
            self.correlation.process_alert(&alert);
            return Some(alert);
        }

        // Check anomaly engine
        let elapsed_ms = self.last_command_time.elapsed().as_secs_f64() * 1000.0;
        self.last_command_time = Instant::now();

        let anomalies = self.anomaly.record_command(cmd, elapsed_ms);
        if let Some(first) = anomalies.first() {
            let alert = Alert {
                id: self.next_alert_id(),
                severity: AlertSeverity::Warning,
                source: "IDS/Anomaly".to_string(),
                message: first.detail.clone(),
                timestamp: Instant::now(),
                acknowledged: false,
                action: AlertAction::Notify,
            };
            self.correlation.process_alert(&alert);
            return Some(alert);
        }

        None
    }

    /// Check a network connection attempt
    pub fn check_connection(&mut self, host: &str, port: u16) -> Option<Alert> {
        if !self.enabled {
            return None;
        }

        if let Some(threat) = self.network.check_connection(host, port) {
            let alert = Alert {
                id: self.next_alert_id(),
                severity: threat.severity,
                source: "IDS/NetworkMonitor".to_string(),
                message: threat.detail,
                timestamp: Instant::now(),
                acknowledged: false,
                action: if threat.severity >= AlertSeverity::Critical {
                    AlertAction::LockSession
                } else {
                    AlertAction::StatusBar
                },
            };
            self.correlation.process_alert(&alert);
            return Some(alert);
        }
        None
    }

    /// Get the correlation engine (for incident queries)
    pub fn correlation(&self) -> &AlertCorrelationEngine {
        &self.correlation
    }

    /// Get the network monitor (for configuration)
    pub fn network_mut(&mut self) -> &mut NetworkMonitor {
        &mut self.network
    }
}
