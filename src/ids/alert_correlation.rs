// ╔══════════════════════════════════════════════════════════════════╗
// ║         GhostShell — Alert Correlation Engine                    ║
// ║    Incident grouping, fatigue prevention, auto-escalation       ║
// ╚══════════════════════════════════════════════════════════════════╝

use crate::ids::alerts::{Alert, AlertSeverity};
use std::collections::HashMap;
use std::time::{Duration, Instant};

// ── Kill Chain Stages ────────────────────────────────────────────

/// MITRE ATT&CK inspired kill chain stages
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KillChainStage {
    /// Scanning, enumeration, info gathering
    Reconnaissance,
    /// Gaining initial access
    InitialAccess,
    /// Running malicious code
    Execution,
    /// Maintaining presence
    Persistence,
    /// Gaining higher privileges
    PrivilegeEscalation,
    /// Avoiding detection
    DefenseEvasion,
    /// Stealing credentials
    CredentialAccess,
    /// Exploring the network/system
    Discovery,
    /// Moving to other systems
    LateralMovement,
    /// Stealing data
    Exfiltration,
    /// Disruption, destruction
    Impact,
}

impl KillChainStage {
    /// Map an alert source/message to a kill-chain stage
    pub fn from_alert(alert: &Alert) -> Self {
        let msg = alert.message.to_lowercase();
        let src = alert.source.to_lowercase();

        if msg.contains("recon") || msg.contains("scan") || msg.contains("enum") {
            KillChainStage::Reconnaissance
        } else if msg.contains("reverse_shell") || msg.contains("shell") {
            KillChainStage::InitialAccess
        } else if msg.contains("privesc") || msg.contains("sudo") || msg.contains("suid") {
            KillChainStage::PrivilegeEscalation
        } else if msg.contains("persistence") || msg.contains("cron") || msg.contains("backdoor") {
            KillChainStage::Persistence
        } else if msg.contains("exfil") || msg.contains("upload") || msg.contains("dns_exfil") {
            KillChainStage::Exfiltration
        } else if msg.contains("fork_bomb") || msg.contains("wipe") || msg.contains("destructive") {
            KillChainStage::Impact
        } else if msg.contains("credential") || msg.contains("password") || msg.contains("key") {
            KillChainStage::CredentialAccess
        } else if msg.contains("anti_forensics") || msg.contains("history_clear") || msg.contains("evasion") {
            KillChainStage::DefenseEvasion
        } else if msg.contains("lateral") || msg.contains("ssh") {
            KillChainStage::LateralMovement
        } else if src.contains("anomaly") || src.contains("biometric") {
            KillChainStage::Discovery
        } else {
            KillChainStage::Execution
        }
    }

    /// Get severity weight for partial kill-chain completion
    pub fn weight(&self) -> f64 {
        match self {
            KillChainStage::Reconnaissance => 0.3,
            KillChainStage::InitialAccess => 0.8,
            KillChainStage::Execution => 0.6,
            KillChainStage::Persistence => 0.7,
            KillChainStage::PrivilegeEscalation => 0.9,
            KillChainStage::DefenseEvasion => 0.5,
            KillChainStage::CredentialAccess => 0.8,
            KillChainStage::Discovery => 0.3,
            KillChainStage::LateralMovement => 0.7,
            KillChainStage::Exfiltration => 0.9,
            KillChainStage::Impact => 1.0,
        }
    }
}

// ── Incident ─────────────────────────────────────────────────────

/// A correlated group of related alerts
#[derive(Debug, Clone)]
pub struct Incident {
    /// Unique incident ID
    pub id: u64,
    /// Alert IDs in this incident
    pub alert_ids: Vec<u64>,
    /// Kill-chain stages observed
    pub stages: Vec<KillChainStage>,
    /// Composite severity (escalated based on stage coverage)
    pub severity: AlertSeverity,
    /// When the incident started
    pub started_at: Instant,
    /// When the last alert was added
    pub last_activity: Instant,
    /// Primary source category
    pub category: String,
    /// Number of alerts
    pub alert_count: usize,
}

impl Incident {
    /// Get the kill-chain coverage score (0.0 - 1.0)
    pub fn kill_chain_coverage(&self) -> f64 {
        if self.stages.is_empty() {
            return 0.0;
        }
        let unique_stages: std::collections::HashSet<_> = self.stages.iter().collect();
        let total_weight: f64 = unique_stages.iter().map(|s| s.weight()).sum();
        (total_weight / 5.0).min(1.0) // Normalize against expected max
    }

    /// How long the incident has been active
    pub fn duration(&self) -> Duration {
        self.started_at.elapsed()
    }

    /// Is this incident still active? (had activity within the window)
    pub fn is_active(&self, window: Duration) -> bool {
        self.last_activity.elapsed() < window
    }
}

// ── Suppression Rule ─────────────────────────────────────────────

/// Alert fatigue prevention rule
struct SuppressionRule {
    /// Source pattern to match
    source_pattern: String,
    /// Max alerts of this type within window
    max_count: usize,
    /// Time window for counting
    window: Duration,
    /// Timestamps of recent alerts matching this rule
    recent: Vec<Instant>,
}

impl SuppressionRule {
    fn new(source_pattern: &str, max_count: usize, window_secs: u64) -> Self {
        Self {
            source_pattern: source_pattern.to_string(),
            max_count,
            window: Duration::from_secs(window_secs),
            recent: Vec::new(),
        }
    }

    /// Check if this alert should be suppressed
    fn should_suppress(&mut self, source: &str) -> bool {
        if !source.contains(&self.source_pattern) {
            return false;
        }

        let now = Instant::now();
        // Clean old entries
        self.recent.retain(|t| now.duration_since(*t) < self.window);

        if self.recent.len() >= self.max_count {
            true // Suppress
        } else {
            self.recent.push(now);
            false
        }
    }
}

// ── Correlation Engine ───────────────────────────────────────────

/// Central alert correlation engine
pub struct AlertCorrelationEngine {
    /// Active incidents
    incidents: Vec<Incident>,
    /// Correlation time window
    correlation_window: Duration,
    /// Next incident ID
    next_id: u64,
    /// Suppression rules
    suppression_rules: Vec<SuppressionRule>,
    /// Alert-to-incident mapping
    alert_incident_map: HashMap<u64, u64>,
    /// Escalation tracking: (source, count) for auto-escalation
    escalation_counters: HashMap<String, EscalationState>,
}

/// Tracks escalation state for a source
struct EscalationState {
    count: u32,
    first_seen: Instant,
    current_severity: AlertSeverity,
}

impl AlertCorrelationEngine {
    pub fn new(correlation_window_secs: u64) -> Self {
        let mut engine = Self {
            incidents: Vec::new(),
            correlation_window: Duration::from_secs(correlation_window_secs),
            next_id: 1,
            suppression_rules: Vec::new(),
            alert_incident_map: HashMap::new(),
            escalation_counters: HashMap::new(),
        };

        // Default suppression rules
        engine.add_suppression_rule("IDS/Anomaly", 5, 60);      // Max 5 anomaly alerts per minute
        engine.add_suppression_rule("IDS/Biometric", 3, 120);   // Max 3 biometric alerts per 2 min
        engine.add_suppression_rule("IDS/CommandAnalyzer", 10, 60); // Max 10 command alerts per minute

        engine
    }

    /// Add a suppression rule
    pub fn add_suppression_rule(&mut self, source_pattern: &str, max_count: usize, window_secs: u64) {
        self.suppression_rules.push(SuppressionRule::new(
            source_pattern,
            max_count,
            window_secs,
        ));
    }

    /// Process a new alert — correlate, suppress, or create new incident
    /// Returns None if the alert was suppressed
    pub fn process_alert(&mut self, alert: &Alert) -> Option<&Incident> {
        // Check suppression rules
        for rule in &mut self.suppression_rules {
            if rule.should_suppress(&alert.source) {
                return None; // Alert suppressed
            }
        }

        // Auto-escalate severity if same source keeps firing
        let escalated_severity = self.check_escalation(&alert.source, alert.severity);

        // Determine kill-chain stage
        let stage = KillChainStage::from_alert(alert);

        // Try to correlate with existing active incident
        let now = Instant::now();
        let window = self.correlation_window;

        if let Some(incident) = self.incidents.iter_mut().find(|inc| {
            inc.is_active(window) && inc.category == alert.source
        }) {
            // Add to existing incident
            incident.alert_ids.push(alert.id);
            incident.stages.push(stage);
            incident.last_activity = now;
            incident.alert_count += 1;

            // Escalate incident severity
            if escalated_severity > incident.severity {
                incident.severity = escalated_severity;
            }

            self.alert_incident_map.insert(alert.id, incident.id);
            let inc_id = incident.id;
            return self.incidents.iter().find(|i| i.id == inc_id);
        }

        // Create new incident
        let inc_id = self.next_id;
        self.next_id += 1;

        self.incidents.push(Incident {
            id: inc_id,
            alert_ids: vec![alert.id],
            stages: vec![stage],
            severity: escalated_severity,
            started_at: now,
            last_activity: now,
            category: alert.source.clone(),
            alert_count: 1,
        });

        self.alert_incident_map.insert(alert.id, inc_id);
        self.incidents.last()
    }

    /// Check if severity should auto-escalate
    fn check_escalation(&mut self, source: &str, base_severity: AlertSeverity) -> AlertSeverity {
        let state = self.escalation_counters
            .entry(source.to_string())
            .or_insert_with(|| EscalationState {
                count: 0,
                first_seen: Instant::now(),
                current_severity: base_severity,
            });

        state.count += 1;

        // Escalate severity after repeated alerts
        let escalated = if state.count >= 10 {
            AlertSeverity::Critical
        } else if state.count >= 5 && base_severity < AlertSeverity::Danger {
            AlertSeverity::Danger
        } else if state.count >= 3 && base_severity < AlertSeverity::Warning {
            AlertSeverity::Warning
        } else {
            base_severity
        };

        state.current_severity = escalated;
        escalated
    }

    /// Get all active incidents
    pub fn active_incidents(&self) -> Vec<&Incident> {
        self.incidents
            .iter()
            .filter(|i| i.is_active(self.correlation_window))
            .collect()
    }

    /// Get the most severe active incident
    pub fn most_severe_incident(&self) -> Option<&Incident> {
        self.active_incidents()
            .into_iter()
            .max_by_key(|i| i.severity)
    }

    /// Get total incident count
    pub fn total_incidents(&self) -> usize {
        self.incidents.len()
    }

    /// Get incident for a specific alert
    pub fn incident_for_alert(&self, alert_id: u64) -> Option<&Incident> {
        self.alert_incident_map
            .get(&alert_id)
            .and_then(|inc_id| self.incidents.iter().find(|i| i.id == *inc_id))
    }

    /// Clear old incidents
    pub fn cleanup(&mut self) {
        let window = self.correlation_window * 10; // Keep 10x the window
        self.incidents.retain(|i| i.is_active(window));
    }

    /// Get kill-chain stages seen across all active incidents
    pub fn observed_kill_chain(&self) -> Vec<KillChainStage> {
        let mut stages: Vec<KillChainStage> = self
            .active_incidents()
            .iter()
            .flat_map(|i| i.stages.clone())
            .collect();
        stages.sort_by_key(|s| *s as u8);
        stages.dedup();
        stages
    }
}

impl Default for AlertCorrelationEngine {
    fn default() -> Self {
        Self::new(300) // 5-minute correlation window
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::alerts::AlertAction;

    fn make_alert(id: u64, source: &str, message: &str, severity: AlertSeverity) -> Alert {
        Alert {
            id,
            severity,
            source: source.to_string(),
            message: message.to_string(),
            timestamp: Instant::now(),
            acknowledged: false,
            action: AlertAction::Notify,
        }
    }

    #[test]
    fn test_incident_creation() {
        let mut engine = AlertCorrelationEngine::new(300);
        let alert = make_alert(1, "IDS/Test", "reverse_shell detected", AlertSeverity::Critical);
        let incident = engine.process_alert(&alert);
        assert!(incident.is_some());
        assert_eq!(engine.total_incidents(), 1);
    }

    #[test]
    fn test_incident_correlation() {
        let mut engine = AlertCorrelationEngine::new(300);
        let a1 = make_alert(1, "IDS/CommandAnalyzer", "recon detected", AlertSeverity::Warning);
        let a2 = make_alert(2, "IDS/CommandAnalyzer", "privesc attempt", AlertSeverity::Danger);

        engine.process_alert(&a1);
        engine.process_alert(&a2);

        // Should be same incident (same source within window)
        assert_eq!(engine.total_incidents(), 1);
        let incidents = engine.active_incidents();
        assert_eq!(incidents[0].alert_count, 2);
    }

    #[test]
    fn test_kill_chain_mapping() {
        let alert = make_alert(1, "IDS/Test", "reverse_shell detected", AlertSeverity::Critical);
        assert_eq!(KillChainStage::from_alert(&alert), KillChainStage::InitialAccess);

        let alert2 = make_alert(2, "IDS/Test", "privesc suid attempt", AlertSeverity::Danger);
        assert_eq!(KillChainStage::from_alert(&alert2), KillChainStage::PrivilegeEscalation);
    }

    #[test]
    fn test_suppression() {
        let mut engine = AlertCorrelationEngine::new(300);
        // Suppress after 5 anomaly alerts per minute
        for i in 0..6 {
            let alert = make_alert(i + 1, "IDS/Anomaly", "anomaly found", AlertSeverity::Info);
            let result = engine.process_alert(&alert);
            if i >= 5 {
                // Should be suppressed
                assert!(result.is_none(), "Alert {} should be suppressed", i);
            }
        }
    }

    #[test]
    fn test_severity_escalation() {
        let mut engine = AlertCorrelationEngine::new(300);
        for i in 0..10 {
            let alert = make_alert(i + 1, "IDS/CommandAnalyzer", "recon scan", AlertSeverity::Info);
            engine.process_alert(&alert);
        }
        // After 10 alerts, severity should auto-escalate to Critical
        let incidents = engine.active_incidents();
        assert!(!incidents.is_empty());
        assert_eq!(incidents[0].severity, AlertSeverity::Critical);
    }

    #[test]
    fn test_incident_kill_chain_coverage() {
        let mut engine = AlertCorrelationEngine::new(300);
        let a1 = make_alert(1, "IDS/Chain", "recon scan detected", AlertSeverity::Info);
        let a2 = make_alert(2, "IDS/Chain", "reverse_shell attempt", AlertSeverity::Critical);
        let a3 = make_alert(3, "IDS/Chain", "privesc detected", AlertSeverity::Danger);

        engine.process_alert(&a1);
        engine.process_alert(&a2);
        engine.process_alert(&a3);

        let incident = &engine.active_incidents()[0];
        assert!(incident.kill_chain_coverage() > 0.0);
        assert!(incident.stages.len() >= 2);
    }

    #[test]
    fn test_most_severe_incident() {
        let mut engine = AlertCorrelationEngine::new(300);
        let a1 = make_alert(1, "IDS/Source1", "low alert", AlertSeverity::Info);
        let a2 = make_alert(2, "IDS/Source2", "critical alert", AlertSeverity::Critical);  

        engine.process_alert(&a1);
        engine.process_alert(&a2);

        let severe = engine.most_severe_incident().unwrap();
        assert_eq!(severe.severity, AlertSeverity::Critical);
    }
}
