// ╔══════════════════════════════════════════════════════════════════╗
// ║              GhostShell — Alert System                           ║
// ║         Centralized alert queue with severity and actions        ║
// ╚══════════════════════════════════════════════════════════════════╝

use std::collections::VecDeque;
use std::time::Instant;

/// Alert severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AlertSeverity {
    Info,
    Warning,
    Danger,
    Critical,
}

impl AlertSeverity {
    pub fn emoji(&self) -> &str {
        match self {
            Self::Info => "ℹ",
            Self::Warning => "⚠",
            Self::Danger => "🔴",
            Self::Critical => "☠",
        }
    }

    pub fn label(&self) -> &str {
        match self {
            Self::Info => "INFO",
            Self::Warning => "WARN",
            Self::Danger => "DANGER",
            Self::Critical => "CRIT",
        }
    }
}

/// An alert event
#[derive(Debug, Clone)]
pub struct Alert {
    pub id: u64,
    pub severity: AlertSeverity,
    pub source: String,
    pub message: String,
    pub timestamp: Instant,
    pub acknowledged: bool,
    pub action: AlertAction,
}

/// What action should be taken for an alert
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlertAction {
    /// Just log it
    LogOnly,
    /// Show a visual notification
    Notify,
    /// Sound an alert in the status bar
    StatusBar,
    /// Lock the session
    LockSession,
    /// Trigger panic mode
    Panic,
    /// Kill the offending process/pane
    KillPane,
}

/// Central alert queue
pub struct AlertQueue {
    alerts: VecDeque<Alert>,
    max_alerts: usize,
    next_id: u64,
    unacknowledged_count: usize,
}

impl AlertQueue {
    pub fn new(max_alerts: usize) -> Self {
        Self {
            alerts: VecDeque::with_capacity(max_alerts),
            max_alerts,
            next_id: 1,
            unacknowledged_count: 0,
        }
    }

    /// Push a new alert
    pub fn push(&mut self, severity: AlertSeverity, source: &str, message: &str, action: AlertAction) -> u64 {
        let id = self.next_id;
        self.next_id += 1;

        // Remove oldest if full
        while self.alerts.len() >= self.max_alerts {
            if let Some(old) = self.alerts.pop_front() {
                if !old.acknowledged {
                    self.unacknowledged_count = self.unacknowledged_count.saturating_sub(1);
                }
            }
        }

        self.alerts.push_back(Alert {
            id,
            severity,
            source: source.to_string(),
            message: message.to_string(),
            timestamp: Instant::now(),
            acknowledged: false,
            action,
        });
        self.unacknowledged_count += 1;

        id
    }

    /// Acknowledge an alert by ID
    pub fn acknowledge(&mut self, id: u64) -> bool {
        if let Some(alert) = self.alerts.iter_mut().find(|a| a.id == id) {
            if !alert.acknowledged {
                alert.acknowledged = true;
                self.unacknowledged_count = self.unacknowledged_count.saturating_sub(1);
                return true;
            }
        }
        false
    }

    /// Acknowledge all alerts
    pub fn acknowledge_all(&mut self) {
        for alert in &mut self.alerts {
            alert.acknowledged = true;
        }
        self.unacknowledged_count = 0;
    }

    /// Get unacknowledged alert count
    pub fn unacknowledged(&self) -> usize {
        self.unacknowledged_count
    }

    /// Get the most severe unacknowledged alert
    pub fn most_severe_unack(&self) -> Option<&Alert> {
        self.alerts
            .iter()
            .filter(|a| !a.acknowledged)
            .max_by_key(|a| a.severity)
    }

    /// Get recent alerts (last N)
    pub fn recent(&self, count: usize) -> Vec<&Alert> {
        self.alerts.iter().rev().take(count).collect()
    }

    /// Get all alerts with a minimum severity
    pub fn by_severity(&self, min_severity: AlertSeverity) -> Vec<&Alert> {
        self.alerts.iter().filter(|a| a.severity >= min_severity).collect()
    }

    /// Get total alert count
    pub fn total(&self) -> usize {
        self.alerts.len()
    }

    /// Clear all alerts
    pub fn clear(&mut self) {
        self.alerts.clear();
        self.unacknowledged_count = 0;
    }

    /// Get alerts requiring action (not just logging)
    pub fn actionable(&self) -> Vec<&Alert> {
        self.alerts
            .iter()
            .filter(|a| !a.acknowledged && a.action != AlertAction::LogOnly)
            .collect()
    }
}

impl Default for AlertQueue {
    fn default() -> Self {
        Self::new(1000)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_push_and_count() {
        let mut queue = AlertQueue::new(100);
        queue.push(AlertSeverity::Warning, "ids", "test alert", AlertAction::Notify);
        assert_eq!(queue.total(), 1);
        assert_eq!(queue.unacknowledged(), 1);
    }

    #[test]
    fn test_acknowledge() {
        let mut queue = AlertQueue::new(100);
        let id = queue.push(AlertSeverity::Danger, "ids", "danger!", AlertAction::StatusBar);
        assert!(queue.acknowledge(id));
        assert_eq!(queue.unacknowledged(), 0);
    }

    #[test]
    fn test_severity_filter() {
        let mut queue = AlertQueue::new(100);
        queue.push(AlertSeverity::Info, "test", "info", AlertAction::LogOnly);
        queue.push(AlertSeverity::Critical, "test", "crit", AlertAction::Panic);
        queue.push(AlertSeverity::Warning, "test", "warn", AlertAction::Notify);

        let critical = queue.by_severity(AlertSeverity::Critical);
        assert_eq!(critical.len(), 1);

        let warnings_up = queue.by_severity(AlertSeverity::Warning);
        assert_eq!(warnings_up.len(), 2); // Warning + Critical
    }

    #[test]
    fn test_max_capacity() {
        let mut queue = AlertQueue::new(3);
        queue.push(AlertSeverity::Info, "x", "1", AlertAction::LogOnly);
        queue.push(AlertSeverity::Info, "x", "2", AlertAction::LogOnly);
        queue.push(AlertSeverity::Info, "x", "3", AlertAction::LogOnly);
        queue.push(AlertSeverity::Info, "x", "4", AlertAction::LogOnly);
        assert_eq!(queue.total(), 3); // Oldest removed
    }

    #[test]
    fn test_most_severe() {
        let mut queue = AlertQueue::new(100);
        queue.push(AlertSeverity::Info, "x", "low", AlertAction::LogOnly);
        queue.push(AlertSeverity::Critical, "x", "high", AlertAction::Panic);
        queue.push(AlertSeverity::Warning, "x", "mid", AlertAction::Notify);

        let severe = queue.most_severe_unack().unwrap();
        assert_eq!(severe.severity, AlertSeverity::Critical);
    }
}
