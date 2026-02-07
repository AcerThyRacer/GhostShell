// ╔══════════════════════════════════════════════════════════════════╗
// ║         GhostShell — Network Threat Detection                    ║
// ║    Connection monitoring, DNS exfil detection, whitelisting     ║
// ╚══════════════════════════════════════════════════════════════════╝

use crate::ids::alerts::AlertSeverity;
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

// ── Network Threat Event ─────────────────────────────────────────

/// A detected network threat event
#[derive(Debug, Clone)]
pub struct NetworkThreatEvent {
    /// Type of threat
    pub threat_type: NetworkThreatType,
    /// Severity level
    pub severity: AlertSeverity,
    /// Detail message
    pub detail: String,
    /// Destination address (if applicable)
    pub destination: String,
    /// When the threat was detected
    pub detected_at: Instant,
}

/// Types of network threats
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkThreatType {
    /// Suspicious outbound connection
    SuspiciousConnection,
    /// Possible DNS exfiltration
    DnsExfiltration,
    /// Unauthorized listener (bind to port)
    UnauthorizedListener,
    /// Connection to cloud metadata service
    MetadataServiceAccess,
    /// High-frequency outbound connections
    ConnectionFlood,
    /// Connection to known bad IP/domain
    KnownBadDestination,
}

// ── Connection Whitelist ─────────────────────────────────────────

/// Allowed destinations for outbound connections
pub struct ConnectionWhitelist {
    /// Allowed host patterns
    allowed_hosts: HashSet<String>,
    /// Allowed port ranges
    allowed_ports: HashSet<u16>,
    /// Whether the whitelist is in enforce mode (block vs warn)
    enforce: bool,
}

impl ConnectionWhitelist {
    pub fn new(enforce: bool) -> Self {
        let mut whitelist = Self {
            allowed_hosts: HashSet::new(),
            allowed_ports: HashSet::new(),
            enforce,
        };

        // Default allowed
        whitelist.allowed_hosts.insert("localhost".to_string());
        whitelist.allowed_hosts.insert("127.0.0.1".to_string());
        whitelist.allowed_hosts.insert("::1".to_string());
        whitelist.allowed_ports.insert(80);
        whitelist.allowed_ports.insert(443);
        whitelist.allowed_ports.insert(22);
        whitelist.allowed_ports.insert(53);

        whitelist
    }

    /// Add a host to the whitelist
    pub fn allow_host(&mut self, host: &str) {
        self.allowed_hosts.insert(host.to_string());
    }

    /// Add a port to the whitelist
    pub fn allow_port(&mut self, port: u16) {
        self.allowed_ports.insert(port);
    }

    /// Check if a destination is allowed
    pub fn is_allowed(&self, host: &str, port: u16) -> bool {
        self.allowed_hosts.contains(host) || self.allowed_ports.contains(&port)
    }

    /// Check if running in enforce mode
    pub fn is_enforcing(&self) -> bool {
        self.enforce
    }
}

impl Default for ConnectionWhitelist {
    fn default() -> Self {
        Self::new(false)
    }
}

// ── DNS Exfil Detector ───────────────────────────────────────────

/// Detects DNS-based data exfiltration patterns
pub struct DnsExfilDetector {
    /// Recent queries per domain (for rate detection)
    query_counts: HashMap<String, Vec<Instant>>,
    /// Threshold for subdomain label length (chars)
    max_label_len: usize,
    /// Threshold for query rate (per minute)
    max_queries_per_minute: usize,
    /// Known suspicious TXT record patterns
    suspicious_record_types: Vec<String>,
}

impl DnsExfilDetector {
    pub fn new() -> Self {
        Self {
            query_counts: HashMap::new(),
            max_label_len: 40,          // Legitimate subdomains rarely exceed 40 chars
            max_queries_per_minute: 30,  // Normal DNS queries
            suspicious_record_types: vec![
                "TXT".to_string(),
                "NULL".to_string(),
                "CNAME".to_string(),
            ],
        }
    }

    /// Analyze a DNS query for exfiltration indicators
    pub fn analyze_query(&mut self, domain: &str, record_type: &str) -> Option<NetworkThreatEvent> {
        let now = Instant::now();

        // Check for unusually long subdomain labels (data encoding)
        let labels: Vec<&str> = domain.split('.').collect();
        for label in &labels {
            if label.len() > self.max_label_len {
                return Some(NetworkThreatEvent {
                    threat_type: NetworkThreatType::DnsExfiltration,
                    severity: AlertSeverity::Danger,
                    detail: format!(
                        "DNS exfil: abnormally long subdomain label ({} chars) in {}",
                        label.len(),
                        domain
                    ),
                    destination: domain.to_string(),
                    detected_at: now,
                });
            }
        }

        // Check for high entropy labels (encoded data)
        for label in &labels {
            if label.len() > 10 && Self::has_high_entropy(label) {
                return Some(NetworkThreatEvent {
                    threat_type: NetworkThreatType::DnsExfiltration,
                    severity: AlertSeverity::Warning,
                    detail: format!(
                        "DNS exfil: high-entropy subdomain label in {}",
                        domain
                    ),
                    destination: domain.to_string(),
                    detected_at: now,
                });
            }
        }

        // Check query rate
        let base_domain = Self::extract_base_domain(domain);
        let entries = self.query_counts.entry(base_domain.clone()).or_default();
        entries.push(now);

        // Clean old entries
        let one_min_ago = now - Duration::from_secs(60);
        entries.retain(|t| *t > one_min_ago);

        if entries.len() > self.max_queries_per_minute {
            return Some(NetworkThreatEvent {
                threat_type: NetworkThreatType::DnsExfiltration,
                severity: AlertSeverity::Danger,
                detail: format!(
                    "DNS exfil: high query rate to {} ({} queries/min)",
                    base_domain,
                    entries.len()
                ),
                destination: domain.to_string(),
                detected_at: now,
            });
        }

        // Check for suspicious record types with encoded data
        if self.suspicious_record_types.contains(&record_type.to_uppercase()) {
            if labels.len() > 3 {
                return Some(NetworkThreatEvent {
                    threat_type: NetworkThreatType::DnsExfiltration,
                    severity: AlertSeverity::Warning,
                    detail: format!(
                        "DNS exfil: {} query with multiple subdomains: {}",
                        record_type, domain
                    ),
                    destination: domain.to_string(),
                    detected_at: now,
                });
            }
        }

        None
    }

    /// Check if a string has high entropy (likely encoded data)
    fn has_high_entropy(s: &str) -> bool {
        if s.is_empty() {
            return false;
        }

        let mut freq = [0u32; 256];
        for b in s.bytes() {
            freq[b as usize] += 1;
        }

        let len = s.len() as f64;
        let mut entropy = 0.0;
        for &count in &freq {
            if count > 0 {
                let p = count as f64 / len;
                entropy -= p * p.log2();
            }
        }

        // > 3.5 bits/byte suggests encoded data
        entropy > 3.5
    }

    /// Extract the base domain (last two labels)
    fn extract_base_domain(domain: &str) -> String {
        let labels: Vec<&str> = domain.split('.').collect();
        if labels.len() >= 2 {
            format!("{}.{}", labels[labels.len() - 2], labels[labels.len() - 1])
        } else {
            domain.to_string()
        }
    }
}

impl Default for DnsExfilDetector {
    fn default() -> Self {
        Self::new()
    }
}

// ── Network Monitor ──────────────────────────────────────────────

/// Central network threat detection monitor
pub struct NetworkMonitor {
    /// Whitelist for allowed connections
    whitelist: ConnectionWhitelist,
    /// DNS exfil detector
    dns_detector: DnsExfilDetector,
    /// Known cloud metadata endpoints
    metadata_endpoints: HashSet<String>,
    /// Recent connections for flood detection
    recent_connections: Vec<(String, Instant)>,
    /// Max connections per minute before flood alert
    flood_threshold: usize,
    /// Detected threats
    threats: Vec<NetworkThreatEvent>,
    /// Total threats detected
    total_threats: u64,
    /// Whether monitoring is enabled
    enabled: bool,
}

impl NetworkMonitor {
    pub fn new(enabled: bool) -> Self {
        let mut metadata_endpoints = HashSet::new();
        // AWS
        metadata_endpoints.insert("169.254.169.254".to_string());
        // GCP
        metadata_endpoints.insert("metadata.google.internal".to_string());
        metadata_endpoints.insert("169.254.169.254".to_string());
        // Azure
        metadata_endpoints.insert("169.254.169.254".to_string());
        // Generic link-local
        metadata_endpoints.insert("169.254.0.0".to_string());

        Self {
            whitelist: ConnectionWhitelist::default(),
            dns_detector: DnsExfilDetector::new(),
            metadata_endpoints,
            recent_connections: Vec::new(),
            flood_threshold: 50,
            threats: Vec::new(),
            total_threats: 0,
            enabled,
        }
    }

    /// Check an outbound connection attempt
    pub fn check_connection(&mut self, host: &str, port: u16) -> Option<NetworkThreatEvent> {
        if !self.enabled {
            return None;
        }

        let now = Instant::now();

        // Check cloud metadata access
        if self.metadata_endpoints.contains(host) {
            let threat = NetworkThreatEvent {
                threat_type: NetworkThreatType::MetadataServiceAccess,
                severity: AlertSeverity::Critical,
                detail: format!("Cloud metadata service access: {}:{}", host, port),
                destination: format!("{}:{}", host, port),
                detected_at: now,
            };
            self.record_threat(threat.clone());
            return Some(threat);
        }

        // Check whitelist
        if !self.whitelist.is_allowed(host, port) {
            let threat = NetworkThreatEvent {
                threat_type: NetworkThreatType::SuspiciousConnection,
                severity: AlertSeverity::Warning,
                detail: format!("Non-whitelisted connection to {}:{}", host, port),
                destination: format!("{}:{}", host, port),
                detected_at: now,
            };
            self.record_threat(threat.clone());
            return Some(threat);
        }

        // Check for connection flooding
        self.recent_connections.push((host.to_string(), now));
        let one_min_ago = now - Duration::from_secs(60);
        self.recent_connections.retain(|(_, t)| *t > one_min_ago);

        if self.recent_connections.len() > self.flood_threshold {
            let threat = NetworkThreatEvent {
                threat_type: NetworkThreatType::ConnectionFlood,
                severity: AlertSeverity::Danger,
                detail: format!(
                    "Connection flood: {} connections/min (threshold: {})",
                    self.recent_connections.len(),
                    self.flood_threshold
                ),
                destination: format!("{}:{}", host, port),
                detected_at: now,
            };
            self.record_threat(threat.clone());
            return Some(threat);
        }

        None
    }

    /// Check a DNS query for exfiltration
    pub fn check_dns_query(&mut self, domain: &str, record_type: &str) -> Option<NetworkThreatEvent> {
        if !self.enabled {
            return None;
        }

        let result = self.dns_detector.analyze_query(domain, record_type);
        if let Some(ref threat) = result {
            self.record_threat(threat.clone());
        }
        result
    }

    /// Check if a process is listening on a port
    pub fn check_listener(&mut self, port: u16, process_name: &str) -> Option<NetworkThreatEvent> {
        if !self.enabled {
            return None;
        }

        // Common legitimate listeners
        let legitimate = ["sshd", "nginx", "httpd", "postgres", "mysql"];
        if legitimate.iter().any(|l| process_name.contains(l)) {
            return None;
        }

        if port < 1024 {
            let threat = NetworkThreatEvent {
                threat_type: NetworkThreatType::UnauthorizedListener,
                severity: AlertSeverity::Danger,
                detail: format!(
                    "Unauthorized privileged port listener: {} on port {}",
                    process_name, port
                ),
                destination: format!("0.0.0.0:{}", port),
                detected_at: Instant::now(),
            };
            self.record_threat(threat.clone());
            return Some(threat);
        }

        None
    }

    /// Get the whitelist (for configuration)
    pub fn whitelist_mut(&mut self) -> &mut ConnectionWhitelist {
        &mut self.whitelist
    }

    /// Get total threat count
    pub fn total_threats(&self) -> u64 {
        self.total_threats
    }

    /// Get recent threats
    pub fn recent_threats(&self, count: usize) -> Vec<&NetworkThreatEvent> {
        self.threats.iter().rev().take(count).collect()
    }

    /// Record a threat
    fn record_threat(&mut self, threat: NetworkThreatEvent) {
        self.total_threats += 1;
        self.threats.push(threat);
        // Keep last 500
        if self.threats.len() > 500 {
            self.threats.drain(..self.threats.len() - 500);
        }
    }

    /// Is monitoring enabled?
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }
}

impl Default for NetworkMonitor {
    fn default() -> Self {
        Self::new(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_whitelist_basic() {
        let whitelist = ConnectionWhitelist::default();
        assert!(whitelist.is_allowed("localhost", 80));
        assert!(whitelist.is_allowed("unknown.host", 443)); // Port whitelisted
        assert!(!whitelist.is_allowed("evil.com", 4444));
    }

    #[test]
    fn test_whitelist_custom_host() {
        let mut whitelist = ConnectionWhitelist::new(true);
        whitelist.allow_host("api.github.com");
        assert!(whitelist.is_allowed("api.github.com", 4444));
        assert!(whitelist.is_enforcing());
    }

    #[test]
    fn test_metadata_detection() {
        let mut monitor = NetworkMonitor::new(true);
        let threat = monitor.check_connection("169.254.169.254", 80);
        assert!(threat.is_some());
        assert_eq!(threat.unwrap().threat_type, NetworkThreatType::MetadataServiceAccess);
    }

    #[test]
    fn test_suspicious_connection() {
        let mut monitor = NetworkMonitor::new(true);
        let threat = monitor.check_connection("evil.com", 4444);
        assert!(threat.is_some());
        assert_eq!(threat.unwrap().threat_type, NetworkThreatType::SuspiciousConnection);
    }

    #[test]
    fn test_dns_exfil_long_label() {
        let mut detector = DnsExfilDetector::new();
        let long_domain = format!("{}.evil.com", "a".repeat(50));
        let result = detector.analyze_query(&long_domain, "A");
        assert!(result.is_some());
        assert_eq!(result.unwrap().threat_type, NetworkThreatType::DnsExfiltration);
    }

    #[test]
    fn test_dns_normal_query() {
        let mut detector = DnsExfilDetector::new();
        let result = detector.analyze_query("www.google.com", "A");
        assert!(result.is_none());
    }

    #[test]
    fn test_listener_detection() {
        let mut monitor = NetworkMonitor::new(true);
        let threat = monitor.check_listener(80, "suspicious_process");
        assert!(threat.is_some());
        assert_eq!(threat.unwrap().threat_type, NetworkThreatType::UnauthorizedListener);
    }

    #[test]
    fn test_legitimate_listener() {
        let mut monitor = NetworkMonitor::new(true);
        let threat = monitor.check_listener(22, "sshd");
        assert!(threat.is_none());
    }

    #[test]
    fn test_monitor_disabled() {
        let mut monitor = NetworkMonitor::new(false);
        assert!(monitor.check_connection("evil.com", 4444).is_none());
        assert!(!monitor.is_enabled());
    }

    #[test]
    fn test_threat_counting() {
        let mut monitor = NetworkMonitor::new(true);
        monitor.check_connection("169.254.169.254", 80);
        monitor.check_connection("evil.com", 4444);
        assert_eq!(monitor.total_threats(), 2);
        assert_eq!(monitor.recent_threats(5).len(), 2);
    }
}
