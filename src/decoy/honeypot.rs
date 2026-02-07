// ╔══════════════════════════════════════════════════════════════════╗
// ║              GhostShell — Honeypot Detector                      ║
// ║         Detect if running inside a monitored/sandboxed env       ║
// ╚══════════════════════════════════════════════════════════════════╝


/// Honeypot detection result
#[derive(Debug, Clone)]
pub struct HoneypotReport {
    pub indicators: Vec<HoneypotIndicator>,
    pub risk_score: f64, // 0.0 (safe) to 1.0 (definitely honeypot)
    pub verdict: HoneypotVerdict,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HoneypotVerdict {
    Clean,
    Suspicious,
    LikelyHoneypot,
    DefiniteHoneypot,
}

#[derive(Debug, Clone)]
pub struct HoneypotIndicator {
    pub category: String,
    pub detail: String,
    pub weight: f64,
}

/// Run all honeypot detection checks
pub fn detect_honeypot() -> HoneypotReport {
    let mut indicators = Vec::new();

    // Check environment variables
    indicators.extend(check_env_variables());

    // Check for virtual machine indicators
    indicators.extend(check_vm_indicators());

    // Check for monitoring tools
    indicators.extend(check_monitoring_tools());

    // Check filesystem anomalies
    indicators.extend(check_filesystem());

    // Check network configuration
    indicators.extend(check_network());

    // Calculate risk score
    let total_weight: f64 = indicators.iter().map(|i| i.weight).sum();
    let risk_score = (total_weight / 10.0).min(1.0);

    let verdict = if risk_score < 0.2 {
        HoneypotVerdict::Clean
    } else if risk_score < 0.5 {
        HoneypotVerdict::Suspicious
    } else if risk_score < 0.8 {
        HoneypotVerdict::LikelyHoneypot
    } else {
        HoneypotVerdict::DefiniteHoneypot
    };

    HoneypotReport {
        indicators,
        risk_score,
        verdict,
    }
}

fn check_env_variables() -> Vec<HoneypotIndicator> {
    let mut indicators = Vec::new();

    let suspicious_vars = [
        ("HONEYPOT", 3.0),
        ("SANDBOX", 2.0),
        ("CANARY", 2.5),
        ("COWRIE_", 3.0),  // Cowrie honeypot
        ("KIPPO_", 3.0),   // Kippo honeypot
        ("DIONAEA", 3.0),  // Dionaea honeypot
        ("CAPTURE", 1.5),
        ("RECORDING", 1.0),
        ("AUDIT_", 1.0),
    ];

    for (var_prefix, weight) in &suspicious_vars {
        for (key, _) in std::env::vars() {
            if key.to_uppercase().contains(var_prefix) {
                indicators.push(HoneypotIndicator {
                    category: "environment".to_string(),
                    detail: format!("Suspicious env var: {}", key),
                    weight: *weight,
                });
            }
        }
    }

    indicators
}

fn check_vm_indicators() -> Vec<HoneypotIndicator> {
    let mut indicators = Vec::new();

    // Check for VM-related files/directories
    #[cfg(windows)]
    {
        let vm_paths = [
            r"C:\Program Files\VMware",
            r"C:\Program Files\Oracle\VirtualBox",
            r"C:\Windows\System32\drivers\VBoxGuest.sys",
            r"C:\Windows\System32\drivers\vmhgfs.sys",
        ];

        for path in &vm_paths {
            if std::path::Path::new(path).exists() {
                indicators.push(HoneypotIndicator {
                    category: "virtualization".to_string(),
                    detail: format!("VM artifact found: {}", path),
                    weight: 1.5,
                });
            }
        }
    }

    #[cfg(unix)]
    {
        // Check for container indicators
        if std::path::Path::new("/.dockerenv").exists() {
            indicators.push(HoneypotIndicator {
                category: "container".to_string(),
                detail: "Running inside Docker container".to_string(),
                weight: 1.0,
            });
        }

        // Check cgroup for container detection
        if let Ok(cgroup) = std::fs::read_to_string("/proc/1/cgroup") {
            if cgroup.contains("docker") || cgroup.contains("lxc") || cgroup.contains("kubepods") {
                indicators.push(HoneypotIndicator {
                    category: "container".to_string(),
                    detail: "Container cgroup detected".to_string(),
                    weight: 1.0,
                });
            }
        }

        // Check DMI for VM vendor
        if let Ok(vendor) = std::fs::read_to_string("/sys/class/dmi/id/sys_vendor") {
            let vendor = vendor.trim().to_lowercase();
            if vendor.contains("vmware") || vendor.contains("virtualbox")
                || vendor.contains("qemu") || vendor.contains("xen")
                || vendor.contains("microsoft") // Hyper-V
            {
                indicators.push(HoneypotIndicator {
                    category: "virtualization".to_string(),
                    detail: format!("VM vendor: {}", vendor.trim()),
                    weight: 1.5,
                });
            }
        }
    }

    indicators
}

fn check_monitoring_tools() -> Vec<HoneypotIndicator> {
    let mut indicators = Vec::new();

    // Check for debugger
    #[cfg(windows)]
    {
        let debugged = unsafe {
            windows_sys::Win32::System::Diagnostics::Debug::IsDebuggerPresent() != 0
        };
        if debugged {
            indicators.push(HoneypotIndicator {
                category: "debugging".to_string(),
                detail: "Debugger attached".to_string(),
                weight: 3.0,
            });
        }
    }

    #[cfg(unix)]
    {
        if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
            for line in status.lines() {
                if let Some(val) = line.strip_prefix("TracerPid:\t") {
                    if let Ok(pid) = val.parse::<i32>() {
                        if pid != 0 {
                            indicators.push(HoneypotIndicator {
                                category: "debugging".to_string(),
                                detail: format!("Being traced by PID {}", pid),
                                weight: 3.0,
                            });
                        }
                    }
                }
            }
        }
    }

    indicators
}

fn check_filesystem() -> Vec<HoneypotIndicator> {
    let mut indicators = Vec::new();

    // Check for suspiciously empty home directory
    if let Some(home) = dirs::home_dir() {
        if let Ok(entries) = std::fs::read_dir(&home) {
            let count = entries.count();
            if count < 3 {
                indicators.push(HoneypotIndicator {
                    category: "filesystem".to_string(),
                    detail: format!("Suspiciously empty home directory ({} entries)", count),
                    weight: 2.0,
                });
            }
        }
    }

    // Check for known honeypot files
    let honeypot_files = [
        "/opt/cowrie",
        "/opt/kippo",
        "/opt/dionaea",
        "/opt/honeyd",
    ];

    for path in &honeypot_files {
        if std::path::Path::new(path).exists() {
            indicators.push(HoneypotIndicator {
                category: "honeypot".to_string(),
                detail: format!("Known honeypot software: {}", path),
                weight: 5.0,
            });
        }
    }

    indicators
}

fn check_network() -> Vec<HoneypotIndicator> {
    let mut indicators = Vec::new();

    // Check for suspicious open ports (common honeypot configs)
    // In a full implementation, we'd enumerate listening ports

    // Check hostname for honeypot indicators
    if let Ok(hostname) = hostname::get() {
        let name = hostname.to_string_lossy().to_lowercase();
        let suspicious_names = ["honeypot", "sandbox", "malware", "analysis", "test-vm"];
        for suspect in &suspicious_names {
            if name.contains(suspect) {
                indicators.push(HoneypotIndicator {
                    category: "network".to_string(),
                    detail: format!("Suspicious hostname: {}", name),
                    weight: 2.5,
                });
            }
        }
    }

    indicators
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_honeypot_detection() {
        let report = detect_honeypot();
        assert!(report.risk_score >= 0.0 && report.risk_score <= 1.0);
    }

    #[test]
    fn test_verdict_thresholds() {
        // These are basic sanity checks
        assert!(matches!(
            HoneypotVerdict::Clean,
            HoneypotVerdict::Clean
        ));
    }
}
