// ╔══════════════════════════════════════════════════════════════════╗
// ║              GhostShell — Fake History                           ║
// ║         Believable shell command history for decoy profiles      ║
// ╚══════════════════════════════════════════════════════════════════╝

/// Fake command history generator
pub struct FakeHistory {
    entries: Vec<String>,
}

impl FakeHistory {
    /// Generate fake history based on profile
    pub fn new(profile: &str) -> Self {
        let entries = match profile.to_lowercase().as_str() {
            "developer" | "dev" => Self::developer_history(),
            "sysadmin" | "admin" => Self::sysadmin_history(),
            "casual" | "user" => Self::casual_history(),
            _ => Self::developer_history(),
        };

        Self { entries }
    }

    /// Get all history entries
    pub fn get_entries(&self) -> Vec<String> {
        self.entries
            .iter()
            .enumerate()
            .map(|(i, cmd)| format!("  {}  {}", i + 1, cmd))
            .collect()
    }

    fn developer_history() -> Vec<String> {
        vec![
            "git status".to_string(),
            "git pull origin main".to_string(),
            "npm install".to_string(),
            "npm run dev".to_string(),
            "vim src/components/Dashboard.tsx".to_string(),
            "npm test".to_string(),
            "git add -A".to_string(),
            "git commit -m \"fix: resolve layout issue on mobile\"".to_string(),
            "git push origin feature/mobile-fix".to_string(),
            "docker compose up -d".to_string(),
            "curl -s http://localhost:3000/api/health | jq .".to_string(),
            "npm run lint".to_string(),
            "git log --oneline -10".to_string(),
            "code .".to_string(),
            "npm run build".to_string(),
            "cat .env.local".to_string(),
            "ssh dev-server".to_string(),
            "git checkout -b feature/auth-refactor".to_string(),
            "npm run test:coverage".to_string(),
            "ls -la src/".to_string(),
        ]
    }

    fn sysadmin_history() -> Vec<String> {
        vec![
            "systemctl status nginx".to_string(),
            "tail -f /var/log/syslog".to_string(),
            "df -h".to_string(),
            "free -m".to_string(),
            "top -bn1 | head -20".to_string(),
            "journalctl -u postgresql --since '1 hour ago'".to_string(),
            "certbot renew --dry-run".to_string(),
            "ufw status verbose".to_string(),
            "ss -tlnp".to_string(),
            "cat /etc/nginx/sites-enabled/default".to_string(),
            "systemctl restart postgresql".to_string(),
            "apt update && apt upgrade -y".to_string(),
            "last -10".to_string(),
            "grep 'Failed password' /var/log/auth.log | tail -20".to_string(),
            "crontab -l".to_string(),
            "du -sh /var/log/*".to_string(),
            "iptables -L -n".to_string(),
            "htop".to_string(),
            "rsync -avz /data/ backup-server:/backup/".to_string(),
            "dmesg | tail".to_string(),
        ]
    }

    fn casual_history() -> Vec<String> {
        vec![
            "ls".to_string(),
            "cd Downloads".to_string(),
            "pwd".to_string(),
            "cat notes.txt".to_string(),
            "mkdir new-folder".to_string(),
            "cp document.pdf ~/Documents/".to_string(),
            "clear".to_string(),
            "date".to_string(),
            "whoami".to_string(),
            "ping google.com -c 4".to_string(),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_developer_history() {
        let history = FakeHistory::new("developer");
        let entries = history.get_entries();
        assert!(!entries.is_empty());
        assert!(entries.iter().any(|e| e.contains("git")));
    }

    #[test]
    fn test_sysadmin_history() {
        let history = FakeHistory::new("sysadmin");
        let entries = history.get_entries();
        assert!(entries.iter().any(|e| e.contains("systemctl")));
    }
}
