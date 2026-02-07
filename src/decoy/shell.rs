// ╔══════════════════════════════════════════════════════════════════╗
// ║              GhostShell — Decoy Shell                            ║
// ║         Fake shell environments with realistic output            ║
// ╚══════════════════════════════════════════════════════════════════╝

use crate::decoy::fake_history::FakeHistory;
use chrono::Local;
use std::collections::HashMap;

/// Pre-built decoy profiles
#[derive(Debug, Clone)]
pub enum DecoyProfile {
    Developer,
    SysAdmin,
    Casual,
    Custom(String),
}

impl DecoyProfile {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "developer" | "dev" => Self::Developer,
            "sysadmin" | "admin" => Self::SysAdmin,
            "casual" | "user" => Self::Casual,
            _ => Self::Custom(s.to_string()),
        }
    }
}

/// A fake shell environment
pub struct DecoyShell {
    profile: DecoyProfile,
    display_lines: Vec<String>,
    history: FakeHistory,
    fake_env: HashMap<String, String>,
    fake_cwd: String,
    username: String,
    hostname: String,
    command_count: usize,
}

impl DecoyShell {
    /// Create a new decoy shell with the given profile
    pub fn new(profile_name: &str) -> Self {
        let profile = DecoyProfile::from_str(profile_name);

        let (username, hostname, cwd, env) = match &profile {
            DecoyProfile::Developer => (
                "devuser".to_string(),
                "workstation".to_string(),
                "~/projects/webapp".to_string(),
                Self::developer_env(),
            ),
            DecoyProfile::SysAdmin => (
                "admin".to_string(),
                "prod-server-01".to_string(),
                "/var/log".to_string(),
                Self::sysadmin_env(),
            ),
            DecoyProfile::Casual => (
                "user".to_string(),
                "laptop".to_string(),
                "~".to_string(),
                Self::casual_env(),
            ),
            DecoyProfile::Custom(name) => (
                "user".to_string(),
                name.clone(),
                "~".to_string(),
                HashMap::new(),
            ),
        };

        Self {
            profile,
            display_lines: Vec::new(),
            history: FakeHistory::new(&profile_name),
            fake_env: env,
            fake_cwd: cwd,
            username,
            hostname,
            command_count: 0,
        }
    }

    fn developer_env() -> HashMap<String, String> {
        let mut env = HashMap::new();
        env.insert("EDITOR".to_string(), "vim".to_string());
        env.insert("NODE_ENV".to_string(), "development".to_string());
        env.insert("LANG".to_string(), "en_US.UTF-8".to_string());
        env.insert("TERM".to_string(), "xterm-256color".to_string());
        env.insert("PATH".to_string(), "/usr/local/bin:/usr/bin:/bin:/usr/local/go/bin".to_string());
        env.insert("GOPATH".to_string(), "/home/devuser/go".to_string());
        env.insert("NVM_DIR".to_string(), "/home/devuser/.nvm".to_string());
        env
    }

    fn sysadmin_env() -> HashMap<String, String> {
        let mut env = HashMap::new();
        env.insert("EDITOR".to_string(), "nano".to_string());
        env.insert("LANG".to_string(), "en_US.UTF-8".to_string());
        env.insert("TERM".to_string(), "xterm".to_string());
        env.insert("PATH".to_string(), "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_string());
        env.insert("SHELL".to_string(), "/bin/bash".to_string());
        env
    }

    fn casual_env() -> HashMap<String, String> {
        let mut env = HashMap::new();
        env.insert("LANG".to_string(), "en_US.UTF-8".to_string());
        env.insert("TERM".to_string(), "xterm-256color".to_string());
        env.insert("SHELL".to_string(), "/bin/bash".to_string());
        env
    }

    /// Initialize the decoy shell with a login prompt
    pub fn initialize(&mut self) {
        self.display_lines.clear();

        let now = Local::now();
        self.display_lines.push(format!(
            "Last login: {} on ttys001",
            now.format("%a %b %e %H:%M:%S %Y")
        ));
        self.display_lines.push(String::new());
        self.display_lines.push(self.prompt());
    }

    /// Generate the prompt string
    fn prompt(&self) -> String {
        match &self.profile {
            DecoyProfile::Developer => {
                format!(
                    "{}@{}:{} (main) $ ",
                    self.username, self.hostname, self.fake_cwd
                )
            }
            DecoyProfile::SysAdmin => {
                format!(
                    "[{}@{} {}]# ",
                    self.username,
                    self.hostname,
                    self.fake_cwd.rsplit('/').next().unwrap_or(&self.fake_cwd)
                )
            }
            DecoyProfile::Casual => {
                format!("{}@{}:{}$ ", self.username, self.hostname, self.fake_cwd)
            }
            DecoyProfile::Custom(_) => {
                format!("$ ")
            }
        }
    }

    /// Execute a command in the decoy environment
    pub fn execute_command(&mut self, cmd: &str) -> Vec<String> {
        self.command_count += 1;
        let mut output = Vec::new();

        let parts: Vec<&str> = cmd.trim().split_whitespace().collect();
        if parts.is_empty() {
            output.push(self.prompt());
            return output;
        }

        match parts[0] {
            "ls" | "dir" => output.extend(self.fake_ls(&parts)),
            "pwd" => output.push(self.fake_cwd.clone()),
            "whoami" => output.push(self.username.clone()),
            "hostname" => output.push(self.hostname.clone()),
            "date" => output.push(Local::now().format("%a %b %e %H:%M:%S %Z %Y").to_string()),
            "uptime" => output.push(self.fake_uptime()),
            "uname" => output.push(self.fake_uname(&parts)),
            "cat" => output.extend(self.fake_cat(&parts)),
            "echo" => output.push(parts[1..].join(" ")),
            "cd" => {
                if let Some(dir) = parts.get(1) {
                    self.fake_cwd = dir.to_string();
                }
            }
            "env" | "printenv" => {
                for (k, v) in &self.fake_env {
                    output.push(format!("{}={}", k, v));
                }
            }
            "history" => {
                output.extend(self.history.get_entries());
            }
            "ps" => output.extend(self.fake_ps()),
            "free" => output.extend(self.fake_free()),
            "df" => output.extend(self.fake_df()),
            "id" => output.push(self.fake_id()),
            "clear" => {
                self.display_lines.clear();
            }
            "exit" | "logout" => {
                output.push("logout".to_string());
            }
            _ => {
                output.push(format!("{}: command not found", parts[0]));
            }
        }

        self.display_lines.extend(output.clone());
        self.display_lines.push(self.prompt());
        output
    }

    /// Get current display lines
    pub fn get_display_lines(&self) -> Vec<String> {
        self.display_lines.clone()
    }

    fn fake_ls(&self, _parts: &[&str]) -> Vec<String> {
        match &self.profile {
            DecoyProfile::Developer => vec![
                "total 48".to_string(),
                "drwxr-xr-x  12 devuser devuser  4096 Feb  7 08:30 .".to_string(),
                "drwxr-xr-x   5 devuser devuser  4096 Feb  6 14:22 ..".to_string(),
                "drwxr-xr-x   8 devuser devuser  4096 Feb  7 08:30 .git".to_string(),
                "-rw-r--r--   1 devuser devuser   234 Feb  5 09:15 .gitignore".to_string(),
                "-rw-r--r--   1 devuser devuser  1847 Feb  6 16:33 README.md".to_string(),
                "-rw-r--r--   1 devuser devuser  2156 Feb  7 08:28 package.json".to_string(),
                "drwxr-xr-x   4 devuser devuser  4096 Feb  6 11:45 src".to_string(),
                "drwxr-xr-x   3 devuser devuser  4096 Feb  5 15:00 tests".to_string(),
                "drwxr-xr-x 842 devuser devuser 32768 Feb  6 11:45 node_modules".to_string(),
                "-rw-r--r--   1 devuser devuser   523 Feb  5 09:15 tsconfig.json".to_string(),
            ],
            DecoyProfile::SysAdmin => vec![
                "total 2048".to_string(),
                "-rw-r--r-- 1 root root   52428 Feb  7 08:45 auth.log".to_string(),
                "-rw-r--r-- 1 root root  128543 Feb  7 08:44 syslog".to_string(),
                "-rw-r--r-- 1 root root   15234 Feb  7 08:30 kern.log".to_string(),
                "-rw-r--r-- 1 root root  245678 Feb  6 23:59 daemon.log".to_string(),
                "-rw-r--r-- 1 root root    8432 Feb  7 08:00 cron.log".to_string(),
                "-rw-r--r-- 1 root root   34521 Feb  7 08:43 nginx/access.log".to_string(),
                "-rw-r--r-- 1 root root    2345 Feb  7 07:12 nginx/error.log".to_string(),
            ],
            _ => vec![
                "Desktop  Documents  Downloads  Music  Pictures  Videos".to_string(),
            ],
        }
    }

    fn fake_uptime(&self) -> String {
        match &self.profile {
            DecoyProfile::SysAdmin => {
                " 08:50:58 up 47 days, 12:33,  2 users,  load average: 0.42, 0.38, 0.35".to_string()
            }
            _ => {
                " 08:50:58 up 3:22,  1 user,  load average: 0.15, 0.12, 0.08".to_string()
            }
        }
    }

    fn fake_uname(&self, parts: &[&str]) -> String {
        if parts.contains(&"-a") {
            "Linux workstation 6.1.0-17-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.69-1 (2023-12-30) x86_64 GNU/Linux".to_string()
        } else {
            "Linux".to_string()
        }
    }

    fn fake_cat(&self, parts: &[&str]) -> Vec<String> {
        if parts.len() < 2 {
            return vec!["cat: missing operand".to_string()];
        }
        match parts[1] {
            "/etc/hostname" => vec![self.hostname.clone()],
            "/etc/os-release" => vec![
                "NAME=\"Debian GNU/Linux\"".to_string(),
                "VERSION=\"12 (bookworm)\"".to_string(),
                "ID=debian".to_string(),
            ],
            _ => vec![format!("cat: {}: No such file or directory", parts[1])],
        }
    }

    fn fake_ps(&self) -> Vec<String> {
        vec![
            "  PID TTY          TIME CMD".to_string(),
            "12345 pts/0    00:00:00 bash".to_string(),
            "12378 pts/0    00:00:01 vim".to_string(),
            "12402 pts/0    00:00:00 ps".to_string(),
        ]
    }

    fn fake_free(&self) -> Vec<String> {
        vec![
            "              total        used        free      shared  buff/cache   available".to_string(),
            "Mem:       16384000     8234567     4123456      234567     4025977     7654321".to_string(),
            "Swap:       2097152      123456     1973696".to_string(),
        ]
    }

    fn fake_df(&self) -> Vec<String> {
        vec![
            "Filesystem     1K-blocks      Used Available Use% Mounted on".to_string(),
            "/dev/sda1      512000000 234567890 277432110  46% /".to_string(),
            "tmpfs            8192000         0   8192000   0% /dev/shm".to_string(),
            "/dev/sdb1     1024000000 567890123 456109877  56% /data".to_string(),
        ]
    }

    fn fake_id(&self) -> String {
        match &self.profile {
            DecoyProfile::SysAdmin => {
                "uid=0(root) gid=0(root) groups=0(root)".to_string()
            }
            _ => {
                format!(
                    "uid=1000({}) gid=1000({}) groups=1000({}),27(sudo)",
                    self.username, self.username, self.username
                )
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_developer_profile() {
        let mut shell = DecoyShell::new("developer");
        shell.initialize();
        assert!(!shell.get_display_lines().is_empty());
    }

    #[test]
    fn test_execute_command() {
        let mut shell = DecoyShell::new("sysadmin");
        shell.initialize();
        let output = shell.execute_command("whoami");
        assert!(output.contains(&"admin".to_string()));
    }

    #[test]
    fn test_fake_ls() {
        let mut shell = DecoyShell::new("developer");
        shell.initialize();
        let output = shell.execute_command("ls -la");
        assert!(!output.is_empty());
        assert!(output.iter().any(|l| l.contains("package.json")));
    }
}
