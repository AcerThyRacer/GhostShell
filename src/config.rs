// ╔══════════════════════════════════════════════════════════════════╗
// ║              GhostShell — Configuration Manager                 ║
// ║         Loads, merges, and validates all settings                ║
// ╚══════════════════════════════════════════════════════════════════╝

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use crate::audit::AuditConfig;

/// Top-level configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GhostConfig {
    #[serde(default)]
    pub general: GeneralConfig,
    #[serde(default)]
    pub keybindings: KeybindingConfig,
    #[serde(default)]
    pub crypto: CryptoConfig,
    #[serde(default)]
    pub clipboard: ClipboardConfig,
    #[serde(default)]
    pub scrollback: ScrollbackConfig,
    #[serde(default)]
    pub stealth: StealthConfig,
    #[serde(default)]
    pub decoy: DecoyConfig,
    #[serde(default)]
    pub ids: IdsConfig,
    #[serde(default)]
    pub network: NetworkConfig,
    #[serde(default)]
    pub theme: ThemeConfig,
    #[serde(default)]
    pub audit: AuditConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneralConfig {
    pub shell: String,
    pub log_level: String,
    pub stealth_mode: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeybindingConfig {
    pub prefix: String,
    pub split_horizontal: String,
    pub split_vertical: String,
    pub pane_up: String,
    pub pane_down: String,
    pub pane_left: String,
    pub pane_right: String,
    pub close_pane: String,
    pub new_tab: String,
    pub next_tab: String,
    pub prev_tab: String,
    pub command_mode: String,
    pub panic_key: String,
    pub toggle_record: String,
    pub wipe_scrollback: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoConfig {
    pub argon2_memory_kib: u32,
    pub argon2_iterations: u32,
    pub argon2_parallelism: u32,
    pub session_encryption: bool,
    pub session_extension: String,
    #[serde(default = "default_cipher_algorithm")]
    pub cipher_algorithm: String,
    /// Enable hybrid post-quantum key exchange (X25519 + Kyber768)
    #[serde(default)]
    pub pq_hybrid: bool,
    /// Key rotation interval in seconds (0 = disable time-based rotation)
    #[serde(default = "default_key_rotation_interval")]
    pub key_rotation_interval_secs: u64,
    /// Max messages before forcing key rotation (0 = no limit)
    #[serde(default = "default_max_messages_before_rekey")]
    pub max_messages_before_rekey: u64,
    /// Enable zstd compression for session recordings
    #[serde(default = "default_recording_compression")]
    pub recording_compression: bool,
}

fn default_cipher_algorithm() -> String {
    "chacha20-poly1305".to_string()
}

fn default_key_rotation_interval() -> u64 {
    3600
}

fn default_max_messages_before_rekey() -> u64 {
    1_000_000
}

fn default_recording_compression() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClipboardConfig {
    pub auto_wipe_seconds: u64,
    pub max_paste_count: u32,
    pub use_system_clipboard: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScrollbackConfig {
    pub buffer_size: usize,
    pub wipe_on_close: bool,
    pub wipe_passes: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StealthConfig {
    pub process_cloak_enabled: bool,
    pub process_cloak_name: String,
    pub dead_man_timeout_seconds: u64,
    pub dead_man_action: String,
    pub clean_on_exit: bool,
    pub phantom_mode: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecoyConfig {
    pub enabled: bool,
    pub default_profile: String,
    // SECURITY: Duress password is NOT stored in config. Storing it here
    // in plaintext would reveal that duress mode exists, completely
    // undermining the deniability design. The duress password is instead
    // derived from the primary password at runtime (see decoy/duress.rs).
    #[serde(skip)]
    pub duress_suffix: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdsConfig {
    pub enabled: bool,
    pub anomaly_threshold: f64,
    pub biometrics_enabled: bool,
    pub biometrics_samples: usize,
    pub signature_matching: bool,
    pub exfil_detection: bool,
    pub privesc_detection: bool,
    #[serde(default)]
    pub responses: IdsResponseConfig,
    #[serde(default = "default_sensitivity")]
    pub sensitivity: f64,
    #[serde(default = "default_biometric_threshold")]
    pub biometric_confidence_threshold: f64,
    #[serde(default = "default_biometric_action")]
    pub biometric_action: String,
    #[serde(default = "default_alert_correlation_window")]
    pub alert_correlation_window_secs: u64,
    #[serde(default = "default_network_monitoring")]
    pub network_monitoring: bool,
}

fn default_sensitivity() -> f64 {
    0.7
}

fn default_biometric_threshold() -> f64 {
    0.6
}

fn default_biometric_action() -> String {
    "warn".to_string()
}

fn default_alert_correlation_window() -> u64 {
    300
}

fn default_network_monitoring() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdsResponseConfig {
    pub info: String,
    pub warn: String,
    pub critical: String,
    pub panic: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    pub tunnel_enabled: bool,
    pub listen_address: String,
    #[serde(default = "default_listen_port")]
    pub listen_port: u16,
    pub obfuscation: bool,
    pub socks5_proxy: String,
}

fn default_listen_port() -> u16 {
    7331
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThemeConfig {
    pub scheme: String,
    /// Theme name alias (for hot-reload detection)
    #[serde(default)]
    pub name: String,
    pub status_bar: String,
    pub show_indicators: bool,
    pub border_style: String,
    pub transparent: bool,
}

// ── Defaults ──────────────────────────────────────────────────────

impl Default for GeneralConfig {
    fn default() -> Self {
        Self {
            shell: if cfg!(windows) {
                "pwsh".to_string()
            } else {
                "/bin/bash".to_string()
            },
            log_level: "info".to_string(),
            stealth_mode: false,
        }
    }
}

impl Default for KeybindingConfig {
    fn default() -> Self {
        Self {
            prefix: "Ctrl-g".to_string(),
            split_horizontal: "Ctrl-g h".to_string(),
            split_vertical: "Ctrl-g v".to_string(),
            pane_up: "Ctrl-g Up".to_string(),
            pane_down: "Ctrl-g Down".to_string(),
            pane_left: "Ctrl-g Left".to_string(),
            pane_right: "Ctrl-g Right".to_string(),
            close_pane: "Ctrl-g x".to_string(),
            new_tab: "Ctrl-g t".to_string(),
            next_tab: "Ctrl-g n".to_string(),
            prev_tab: "Ctrl-g p".to_string(),
            command_mode: "Ctrl-g :".to_string(),
            panic_key: "Ctrl-g Ctrl-g Ctrl-g".to_string(),
            toggle_record: "Ctrl-g r".to_string(),
            wipe_scrollback: "Ctrl-g w".to_string(),
        }
    }
}

impl Default for CryptoConfig {
    fn default() -> Self {
        Self {
            argon2_memory_kib: 65536,
            argon2_iterations: 3,
            argon2_parallelism: 4,
            session_encryption: true,
            session_extension: ".ghost".to_string(),
            cipher_algorithm: "chacha20-poly1305".to_string(),
            pq_hybrid: false,
            key_rotation_interval_secs: 3600,
            max_messages_before_rekey: 1_000_000,
            recording_compression: true,
        }
    }
}

impl Default for ClipboardConfig {
    fn default() -> Self {
        Self {
            auto_wipe_seconds: 30,
            max_paste_count: 5,
            use_system_clipboard: false,
        }
    }
}

impl Default for ScrollbackConfig {
    fn default() -> Self {
        Self {
            buffer_size: 1000,
            wipe_on_close: true,
            wipe_passes: 3,
        }
    }
}

impl Default for StealthConfig {
    fn default() -> Self {
        Self {
            process_cloak_enabled: true,
            process_cloak_name: "bash".to_string(),
            dead_man_timeout_seconds: 900,
            dead_man_action: "lock".to_string(),
            clean_on_exit: true,
            phantom_mode: false,
        }
    }
}

impl Default for DecoyConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            default_profile: "developer".to_string(),
            duress_suffix: "!".to_string(),
        }
    }
}

impl Default for IdsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            anomaly_threshold: 0.7,
            biometrics_enabled: true,
            biometrics_samples: 100,
            signature_matching: true,
            exfil_detection: true,
            privesc_detection: true,
            responses: IdsResponseConfig::default(),
            sensitivity: 0.7,
            biometric_confidence_threshold: 0.6,
            biometric_action: "warn".to_string(),
            alert_correlation_window_secs: 300,
            network_monitoring: true,
        }
    }
}

impl Default for IdsResponseConfig {
    fn default() -> Self {
        Self {
            info: "log".to_string(),
            warn: "notify".to_string(),
            critical: "lock".to_string(),
            panic: "wipe".to_string(),
        }
    }
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            tunnel_enabled: false,
            listen_address: "127.0.0.1:7331".to_string(),
            listen_port: 7331,
            obfuscation: true,
            socks5_proxy: String::new(),
        }
    }
}

impl Default for ThemeConfig {
    fn default() -> Self {
        Self {
            scheme: "ghost".to_string(),
            name: String::new(),
            status_bar: "bottom".to_string(),
            show_indicators: true,
            border_style: "rounded".to_string(),
            transparent: false,
        }
    }
}

impl Default for GhostConfig {
    fn default() -> Self {
        Self {
            general: GeneralConfig::default(),
            keybindings: KeybindingConfig::default(),
            crypto: CryptoConfig::default(),
            clipboard: ClipboardConfig::default(),
            scrollback: ScrollbackConfig::default(),
            stealth: StealthConfig::default(),
            decoy: DecoyConfig::default(),
            ids: IdsConfig::default(),
            network: NetworkConfig::default(),
            theme: ThemeConfig::default(),
            audit: AuditConfig::default(),
        }
    }
}

// ── Loading ───────────────────────────────────────────────────────

impl GhostConfig {
    /// Load configuration from default paths, merging with defaults
    pub fn load() -> Self {
        // Try user config first
        let config_path = Self::config_path();
        if config_path.exists() {
            if let Ok(content) = std::fs::read_to_string(&config_path) {
                if let Ok(config) = toml::from_str::<GhostConfig>(&content) {
                    return config;
                }
            }
        }

        // Try bundled default config
        let default_content = include_str!("../config/default.toml");
        toml::from_str(default_content).unwrap_or_default()
    }

    /// Get the config file path (~/.ghostshell/config.toml)
    pub fn config_path() -> PathBuf {
        let base = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
        base.join(".ghostshell").join("config.toml")
    }

    /// Get the data directory (~/.ghostshell/)
    pub fn data_dir() -> PathBuf {
        let base = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
        let dir = base.join(".ghostshell");
        let _ = std::fs::create_dir_all(&dir);
        dir
    }

    /// Get the sessions directory
    pub fn sessions_dir() -> PathBuf {
        let dir = Self::data_dir().join("sessions");
        let _ = std::fs::create_dir_all(&dir);
        dir
    }

    /// Get the recordings directory
    pub fn recordings_dir() -> PathBuf {
        let dir = Self::data_dir().join("recordings");
        let _ = std::fs::create_dir_all(&dir);
        dir
    }

    /// Save current config to file
    pub fn save(&self) -> std::io::Result<()> {
        let path = Self::config_path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let content = toml::to_string_pretty(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        std::fs::write(path, content)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = GhostConfig::default();
        assert_eq!(config.crypto.argon2_iterations, 3);
        assert_eq!(config.ids.anomaly_threshold, 0.7);
        assert!(config.stealth.process_cloak_enabled);
    }

    #[test]
    fn test_config_serialization() {
        let config = GhostConfig::default();
        let serialized = toml::to_string_pretty(&config).unwrap();
        let deserialized: GhostConfig = toml::from_str(&serialized).unwrap();
        assert_eq!(config.crypto.argon2_memory_kib, deserialized.crypto.argon2_memory_kib);
    }
}
