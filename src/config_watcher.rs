// ╔══════════════════════════════════════════════════════════════════╗
// ║              GhostShell — Config Hot-Reload Watcher              ║
// ║         Watches config.toml for changes, sends reload events    ║
// ╚══════════════════════════════════════════════════════════════════╝

use crate::config::GhostConfig;
use crate::error::GhostError;
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::path::{Path, PathBuf};
use std::sync::mpsc as std_mpsc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

/// Events emitted by the config watcher
#[derive(Debug)]
pub enum ConfigEvent {
    /// Config file was modified — new config parsed
    Reloaded(GhostConfig),
    /// Config file parse error (non-fatal)
    ParseError(String),
}

/// Watches the GhostShell config file for changes and emits reload events
pub struct ConfigWatcher {
    _watcher: RecommendedWatcher,
    config_path: PathBuf,
}

impl ConfigWatcher {
    /// Start watching the config file, sending events to the returned channel.
    /// Debounces rapid modifications (500ms window).
    pub fn start(config_path: PathBuf) -> Result<(Self, mpsc::Receiver<ConfigEvent>), GhostError> {
        let (tx, rx) = mpsc::channel::<ConfigEvent>(16);
        let watch_path = config_path.clone();

        // Use std::sync::mpsc for the notify callback (must be Sync)
        let (notify_tx, notify_rx) = std_mpsc::channel::<()>();

        let mut watcher = notify::recommended_watcher(
            move |result: Result<Event, notify::Error>| {
                if let Ok(event) = result {
                    match event.kind {
                        EventKind::Modify(_) | EventKind::Create(_) => {
                            let _ = notify_tx.send(());
                        }
                        _ => {}
                    }
                }
            },
        )
        .map_err(|e| GhostError::Config(format!("Failed to create file watcher: {}", e)))?;

        // Watch the config file's parent directory
        let watch_dir = config_path
            .parent()
            .unwrap_or(Path::new("."))
            .to_path_buf();

        watcher
            .watch(&watch_dir, RecursiveMode::NonRecursive)
            .map_err(|e| GhostError::Config(format!("Failed to watch directory: {}", e)))?;

        // Spawn debounce + reload task
        let reload_path = config_path.clone();
        let (signal_tx, mut signal_rx) = mpsc::channel::<()>(16);

        // Blocking task that receives from std mpsc and forwards to tokio mpsc
        tokio::task::spawn_blocking(move || {
            while notify_rx.recv().is_ok() {
                if signal_tx.blocking_send(()).is_err() {
                    break; // Receiver dropped
                }
            }
        });

        // Async task that debounces and reloads
        tokio::spawn(async move {
            let debounce = Duration::from_millis(500);
            let mut last_reload = Instant::now() - debounce;

            while signal_rx.recv().await.is_some() {
                // Debounce: skip if too recent
                if last_reload.elapsed() < debounce {
                    continue;
                }
                last_reload = Instant::now();

                // Small delay to let the write finish
                tokio::time::sleep(Duration::from_millis(100)).await;

                // Try to reload
                let path = reload_path.clone();
                match std::fs::read_to_string(&path) {
                    Ok(content) => match toml::from_str::<GhostConfig>(&content) {
                        Ok(config) => {
                            let _ = tx.send(ConfigEvent::Reloaded(config)).await;
                        }
                        Err(e) => {
                            let _ = tx
                                .send(ConfigEvent::ParseError(format!(
                                    "Config parse error: {}",
                                    e
                                )))
                                .await;
                        }
                    },
                    Err(e) => {
                        let _ = tx
                            .send(ConfigEvent::ParseError(format!(
                                "Failed to read config: {}",
                                e
                            )))
                            .await;
                    }
                }
            }
        });

        Ok((
            Self {
                _watcher: watcher,
                config_path,
            },
            rx,
        ))
    }

    /// Get the config path being watched
    pub fn config_path(&self) -> &Path {
        &self.config_path
    }

    /// Check if a given config change requires a restart
    pub fn requires_restart(old: &GhostConfig, new: &GhostConfig) -> bool {
        // Security-critical fields require restart
        old.crypto.cipher_algorithm != new.crypto.cipher_algorithm
            || old.stealth.process_cloak_name != new.stealth.process_cloak_name
            || old.general.shell != new.general.shell
            || old.network.listen_port != new.network.listen_port
    }
}

/// Fields that can be hot-reloaded without restart
#[derive(Debug, Clone)]
pub struct HotReloadableFields {
    pub theme_changed: bool,
    pub keybindings_changed: bool,
    pub ids_sensitivity_changed: bool,
    pub scrollback_changed: bool,
}

impl HotReloadableFields {
    /// Compare two configs and return which hot-reloadable fields changed
    pub fn diff(old: &GhostConfig, new: &GhostConfig) -> Self {
        Self {
            theme_changed: old.theme.name != new.theme.name,
            keybindings_changed: old.keybindings.prefix != new.keybindings.prefix,
            ids_sensitivity_changed: old.ids.sensitivity != new.ids.sensitivity,
            scrollback_changed: old.scrollback.buffer_size != new.scrollback.buffer_size,
        }
    }

    pub fn any_changed(&self) -> bool {
        self.theme_changed
            || self.keybindings_changed
            || self.ids_sensitivity_changed
            || self.scrollback_changed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hot_reload_diff_no_change() {
        let config = GhostConfig::default();
        let diff = HotReloadableFields::diff(&config, &config);
        assert!(!diff.any_changed());
    }

    #[test]
    fn test_hot_reload_diff_theme_change() {
        let old = GhostConfig::default();
        let mut new = old.clone();
        new.theme.name = "dracula".to_string();
        let diff = HotReloadableFields::diff(&old, &new);
        assert!(diff.theme_changed);
        assert!(diff.any_changed());
    }

    #[test]
    fn test_requires_restart_shell_change() {
        let old = GhostConfig::default();
        let mut new = old.clone();
        new.general.shell = "/bin/zsh".to_string();
        assert!(ConfigWatcher::requires_restart(&old, &new));
    }

    #[test]
    fn test_no_restart_for_theme_change() {
        let old = GhostConfig::default();
        let mut new = old.clone();
        new.theme.name = "gruvbox".to_string();
        assert!(!ConfigWatcher::requires_restart(&old, &new));
    }
}
