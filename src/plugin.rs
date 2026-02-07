// ╔══════════════════════════════════════════════════════════════════╗
// ║              GhostShell — Plugin / Extension System              ║
// ║         Trait-based plugin architecture with lifecycle hooks     ║
// ╚══════════════════════════════════════════════════════════════════╝

use crate::error::GhostError;
use std::collections::HashMap;

/// Response from a plugin command handler
#[derive(Debug, Clone)]
pub enum PluginResponse {
    /// Plugin handled the command, display this output
    Output(String),
    /// Plugin wants to suppress the command (don't forward to PTY)
    Suppress,
    /// Plugin didn't handle this command
    Ignored,
}

/// Context passed to plugins for safe, scoped access to app state
#[derive(Debug)]
pub struct PluginContext {
    /// Current session ID
    pub session_id: String,
    /// Application version
    pub app_version: String,
    /// Current mode (Normal, Stealth, Decoy, etc.)
    pub mode: String,
    /// Number of active panes
    pub pane_count: usize,
}

/// Trait that all GhostShell plugins must implement
pub trait GhostPlugin: Send {
    /// Plugin name (must be unique)
    fn name(&self) -> &str;

    /// Plugin version string
    fn version(&self) -> &str;

    /// Plugin description
    fn description(&self) -> &str;

    /// Called when the plugin is loaded
    fn on_init(&mut self, _ctx: &PluginContext) -> Result<(), GhostError> {
        Ok(())
    }

    /// Called for each command entered. Return PluginResponse to indicate handling.
    fn on_command(&mut self, cmd: &str, ctx: &PluginContext) -> PluginResponse {
        let _ = (cmd, ctx);
        PluginResponse::Ignored
    }

    /// Called on each tick of the event loop (for background work)
    fn on_tick(&mut self, _ctx: &PluginContext) {}

    /// Called when the plugin is being unloaded
    fn on_shutdown(&mut self) {}
}

/// Registry that manages all loaded plugins
pub struct PluginRegistry {
    plugins: HashMap<String, Box<dyn GhostPlugin>>,
    load_order: Vec<String>,
}

impl PluginRegistry {
    pub fn new() -> Self {
        Self {
            plugins: HashMap::new(),
            load_order: Vec::new(),
        }
    }

    /// Register a plugin. Returns error if name already taken.
    pub fn register(&mut self, plugin: Box<dyn GhostPlugin>) -> Result<(), GhostError> {
        let name = plugin.name().to_string();
        if self.plugins.contains_key(&name) {
            return Err(GhostError::Plugin(format!(
                "Plugin '{}' already registered",
                name
            )));
        }
        self.load_order.push(name.clone());
        self.plugins.insert(name, plugin);
        Ok(())
    }

    /// Initialize all registered plugins
    pub fn init_all(&mut self, ctx: &PluginContext) -> Vec<GhostError> {
        let mut errors = Vec::new();
        for name in &self.load_order {
            if let Some(plugin) = self.plugins.get_mut(name) {
                if let Err(e) = plugin.on_init(ctx) {
                    tracing::warn!("Plugin '{}' init failed: {}", name, e);
                    errors.push(e);
                } else {
                    tracing::info!("Plugin '{}' v{} loaded", name, plugin.version());
                }
            }
        }
        errors
    }

    /// Route a command to all plugins, return first non-Ignored response
    pub fn route_command(&mut self, cmd: &str, ctx: &PluginContext) -> PluginResponse {
        for name in &self.load_order {
            if let Some(plugin) = self.plugins.get_mut(name) {
                match plugin.on_command(cmd, ctx) {
                    PluginResponse::Ignored => continue,
                    response => return response,
                }
            }
        }
        PluginResponse::Ignored
    }

    /// Tick all plugins
    pub fn tick_all(&mut self, ctx: &PluginContext) {
        for name in &self.load_order {
            if let Some(plugin) = self.plugins.get_mut(name) {
                plugin.on_tick(ctx);
            }
        }
    }

    /// Shutdown all plugins in reverse order
    pub fn shutdown_all(&mut self) {
        for name in self.load_order.iter().rev() {
            if let Some(plugin) = self.plugins.get_mut(name) {
                plugin.on_shutdown();
                tracing::info!("Plugin '{}' shutdown", name);
            }
        }
    }

    /// Get number of loaded plugins
    pub fn count(&self) -> usize {
        self.plugins.len()
    }

    /// List all plugin names
    pub fn list(&self) -> Vec<(&str, &str)> {
        self.load_order
            .iter()
            .filter_map(|name| {
                self.plugins
                    .get(name)
                    .map(|p| (p.name(), p.version()))
            })
            .collect()
    }
}

impl Default for PluginRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ── Built-in Plugins ────────────────────────────────────────────────

/// Built-in version info plugin — responds to `:version` command
pub struct VersionPlugin;

impl GhostPlugin for VersionPlugin {
    fn name(&self) -> &str {
        "version"
    }

    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }

    fn description(&self) -> &str {
        "Built-in version info plugin"
    }

    fn on_command(&mut self, cmd: &str, _ctx: &PluginContext) -> PluginResponse {
        match cmd.trim() {
            ":version" | ":ver" => PluginResponse::Output(format!(
                "👻 GhostShell v{} — Stealth Terminal Multiplexer",
                env!("CARGO_PKG_VERSION")
            )),
            ":plugins" => PluginResponse::Output(
                "Use the plugin registry to list all loaded plugins.".to_string(),
            ),
            _ => PluginResponse::Ignored,
        }
    }
}

/// Built-in uptime plugin — responds to `:uptime` command
pub struct UptimePlugin {
    started_at: std::time::Instant,
}

impl UptimePlugin {
    pub fn new() -> Self {
        Self {
            started_at: std::time::Instant::now(),
        }
    }
}

impl Default for UptimePlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl GhostPlugin for UptimePlugin {
    fn name(&self) -> &str {
        "uptime"
    }

    fn version(&self) -> &str {
        "1.0.0"
    }

    fn description(&self) -> &str {
        "Shows session uptime"
    }

    fn on_command(&mut self, cmd: &str, _ctx: &PluginContext) -> PluginResponse {
        if cmd.trim() == ":uptime" {
            let elapsed = self.started_at.elapsed();
            let hours = elapsed.as_secs() / 3600;
            let mins = (elapsed.as_secs() % 3600) / 60;
            let secs = elapsed.as_secs() % 60;
            PluginResponse::Output(format!(
                "👻 Session uptime: {:02}:{:02}:{:02}",
                hours, mins, secs
            ))
        } else {
            PluginResponse::Ignored
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_context() -> PluginContext {
        PluginContext {
            session_id: "test-session".to_string(),
            app_version: "0.1.0".to_string(),
            mode: "Normal".to_string(),
            pane_count: 1,
        }
    }

    #[test]
    fn test_plugin_registry_lifecycle() {
        let mut registry = PluginRegistry::new();
        assert_eq!(registry.count(), 0);

        registry
            .register(Box::new(VersionPlugin))
            .expect("register failed");
        assert_eq!(registry.count(), 1);

        let ctx = test_context();
        let errors = registry.init_all(&ctx);
        assert!(errors.is_empty());

        registry.shutdown_all();
    }

    #[test]
    fn test_duplicate_plugin_error() {
        let mut registry = PluginRegistry::new();
        registry
            .register(Box::new(VersionPlugin))
            .expect("first register");
        let result = registry.register(Box::new(VersionPlugin));
        assert!(result.is_err());
    }

    #[test]
    fn test_version_plugin_command() {
        let mut plugin = VersionPlugin;
        let ctx = test_context();
        match plugin.on_command(":version", &ctx) {
            PluginResponse::Output(s) => assert!(s.contains("GhostShell")),
            _ => panic!("Expected Output response"),
        }
    }

    #[test]
    fn test_uptime_plugin() {
        let mut plugin = UptimePlugin::new();
        let ctx = test_context();
        match plugin.on_command(":uptime", &ctx) {
            PluginResponse::Output(s) => assert!(s.contains("uptime")),
            _ => panic!("Expected Output response"),
        }
    }

    #[test]
    fn test_command_routing() {
        let mut registry = PluginRegistry::new();
        registry.register(Box::new(VersionPlugin)).unwrap();
        registry.register(Box::new(UptimePlugin::new())).unwrap();

        let ctx = test_context();

        // Version command
        match registry.route_command(":version", &ctx) {
            PluginResponse::Output(s) => assert!(s.contains("GhostShell")),
            _ => panic!("Expected version output"),
        }

        // Unknown command → Ignored
        match registry.route_command(":unknown", &ctx) {
            PluginResponse::Ignored => {}
            _ => panic!("Expected Ignored"),
        }
    }

    #[test]
    fn test_plugin_list() {
        let mut registry = PluginRegistry::new();
        registry.register(Box::new(VersionPlugin)).unwrap();
        registry.register(Box::new(UptimePlugin::new())).unwrap();

        let list = registry.list();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].0, "version");
        assert_eq!(list[1].0, "uptime");
    }
}
