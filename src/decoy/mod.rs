// ╔══════════════════════════════════════════════════════════════════╗
// ║              GhostShell — Decoy Module                           ║
// ╚══════════════════════════════════════════════════════════════════╝

pub mod duress;
pub mod fake_history;
pub mod honeypot;
pub mod panic_key;
pub mod shell;

use crate::config::DecoyConfig;

/// The decoy system manager
pub struct DecoySystem {
    pub active: bool,
    pub profile: String,
    pub shell: shell::DecoyShell,
    // SECURITY: No `duress_enabled` boolean — storing it would reveal
    // whether duress mode is configured, undermining deniability.
}

impl DecoySystem {
    /// Create a new decoy system
    pub fn new(config: &DecoyConfig) -> Self {
        Self {
            active: false,
            profile: config.default_profile.clone(),
            shell: shell::DecoyShell::new(&config.default_profile),
        }
    }

    /// Activate the decoy environment
    pub fn activate(&mut self) {
        self.active = true;
        self.shell.initialize();
    }

    /// Deactivate the decoy
    pub fn deactivate(&mut self) {
        self.active = false;
    }

    /// Get the visible content for the decoy display
    pub fn get_visible_content(&self) -> Vec<String> {
        if self.active {
            self.shell.get_display_lines()
        } else {
            vec!["Decoy system inactive.".to_string()]
        }
    }

    /// Process a command in the decoy environment
    pub fn process_command(&mut self, cmd: &str) -> Vec<String> {
        if self.active {
            self.shell.execute_command(cmd)
        } else {
            vec!["Error: decoy not active".to_string()]
        }
    }
}
