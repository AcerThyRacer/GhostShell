// ╔══════════════════════════════════════════════════════════════════╗
// ║              GhostShell — Application State Machine              ║
// ║         Central orchestrator for all subsystems                  ║
// ╚══════════════════════════════════════════════════════════════════╝

use crate::config::GhostConfig;
use crate::crypto::clipboard::SecureClipboard;
use crate::crypto::session_recorder::SessionRecorder;
use crate::decoy::duress::{AuthResult, DuressAuth};
use crate::decoy::DecoySystem;
use crate::ids::alerts::AlertQueue;
use crate::ids::IdsEngine;
use crate::stealth::dead_man::DeadManSwitch;
use crate::stealth::scrollback::SecureScrollback;
use crate::terminal::input::{InputAction, InputMode};
use crate::terminal::layout::LayoutEngine;
use crate::terminal::pane::PaneManager;
use std::time::Instant;
use uuid::Uuid;
use zeroize::Zeroize;

/// Application operating mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppMode {
    /// Normal operation
    Normal,
    /// Stealth mode — minimal UI, maximum OpSec
    Stealth,
    /// Decoy mode — showing fake environment
    Decoy,
    /// Locked — requires re-authentication
    Locked,
    /// Command input mode
    Command,
    /// Panic — transitioning to decoy
    Panic,
}

/// Security clearance state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityState {
    /// Fully authenticated
    Authenticated,
    /// Locked out, needs password
    Locked,
    /// Under duress (decoy password entered)
    Duress,
    /// Unauthenticated
    Unauthenticated,
}

/// Central application state
pub struct GhostApp {
    pub config: GhostConfig,
    pub mode: AppMode,
    pub security_state: SecurityState,
    pub input_mode: InputMode,
    pub layout: LayoutEngine,
    pub panes: PaneManager,
    pub scrollbacks: Vec<SecureScrollback>,
    pub clipboard: SecureClipboard,
    pub recorder: Option<SessionRecorder>,
    pub ids_engine: IdsEngine,
    pub decoy_system: DecoySystem,
    pub dead_man: DeadManSwitch,
    pub alert_queue: AlertQueue,
    pub command_buffer: String,
    pub should_quit: bool,
    pub session_id: Uuid,
    pub last_activity: Instant,
    pub recording_active: bool,
    pub stealth_indicators: StealthIndicators,
    /// Whether animations and visual effects are enabled
    pub animations_enabled: bool,
    /// Whether the help screen is currently showing
    pub show_help: bool,
    /// Output messages from slash commands
    pub command_output: Vec<String>,
    /// Currently active visual effect (requires animations_enabled)
    pub active_effect: Option<String>,
    /// Duress-aware authentication system
    pub auth_system: Option<DuressAuth>,
    /// Safe mode: plugins, stealth, and complex features are disabled
    pub safe_mode: bool,
}

/// Current stealth status indicators for the status bar
#[derive(Debug, Clone)]
pub struct StealthIndicators {
    pub encrypted: bool,
    pub phantom: bool,
    pub decoy_active: bool,
    pub ids_active: bool,
    pub recording: bool,
    pub locked: bool,
    pub dead_man_armed: bool,
    pub tunnel_active: bool,
}

impl Default for StealthIndicators {
    fn default() -> Self {
        Self {
            encrypted: true,
            phantom: false,
            decoy_active: false,
            ids_active: true,
            recording: false,
            locked: false,
            dead_man_armed: false,
            tunnel_active: false,
        }
    }
}

impl GhostApp {
    /// Create a new application instance
    pub fn new(config: GhostConfig, safe_mode: bool) -> Self {
        let mut ids_config = config.ids.clone();
        if safe_mode {
            ids_config.enabled = false;
            ids_config.biometrics_enabled = false;
        }
        let ids_engine = IdsEngine::new(&ids_config);
        let decoy_system = DecoySystem::new(&config.decoy);
        let dead_man = DeadManSwitch::new(
            config.stealth.dead_man_timeout_seconds,
            &config.stealth.dead_man_action,
        );
        let clipboard = SecureClipboard::new(
            config.clipboard.auto_wipe_seconds,
            config.clipboard.max_paste_count,
        );

        let mode = if safe_mode {
            AppMode::Normal // Force normal mode in safe mode
        } else if config.general.stealth_mode {
            AppMode::Stealth
        } else {
            AppMode::Normal
        };

        Self {
            config: config.clone(),
            mode,
            security_state: SecurityState::Authenticated,
            input_mode: InputMode::Normal,
            layout: LayoutEngine::new(),
            panes: PaneManager::new(),
            scrollbacks: Vec::new(),
            clipboard,
            recorder: None,
            ids_engine,
            decoy_system,
            dead_man,
            alert_queue: AlertQueue::default(),
            command_buffer: String::new(),
            should_quit: false,
            session_id: Uuid::new_v4(),
            last_activity: Instant::now(),
            recording_active: false,
            stealth_indicators: StealthIndicators::default(),
            animations_enabled: false,
            show_help: false,
            command_output: Vec::new(),
            active_effect: None,
            auth_system: None,
            safe_mode,
        }
    }

    /// Process an input action from the keybind router
    pub fn handle_action(&mut self, action: InputAction) {
        self.last_activity = Instant::now();
        self.dead_man.reset();

        match action {
            InputAction::SplitHorizontal => {
                self.layout.split_horizontal();
                self.panes.create_pane(&self.config.general.shell);
            }
            InputAction::SplitVertical => {
                self.layout.split_vertical();
                self.panes.create_pane(&self.config.general.shell);
            }
            InputAction::FocusUp => self.layout.focus_up(),
            InputAction::FocusDown => self.layout.focus_down(),
            InputAction::FocusLeft => self.layout.focus_left(),
            InputAction::FocusRight => self.layout.focus_right(),
            InputAction::ClosePane => {
                if let Some(id) = self.layout.active_pane_id() {
                    self.panes.close_pane(id);
                    self.layout.remove_pane(id);
                }
            }
            InputAction::NewTab => {
                self.layout.new_tab();
                self.panes.create_pane(&self.config.general.shell);
            }
            InputAction::NextTab => self.layout.next_tab(),
            InputAction::PrevTab => self.layout.prev_tab(),
            InputAction::ToggleRecord => {
                self.recording_active = !self.recording_active;
                self.stealth_indicators.recording = self.recording_active;
                if self.recording_active {
                    self.recorder = Some(SessionRecorder::new(&self.config.crypto));
                } else {
                    if let Some(recorder) = self.recorder.take() {
                        recorder.finalize();
                    }
                }
            }
            InputAction::WipeScrollback => {
                for sb in &mut self.scrollbacks {
                    sb.wipe_now();
                }
            }
            InputAction::PanicSwitch => {
                self.trigger_panic();
            }
            InputAction::EnterCommand => {
                self.mode = AppMode::Command;
                self.input_mode = InputMode::Command;
                self.command_buffer.clear();
            }
            InputAction::ExecuteCommand => {
                let cmd = self.command_buffer.clone();
                self.execute_command(&cmd);
                self.command_buffer.clear();
                self.mode = AppMode::Normal;
            }
            InputAction::CommandChar(c) => {
                self.command_buffer.push(c);
            }
            InputAction::CommandBackspace => {
                self.command_buffer.pop();
            }
            InputAction::Quit => {
                self.should_quit = true;
            }
            InputAction::PassThrough(data) => {
                // Forward raw input to active pane
                if let Some(id) = self.layout.active_pane_id() {
                    self.panes.write_to_pane(id, &data);
                }
                // Feed command to IDS for analysis
                if self.config.ids.enabled {
                    let cmd = String::from_utf8_lossy(&data).to_string();
                    if let Some(alert) = self.ids_engine.analyze_command(&cmd) {
                        self.alert_queue.push(
                            alert.severity,
                            &alert.source,
                            &alert.message,
                            alert.action,
                        );
                    }
                }
            }
            InputAction::None => {}
        }
    }

    /// Trigger panic mode — switch to decoy immediately
    fn trigger_panic(&mut self) {
        // Wipe all scrollbacks
        for sb in &mut self.scrollbacks {
            sb.wipe_now();
        }

        // Clear clipboard
        self.clipboard.wipe();

        // Stop recording
        if let Some(recorder) = self.recorder.take() {
            recorder.secure_delete();
        }

        // Switch to decoy
        self.mode = AppMode::Decoy;
        self.stealth_indicators.decoy_active = true;
        self.decoy_system.activate();
    }

    /// Lock the session
    pub fn lock(&mut self) {
        self.mode = AppMode::Locked;
        self.security_state = SecurityState::Locked;
        self.stealth_indicators.locked = true;
    }

    /// Attempt authentication.
    /// SECURITY: Uses DuressAuth (Argon2id + constant-time comparison)
    /// when available. Returns false on invalid credentials.
    pub fn authenticate(&mut self, password: &str) -> bool {
        if let Some(ref mut auth) = self.auth_system {
            match auth.authenticate(password) {
                AuthResult::Authenticated => {
                    self.security_state = SecurityState::Authenticated;
                    self.mode = AppMode::Normal;
                    self.stealth_indicators.locked = false;
                    true
                }
                AuthResult::Duress => {
                    self.security_state = SecurityState::Duress;
                    self.mode = AppMode::Decoy;
                    self.stealth_indicators.locked = false;
                    self.stealth_indicators.decoy_active = true;
                    self.decoy_system.activate();
                    true // appear to unlock
                }
                AuthResult::LockedOut => {
                    tracing::warn!("Authentication locked out — too many failed attempts");
                    false
                }
                AuthResult::Failed => {
                    tracing::warn!("Authentication failed");
                    false
                }
            }
        } else {
            // No auth system configured — fail closed
            tracing::error!("No authentication system configured — denying access");
            false
        }
    }

    /// Check dead man's switch and return action if triggered
    pub fn check_dead_man(&mut self) -> Option<String> {
        if self.dead_man.is_triggered(self.last_activity) {
            let action = self.dead_man.action().to_string();
            match action.as_str() {
                "lock" => self.lock(),
                "wipe" => {
                    self.trigger_panic();
                    self.should_quit = true;
                }
                "exit" => {
                    self.should_quit = true;
                }
                _ => self.lock(),
            }
            Some(action)
        } else {
            None
        }
    }

    /// Apply a hot-reloaded config update (safe fields only)
    pub fn apply_config_update(&mut self, new_config: GhostConfig) {
        // Hot-reloadable: theme, keybindings, IDS sensitivity, scrollback
        self.config.theme = new_config.theme;
        self.config.keybindings = new_config.keybindings;
        self.config.ids.sensitivity = new_config.ids.sensitivity;
        self.config.scrollback = new_config.scrollback;

        tracing::info!("Config hot-reloaded (theme, keybindings, IDS, scrollback)");
    }

    /// Perform secure cleanup before exit
    pub fn secure_shutdown(&mut self) {
        // Wipe all scrollbacks
        for sb in &mut self.scrollbacks {
            sb.wipe_now();
        }

        // Clear clipboard
        self.clipboard.wipe();

        // Finalize or destroy recordings
        if let Some(recorder) = self.recorder.take() {
            if self.mode == AppMode::Panic {
                recorder.secure_delete();
            } else {
                recorder.finalize();
            }
        }

        // Close all panes
        self.panes.close_all();

        // Clear alerts (zeroize sensitive data)
        self.alert_queue.clear();
        // SECURITY: Zeroize command buffer — .clear() only sets len=0,
        // leaving the contents in freed heap memory.
        self.command_buffer.zeroize();
    }

    /// Execute a slash command from the command buffer
    pub fn execute_command(&mut self, cmd: &str) {
        let cmd = cmd.trim();

        // Dismiss help on any command
        if self.show_help && cmd != "/help" {
            self.show_help = false;
        }

        if cmd.is_empty() {
            return;
        }

        let parts: Vec<&str> = cmd.splitn(2, ' ').collect();
        let command = parts[0];
        let arg = parts.get(1).map(|s| s.trim()).unwrap_or("");

        match command {
            "/help" => {
                self.show_help = !self.show_help;
                self.command_output.clear();
            }
            "/animations" => {
                self.animations_enabled = !self.animations_enabled;
                if self.animations_enabled {
                    self.command_output = vec!["Animations enabled. Use /effects <name> to activate.".to_string()];
                } else {
                    self.active_effect = None;
                    self.command_output = vec!["Animations disabled.".to_string()];
                }
            }
            "/effects" => {
                if !self.animations_enabled {
                    self.command_output = vec!["Enable animations first with /animations".to_string()];
                } else if arg.is_empty() {
                    self.command_output = vec!["Usage: /effects <fog|matrix|glitch|static|rain|off>".to_string()];
                } else {
                    match arg {
                        "fog" | "matrix" | "glitch" | "static" | "rain" => {
                            self.active_effect = Some(arg.to_string());
                            self.command_output = vec![format!("Effect '{}' activated.", arg)];
                        }
                        "off" => {
                            self.active_effect = None;
                            self.command_output = vec!["Effects disabled.".to_string()];
                        }
                        _ => {
                            self.command_output = vec![format!("Unknown effect '{}'. Options: fog, matrix, glitch, static, rain, off", arg)];
                        }
                    }
                }
            }
            "/theme" => {
                if arg.is_empty() {
                    self.command_output = vec!["Usage: /theme <ghost|matrix|midnight|stealth|crimson>".to_string()];
                } else {
                    self.config.theme.scheme = arg.to_string();
                    self.command_output = vec![format!("Theme set to '{}'.", arg)];
                }
            }
            "/stealth" => {
                if self.mode == AppMode::Stealth {
                    self.mode = AppMode::Normal;
                    self.config.general.stealth_mode = false;
                    self.command_output = vec!["Stealth mode disabled.".to_string()];
                } else {
                    self.mode = AppMode::Stealth;
                    self.config.general.stealth_mode = true;
                    self.command_output = vec!["Stealth mode enabled.".to_string()];
                }
            }
            "/lock" => {
                self.lock();
                self.command_output.clear();
            }
            "/clear" => {
                self.command_output.clear();
                self.show_help = false;
            }
            "/quit" | "/exit" => {
                self.should_quit = true;
            }
            _ => {
                self.command_output = vec![format!("Unknown command '{}'. Type /help for available commands.", command)];
            }
        }
    }
}
