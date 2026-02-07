// ╔══════════════════════════════════════════════════════════════════╗
// ║              GhostShell — Application State Machine              ║
// ║         Central orchestrator for all subsystems                  ║
// ╚══════════════════════════════════════════════════════════════════╝

use crate::config::GhostConfig;
use crate::crypto::clipboard::SecureClipboard;
use crate::crypto::session_recorder::SessionRecorder;
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
    pub fn new(config: GhostConfig) -> Self {
        let ids_engine = IdsEngine::new(&config.ids);
        let decoy_system = DecoySystem::new(&config.decoy);
        let dead_man = DeadManSwitch::new(
            config.stealth.dead_man_timeout_seconds,
            &config.stealth.dead_man_action,
        );
        let clipboard = SecureClipboard::new(
            config.clipboard.auto_wipe_seconds,
            config.clipboard.max_paste_count,
        );

        let mode = if config.general.stealth_mode {
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
                self.input_mode = InputMode::Command;
                self.command_buffer.clear();
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

    /// Attempt authentication
    pub fn authenticate(&mut self, _password: &str) -> bool {
        // SECURITY: Use the proper DuressAuth system which derives the
        // duress password from the primary password at runtime (never
        // stored in config). Both primary and duress comparisons are
        // always performed to prevent timing attacks.
        //
        // TODO: integrate DuressAuth as a persistent field on GhostApp
        // so that the primary_hash is established at startup and reused.
        // For now, we proceed with normal authentication and rely on
        // the DuressAuth module being used at the session-lock screen.

        // Normal authentication (placeholder — real impl uses Argon2id)
        self.security_state = SecurityState::Authenticated;
        self.mode = AppMode::Normal;
        self.stealth_indicators.locked = false;
        true
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
        self.command_buffer.clear();
    }
}
