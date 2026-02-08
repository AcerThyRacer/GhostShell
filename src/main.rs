// ╔══════════════════════════════════════════════════════════════════╗
// ║              GhostShell — Main Entry Point                       ║
// ║         Async CLI parsing, initialization, and event loop        ║
// ╚══════════════════════════════════════════════════════════════════╝

// Suppress dead-code warnings for roadmap features not yet wired in
// Modules contain APIs for future phases; allow for now


mod app;
pub mod audit;
mod config;
mod config_watcher;
mod crypto;
mod decoy;
pub mod error;
mod ids;
mod network;
pub mod plugin;
mod stealth;
mod terminal;

use app::GhostApp;
use zeroize::Zeroize;
use clap::{Parser, Subcommand};
use config::GhostConfig;
use crossterm::{
    event::{DisableMouseCapture, EnableMouseCapture, Event, EventStream},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use error::GhostError;
use futures::StreamExt;
use plugin::{PluginContext, PluginRegistry, VersionPlugin, UptimePlugin};
use ratatui::{backend::CrosstermBackend, Terminal};
use std::io;
use std::time::Duration;
use tokio_util::sync::CancellationToken;
use tracing_subscriber::EnvFilter;

/// 👻 GhostShell — Stealth Terminal Multiplexer
#[derive(Parser)]
#[command(
    name = "ghostshell",
    version = "0.1.0",
    about = "👻 Stealth terminal multiplexer with encrypted sessions, decoy shells, and intrusion detection",
    long_about = r#"
╔══════════════════════════════════════════════════════════════╗
║                    👻 GhostShell v0.1.0                      ║
║              Stealth Terminal Multiplexer                     ║
╠══════════════════════════════════════════════════════════════╣
║  Features:                                                    ║
║  • Encrypted session recording & playback                    ║
║  • Auto-wiping scrollback buffers                            ║
║  • Decoy shells with panic key switching                     ║
║  • Anomaly-based intrusion detection (IDS)                   ║
║  • Behavioral biometrics (typing cadence)                    ║
║  • Dead man's switch (inactivity auto-wipe)                  ║
║  • Steganographic session export                             ║
║  • Process name cloaking                                     ║
║  • Encrypted peer-to-peer tunneling                          ║
║  • Secure clipboard with TTL                                 ║
║  • Plugin system with lifecycle hooks                        ║
║  • Config hot-reload                                         ║
║  • Encrypted audit trail                                     ║
╚══════════════════════════════════════════════════════════════╝
"#
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Start in stealth mode (minimal UI, maximum OpSec)
    #[arg(long)]
    stealth: bool,

    /// Start in decoy mode (fake shell environment)
    #[arg(long)]
    decoy: bool,

    /// Use specific config file
    #[arg(short, long)]
    config: Option<String>,

    /// Start in safe mode (disables plugins, stealth, and advanced features)
    #[arg(long)]
    safe_mode: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Start a new terminal session
    New {
        /// Session name
        #[arg(short, long)]
        name: Option<String>,
    },
    /// Attach to an existing session
    Attach {
        /// Session name or ID
        name: String,
    },
    /// List active sessions
    List,
    /// Play back an encrypted session recording
    Play {
        /// Path to .ghost recording file
        path: String,
        /// Playback speed multiplier
        #[arg(short, long, default_value = "1.0")]
        speed: f64,
    },
    /// Manage configuration
    Config {
        /// Show current config
        #[arg(long)]
        show: bool,
        /// Reset to defaults
        #[arg(long)]
        reset: bool,
    },
    /// Generate a new encryption key
    Keygen,
    /// Export session with steganography
    Stego {
        /// Path to session recording
        session: String,
        /// Path to cover image (PNG)
        image: String,
        /// Output path
        output: String,
    },
}

#[tokio::main]
async fn main() -> Result<(), GhostError> {
    // Initialize structured logging
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info"));

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(true)
        .with_thread_ids(true)
        .init();

    let cli = Cli::parse();

    // Load configuration
    let mut config = if let Some(path) = &cli.config {
        let content = std::fs::read_to_string(path)?;
        toml::from_str(&content)?
    } else {
        GhostConfig::load()
    };

    // SECURITY: Validate loaded config for security misconfigurations
    let validation_errors = config::ConfigValidator::validate(&config);
    for err in &validation_errors {
        tracing::warn!("Config validation: {}", err);
    }

    // Apply CLI overrides
    if cli.stealth {
        config.general.stealth_mode = true;
    }

    // Handle subcommands (sync, exit early)
    match &cli.command {
        Some(Commands::List) => {
            list_sessions();
            return Ok(());
        }
        Some(Commands::Play { path, speed }) => {
            play_recording(path, *speed)?;
            return Ok(());
        }
        Some(Commands::Config { show, reset }) => {
            if *reset {
                let default = GhostConfig::default();
                default.save()?;
                println!("👻 Configuration reset to defaults.");
            }
            if *show || !*reset {
                let config = GhostConfig::load();
                println!(
                    "{}",
                    toml::to_string_pretty(&config)
                        .map_err(|e| GhostError::Config(e.to_string()))?
                );
            }
            return Ok(());
        }
        Some(Commands::Keygen) => {
            let key = crypto::keys::generate_master_key();
            let mut encoded = base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                key.as_bytes(),
            );
            println!("👻 Generated master key (keep this safe!):");
            println!("  {}", encoded);
            // SECURITY: Zeroize the base64 string — it contains the key material
            encoded.zeroize();
            // key is a SecureBuffer — zeroized on drop automatically
            return Ok(());
        }
        Some(Commands::Stego {
            session,
            image,
            output,
        }) => {
            stealth::stego::embed_session(session, image, output)?;
            println!("👻 Session embedded in image: {}", output);
            return Ok(());
        }
        _ => {}
    }

    // ── Launch TUI ────────────────────────────────────────────────

    tracing::info!("GhostShell v{} starting", env!("CARGO_PKG_VERSION"));

    // ── Crash Recovery ───────────────────────────────────────────
    let safe_mode = if cli.safe_mode {
        tracing::info!("Safe mode enabled via --safe-mode flag");
        true
    } else if GhostConfig::detect_crash() {
        tracing::warn!(
            "Previous session did not exit cleanly — starting in SAFE MODE. \
             Plugins, stealth, and advanced features are disabled."
        );
        true
    } else {
        false
    };

    // Write session lock (will be cleared on clean exit)
    if let Err(e) = GhostConfig::write_session_lock() {
        tracing::warn!("Failed to write session lock: {}", e);
    }

    // Apply process cloaking before entering the TUI (skip in safe mode)
    if !safe_mode && config.stealth.process_cloak_enabled {
        if let Err(e) = stealth::process_cloak::cloak_process(&config.stealth.process_cloak_name) {
            tracing::warn!("Process cloaking failed: {}", e);
        }
    }

    // Initialize audit log
    let data_dir = GhostConfig::data_dir();
    let mut audit_log = audit::AuditLog::new(&data_dir, &config.audit)?;
    audit_log.log_session_start()?;
    tracing::info!("Audit log initialized: {:?}", audit_log.current_log_path());

    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Create app
    let config_path = GhostConfig::config_path();
    let mut app = GhostApp::new(config, safe_mode);

    // Create initial pane
    app.panes.create_pane(&app.config.general.shell);
    app.scrollbacks
        .push(SecureScrollback::new(app.config.scrollback.buffer_size));

    // If starting in decoy mode, activate it
    if cli.decoy {
        app.mode = app::AppMode::Decoy;
        app.decoy_system.activate();
    }

    // Initialize plugin system (skip in safe mode)
    let mut plugins = PluginRegistry::new();
    if !safe_mode {
        if let Err(e) = plugins.register(Box::new(VersionPlugin)) {
            tracing::warn!("Failed to register VersionPlugin: {}", e);
        }
        if let Err(e) = plugins.register(Box::new(UptimePlugin::new())) {
            tracing::warn!("Failed to register UptimePlugin: {}", e);
        }

        let plugin_ctx = PluginContext {
            session_id: app.session_id.to_string(),
            app_version: env!("CARGO_PKG_VERSION").to_string(),
            mode: format!("{:?}", app.mode),
            pane_count: 1,
        };
        let init_errors = plugins.init_all(&plugin_ctx);
        if !init_errors.is_empty() {
            tracing::warn!("{} plugin(s) failed to initialize", init_errors.len());
        }
        tracing::info!("{} plugin(s) loaded", plugins.count());
    } else {
        tracing::info!("Safe mode: plugins disabled");
    }

    // Start config hot-reload watcher
    let config_watcher_rx = match config_watcher::ConfigWatcher::start(config_path) {
        Ok((_watcher, rx)) => {
            tracing::info!("Config watcher started");
            Some(rx)
        }
        Err(e) => {
            tracing::warn!("Config watcher failed to start: {}", e);
            None
        }
    };

    // Cancellation token for graceful shutdown
    let cancel_token = CancellationToken::new();

    // Main async event loop
    let result = run_event_loop_async(
        &mut terminal,
        &mut app,
        &mut plugins,
        &mut audit_log,
        config_watcher_rx,
        cancel_token.clone(),
    )
    .await;

    // Shutdown plugins
    plugins.shutdown_all();

    // Audit session end
    let _ = audit_log.log_session_end();
    let _ = audit_log.rotate_logs();

    app.secure_shutdown();

    // Clear session lock — clean exit
    GhostConfig::clear_session_lock();

    // Restore terminal
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    // Clean up on exit if configured
    if app.config.stealth.clean_on_exit {
        if let Err(e) = stealth::phantom::clean_traces() {
            tracing::warn!("Trace cleaning failed: {}", e);
        }
    }

    tracing::info!("GhostShell shutdown complete");
    result
}

use stealth::scrollback::SecureScrollback;

/// Async event loop using tokio::select! for concurrent handling
async fn run_event_loop_async(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &mut GhostApp,
    plugins: &mut PluginRegistry,
    audit_log: &mut audit::AuditLog,
    mut config_rx: Option<tokio::sync::mpsc::Receiver<config_watcher::ConfigEvent>>,
    cancel_token: CancellationToken,
) -> Result<(), GhostError> {
    let mut event_stream = EventStream::new();
    let mut dead_man_interval = tokio::time::interval(Duration::from_secs(1));
    let mut plugin_tick_interval = tokio::time::interval(Duration::from_secs(5));

    loop {
        // Render
        terminal.draw(|f| {
            terminal::renderer::render(f, app);
        })?;

        if app.should_quit {
            break;
        }

        // Async select across all event sources
        tokio::select! {
            // Branch 1: Terminal key/mouse events
            maybe_event = event_stream.next() => {
                match maybe_event {
                    Some(Ok(Event::Key(key))) => {
                        // Feed to biometrics if enabled
                        if app.config.ids.biometrics_enabled {
                            app.ids_engine.record_keystroke(&key);
                        }

                        // Route through input handler
                        let action = terminal::input::process_key(key, &mut app.input_mode);
                        app.handle_action(action);
                    }
                    Some(Ok(_)) => {
                        // Mouse events, resize, etc — ignore for now
                    }
                    Some(Err(e)) => {
                        tracing::error!("Terminal event error: {}", e);
                    }
                    None => {
                        // Event stream ended
                        break;
                    }
                }
            }

            // Branch 2: Dead man's switch check (every 1s)
            _ = dead_man_interval.tick() => {
                if let Some(action) = app.check_dead_man() {
                    tracing::warn!("Dead man's switch triggered: {}", action);
                    let _ = audit_log.log_event(
                        "dead_man",
                        audit::AuditEventKind::DeadManTriggered { action },
                    );
                }

                // Read output from active panes
                app.panes.read_outputs();
            }

            // Branch 3: Config hot-reload events
            config_event = async {
                match &mut config_rx {
                    Some(rx) => rx.recv().await,
                    None => std::future::pending().await,
                }
            } => {
                match config_event {
                    Some(config_watcher::ConfigEvent::Reloaded(new_config)) => {
                        if config_watcher::ConfigWatcher::requires_restart(&app.config, &new_config) {
                            tracing::warn!("Config change requires restart (security-critical fields changed)");
                        } else {
                            app.apply_config_update(new_config);
                            let _ = audit_log.log_config_change("hot-reload");
                        }
                    }
                    Some(config_watcher::ConfigEvent::ParseError(msg)) => {
                        tracing::error!("Config reload failed: {}", msg);
                    }
                    Some(config_watcher::ConfigEvent::ValidationError(errors)) => {
                        for err in &errors {
                            tracing::error!("Config validation error: {}", err);
                        }
                    }
                    None => {
                        config_rx = None; // Watcher dropped
                    }
                }
            }

            // Branch 4: Plugin tick (every 5s)
            _ = plugin_tick_interval.tick() => {
                let ctx = PluginContext {
                    session_id: app.session_id.to_string(),
                    app_version: env!("CARGO_PKG_VERSION").to_string(),
                    mode: format!("{:?}", app.mode),
                    pane_count: app.panes.count(),
                };
                plugins.tick_all(&ctx);
            }

            // Branch 5: Graceful shutdown signal
            _ = cancel_token.cancelled() => {
                tracing::info!("Shutdown signal received");
                app.should_quit = true;
            }
        }
    }

    Ok(())
}

fn list_sessions() {
    let sessions_dir = GhostConfig::sessions_dir();
    println!("👻 Active GhostShell Sessions:");
    println!("─────────────────────────────────────────");

    if let Ok(entries) = std::fs::read_dir(&sessions_dir) {
        let mut found = false;
        for entry in entries.flatten() {
            if let Some(name) = entry.file_name().to_str() {
                found = true;
                println!("  📟 {}", name);
            }
        }
        if !found {
            println!("  (no active sessions)");
        }
    } else {
        println!("  (no sessions directory)");
    }
}

fn play_recording(path: &str, speed: f64) -> Result<(), GhostError> {
    println!("👻 Playing recording: {} ({}x speed)", path, speed);
    println!("   (Recording playback engine — implementation ready)");
    crypto::session_recorder::play_recording(path, speed)?;
    Ok(())
}
