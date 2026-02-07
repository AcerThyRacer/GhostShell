<p align="center">
  <img src="https://img.shields.io/badge/version-0.1.0-blueviolet?style=for-the-badge" alt="Version">
  <img src="https://img.shields.io/badge/rust-2021-orange?style=for-the-badge&logo=rust" alt="Rust 2021">
  <img src="https://img.shields.io/badge/license-GPL--v3-green?style=for-the-badge" alt="License">
  <img src="https://img.shields.io/badge/platform-windows%20%7C%20linux-lightgrey?style=for-the-badge" alt="Platform">
</p>

<h1 align="center">👻 GhostShell</h1>

<p align="center">
  <b>Stealth Terminal Multiplexer with Encrypted Sessions, Decoy Shells & Intrusion Detection</b>
</p>

<p align="center">
  <i>Your terminal sessions — invisible, encrypted, deniable.</i>
</p>

---

## 🔥 What is GhostShell?

GhostShell is a security-first terminal multiplexer built in Rust. It combines encrypted session recording, decoy environments, behavioral biometrics, and anti-forensic features into a single tool designed for **privacy-conscious** operators.

Unlike traditional multiplexers (tmux, screen), GhostShell treats every session as a potential threat surface and defends accordingly.

---

## ✨ Features

| Feature | Description |
|---|---|
| 🔐 **Encrypted Sessions** | All session recordings encrypted with ChaCha20-Poly1305 + Argon2id key derivation |
| 🎭 **Decoy Shells** | Panic key instantly switches to a fake developer/sysadmin/casual environment |
| 🕵️ **Duress Authentication** | Enter a duress password to silently activate the decoy — adversary sees nothing |
| 🛡️ **Intrusion Detection (IDS)** | Anomaly-based detection for reverse shells, privilege escalation, and data exfiltration |
| ⌨️ **Behavioral Biometrics** | Typing cadence profiling detects unauthorized users on your session |
| 💀 **Dead Man's Switch** | Auto-lock or wipe after configurable inactivity timeout |
| 🖼️ **Steganographic Export** | Hide encrypted session data inside PNG images |
| 👤 **Process Cloaking** | GhostShell disguises its process name to evade forensic tools |
| 🔗 **Encrypted P2P Tunneling** | Noise Protocol-based encrypted tunnels between peers |
| 📋 **Secure Clipboard** | Auto-wiping clipboard with TTL and paste count limits |
| 🔌 **Plugin System** | Extend GhostShell with custom plugins and lifecycle hooks |
| 🔄 **Config Hot-Reload** | Change settings on the fly without restarting |
| 📝 **Encrypted Audit Trail** | Append-only encrypted log of all security events |
| 🧹 **Anti-Forensics** | Secure multi-pass scrollback wipe and clean-on-exit |

---

## 🚀 Quick Install

### One-Liner (Windows PowerShell) — Recommended

```powershell
irm https://raw.githubusercontent.com/AcerThyRacer/GhostShell/main/install.ps1 | iex
```

The Windows installer provides a **premium app experience**:

| Integration | Description |
|---|---|
| 🪟 **Start Menu** | GhostShell shortcut with custom ghost icon |
| 🖥️ **Desktop Shortcut** | Optional, prompted during install |
| ⚙️ **Apps & Features** | Appears in Windows Settings → Apps with full uninstaller |
| 🔤 **PATH Registration** | Run `ghostshell` from any terminal |
| 📟 **Windows Terminal** | Custom profile with ghost-themed color scheme + acrylic |
| 📁 **Context Menu** | Right-click → "Open GhostShell Here" in File Explorer |
| 📎 **File Association** | `.ghost` encrypted recordings open with GhostShell |
| 🗑️ **Clean Uninstall** | Removes all registry entries, shortcuts, and profiles |

The installer auto-detects and installs prerequisites (Rust, Git, VS Build Tools).

### One-Liner (Linux/macOS)

```bash
curl -fsSL https://raw.githubusercontent.com/AcerThyRacer/GhostShell/main/install.sh | bash
```

### Manual Install

```bash
# Clone the repository
git clone https://github.com/AcerThyRacer/GhostShell.git
cd GhostShell

# Build (requires Rust 1.70+)
cargo build --release

# The binary is at target/release/ghostshell (or ghostshell.exe on Windows)
```

---

## 📦 Requirements

- **Rust** 1.70+ (install from [rustup.rs](https://rustup.rs))
- **Git** (for cloning)
- **C/C++ compiler** (for native dependencies)
  - **Linux**: `build-essential` / `gcc`
  - **Windows**: Visual Studio Build Tools or MSVC

---

## 🖥️ Usage

```bash
# Start GhostShell
ghostshell

# Start in stealth mode (minimal UI, maximum OpSec)
ghostshell --stealth

# Start in decoy mode
ghostshell --decoy

# Start a named session
ghostshell new --name myproject

# Play back an encrypted recording
ghostshell play session.ghost --speed 2.0

# List active sessions
ghostshell list

# Use a custom config file
ghostshell --config /path/to/config.toml
```

---

## ⌨️ Default Keybindings

All keybindings use the `Ctrl-g` prefix:

| Keybinding | Action |
|---|---|
| `Ctrl-g h` | Split pane horizontally |
| `Ctrl-g v` | Split pane vertically |
| `Ctrl-g ↑↓←→` | Navigate panes |
| `Ctrl-g x` | Close active pane |
| `Ctrl-g t` | New tab |
| `Ctrl-g n/p` | Next/previous tab |
| `Ctrl-g :` | Command mode |
| `Ctrl-g r` | Toggle session recording |
| `Ctrl-g w` | Wipe scrollback buffer |
| `Ctrl-g Ctrl-g Ctrl-g` | **🚨 PANIC KEY** — instant switch to decoy |

---

## 🔐 Security Architecture

```
┌─────────────────────────────────────────────┐
│                 GhostShell                   │
├───────────┬───────────┬───────────┬─────────┤
│  Crypto   │  Decoy    │  IDS      │ Stealth │
│           │           │           │         │
│ ChaCha20  │ Fake Env  │ Anomaly   │ Cloak   │
│ Argon2id  │ Duress PW │ Biometric │ DeadMan │
│ Noise     │ Panic Key │ Exfil Det │ Stego   │
│ Shamir SS │ Honeypots │ Sigs      │ Wipe    │
└───────────┴───────────┴───────────┴─────────┘
```

- **Key Derivation**: Argon2id (64 MiB memory, 3 iterations, 4 threads)
- **Encryption**: ChaCha20-Poly1305 AEAD with counter + random prefix nonces
- **Networking**: Noise Protocol (snow) for peer-to-peer tunnels
- **Secret Sharing**: Shamir's Secret Sharing for key splitting
- **Memory Security**: `mlock` + `zeroize`-on-drop for all key material

---

## ⚙️ Configuration

GhostShell looks for configuration at `config/default.toml`. See the file for all options. Key sections:

```toml
[crypto]
argon2_memory_kib = 65536    # 64 MiB for KDF
argon2_iterations = 3
session_encryption = true

[stealth]
process_cloak_enabled = true
dead_man_timeout_seconds = 900  # 15 min
dead_man_action = "lock"        # lock | wipe | exit
phantom_mode = false

[decoy]
enabled = true
default_profile = "developer"   # developer | sysadmin | casual

[ids]
enabled = true
anomaly_threshold = 0.7
biometrics_enabled = true
signature_matching = true
```

---

## 🏗️ Project Structure

```
GhostShell/
├── src/
│   ├── main.rs              # Entry point, CLI parsing, TUI event loop
│   ├── app.rs               # Central state machine
│   ├── config.rs            # Configuration management
│   ├── audit.rs             # Encrypted audit trail
│   ├── error.rs             # Error types
│   ├── plugin.rs            # Plugin system
│   ├── crypto/              # Cryptographic primitives
│   │   ├── cipher.rs        # ChaCha20-Poly1305 AEAD
│   │   ├── keys.rs          # Argon2id KDF & key generation
│   │   ├── key_hierarchy.rs # Key hierarchy & Shamir's SS
│   │   ├── secure_mem.rs    # mlock'd, zeroize-on-drop buffers
│   │   ├── session_recorder.rs  # Encrypted session recording
│   │   ├── clipboard.rs     # Secure clipboard with TTL
│   │   └── pq_crypto.rs     # Post-quantum crypto stubs
│   ├── decoy/               # Decoy & deniability system
│   │   ├── duress.rs        # Duress authentication
│   │   ├── shell.rs         # Fake shell environments
│   │   ├── fake_history.rs  # Generated fake command history
│   │   ├── honeypot.rs      # Honeypot files
│   │   └── panic_key.rs     # Panic key handler
│   ├── ids/                 # Intrusion Detection System
│   │   ├── anomaly.rs       # Anomaly detection engine
│   │   ├── biometrics.rs    # Typing cadence profiling
│   │   ├── signatures.rs    # Known attack signatures
│   │   └── alerts.rs        # Alert queue & responses
│   ├── stealth/             # Anti-forensic features
│   │   ├── process_cloak.rs # Process name disguise
│   │   ├── dead_man.rs      # Dead man's switch
│   │   ├── stego.rs         # Steganography engine
│   │   └── scrollback.rs    # Secure scrollback buffer
│   ├── network/             # Encrypted networking
│   │   ├── tunnel.rs        # Noise Protocol tunnels
│   │   └── traffic_obfuscation.rs  # TLS-like framing
│   └── terminal/            # TUI components
│       ├── layout.rs        # Layout engine
│       ├── pane.rs          # Pane manager
│       ├── input.rs         # Input handling
│       ├── renderer.rs      # Ratatui rendering
│       └── theme.rs         # Color themes
├── config/
│   └── default.toml         # Default configuration
├── install.sh               # Linux/macOS installer
├── install.ps1              # Windows installer
├── Cargo.toml               # Rust dependencies
├── LICENSE                  # GPL-3.0
└── README.md
```

---

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Commit your changes (`git commit -m 'Add my feature'`)
4. Push to the branch (`git push origin feature/my-feature`)
5. Open a Pull Request

---

## ⚠️ Disclaimer

GhostShell is designed for **legitimate privacy and security use cases** — protecting sensitive terminal sessions, security research, penetration testing with authorization, and privacy-focused development workflows.

**Do not use this tool for unauthorized access, evasion of lawful monitoring, or any illegal activity.** The authors are not responsible for misuse.

---

## 📜 License

This project is licensed under the **GNU General Public License v3.0** — see the [LICENSE](LICENSE) file for details.

```
Copyright (C) 2026 AcerThyRacer

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
```

---

<p align="center">
  <b>👻 Stay invisible. Stay encrypted. Stay ghost.</b>
</p>
