#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════╗
# ║              GhostShell — Linux/macOS Installer              ║
# ╚══════════════════════════════════════════════════════════════╝
set -euo pipefail

REPO="https://github.com/AcerThyRacer/GhostShell.git"
INSTALL_DIR="$HOME/.ghostshell"
BIN_DIR="$HOME/.local/bin"
BINARY_NAME="ghostshell"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

info()  { echo -e "${CYAN}[INFO]${NC} $*"; }
ok()    { echo -e "${GREEN}[  OK]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
fail()  { echo -e "${RED}[FAIL]${NC} $*"; exit 1; }

echo ""
echo "  👻 GhostShell Installer"
echo "  ========================"
echo ""

# ── Check for Rust toolchain ──────────────────────────────────
if ! command -v cargo &>/dev/null; then
    warn "Rust toolchain not found."
    info "Installing Rust via rustup..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
    ok "Rust installed."
fi

# ── Check for Git ─────────────────────────────────────────────
if ! command -v git &>/dev/null; then
    fail "Git is not installed. Please install git and try again."
fi

# ── Check for C compiler ──────────────────────────────────────
if ! command -v cc &>/dev/null && ! command -v gcc &>/dev/null; then
    warn "No C compiler found. Attempting to install build-essential..."
    if command -v apt-get &>/dev/null; then
        sudo apt-get update -qq && sudo apt-get install -y -qq build-essential
    elif command -v dnf &>/dev/null; then
        sudo dnf install -y gcc gcc-c++ make
    elif command -v pacman &>/dev/null; then
        sudo pacman -S --noconfirm base-devel
    else
        fail "Could not install a C compiler. Please install gcc/build-essential manually."
    fi
    ok "Build tools installed."
fi

# ── Clone or update the repository ────────────────────────────
if [ -d "$INSTALL_DIR" ]; then
    info "Updating existing installation..."
    cd "$INSTALL_DIR"
    git pull --quiet
    ok "Repository updated."
else
    info "Cloning GhostShell..."
    git clone --quiet "$REPO" "$INSTALL_DIR"
    ok "Repository cloned."
fi

# ── Build ─────────────────────────────────────────────────────
cd "$INSTALL_DIR"
info "Building GhostShell (release mode)... this may take a few minutes."
cargo build --release --quiet
ok "Build complete."

# ── Install binary ────────────────────────────────────────────
mkdir -p "$BIN_DIR"
cp "target/release/$BINARY_NAME" "$BIN_DIR/$BINARY_NAME"
chmod +x "$BIN_DIR/$BINARY_NAME"
ok "Installed to $BIN_DIR/$BINARY_NAME"

# ── Ensure BIN_DIR is on PATH ─────────────────────────────────
if ! echo "$PATH" | tr ':' '\n' | grep -qx "$BIN_DIR"; then
    SHELL_RC=""
    if [ -f "$HOME/.bashrc" ]; then
        SHELL_RC="$HOME/.bashrc"
    elif [ -f "$HOME/.zshrc" ]; then
        SHELL_RC="$HOME/.zshrc"
    fi

    if [ -n "$SHELL_RC" ]; then
        echo "export PATH=\"$BIN_DIR:\$PATH\"" >> "$SHELL_RC"
        info "Added $BIN_DIR to PATH in $SHELL_RC"
        warn "Run 'source $SHELL_RC' or open a new terminal to use ghostshell."
    else
        warn "$BIN_DIR is not on your PATH. Add it manually:"
        echo "  export PATH=\"$BIN_DIR:\$PATH\""
    fi
fi

# ── Done ──────────────────────────────────────────────────────
echo ""
ok "GhostShell installed successfully! 👻"
echo ""
echo "  Run:  ghostshell"
echo "  Help: ghostshell --help"
echo ""
