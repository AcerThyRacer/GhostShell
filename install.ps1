# ╔══════════════════════════════════════════════════════════════╗
# ║              GhostShell — Windows Installer (PowerShell)     ║
# ╚══════════════════════════════════════════════════════════════╝

$ErrorActionPreference = "Stop"

$Repo        = "https://github.com/AcerThyRacer/GhostShell.git"
$InstallDir  = "$env:USERPROFILE\.ghostshell"
$BinDir      = "$env:USERPROFILE\.local\bin"
$BinaryName  = "ghostshell.exe"

function Write-Info  { param($Msg) Write-Host "[INFO] $Msg" -ForegroundColor Cyan }
function Write-Ok    { param($Msg) Write-Host "[  OK] $Msg" -ForegroundColor Green }
function Write-Warn  { param($Msg) Write-Host "[WARN] $Msg" -ForegroundColor Yellow }
function Write-Fail  { param($Msg) Write-Host "[FAIL] $Msg" -ForegroundColor Red; exit 1 }

Write-Host ""
Write-Host "  GhostShell Installer" -ForegroundColor Magenta
Write-Host "  ========================" -ForegroundColor Magenta
Write-Host ""

# ── Check for Rust toolchain ──────────────────────────────────
if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
    Write-Warn "Rust toolchain not found."
    Write-Info "Installing Rust via rustup..."

    $RustupInit = "$env:TEMP\rustup-init.exe"
    Invoke-WebRequest -Uri "https://win.rustup.rs/x86_64" -OutFile $RustupInit -UseBasicParsing
    & $RustupInit -y --quiet
    Remove-Item $RustupInit -ErrorAction SilentlyContinue

    # Refresh PATH
    $env:PATH = "$env:USERPROFILE\.cargo\bin;$env:PATH"
    Write-Ok "Rust installed."
}

# ── Check for Git ─────────────────────────────────────────────
if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    Write-Fail "Git is not installed. Please install Git from https://git-scm.com and try again."
}

# ── Clone or update the repository ────────────────────────────
if (Test-Path $InstallDir) {
    Write-Info "Updating existing installation..."
    Push-Location $InstallDir
    git pull --quiet
    Pop-Location
    Write-Ok "Repository updated."
} else {
    Write-Info "Cloning GhostShell..."
    git clone --quiet $Repo $InstallDir
    Write-Ok "Repository cloned."
}

# ── Build ─────────────────────────────────────────────────────
Push-Location $InstallDir
Write-Info "Building GhostShell (release mode)... this may take a few minutes."
cargo build --release --quiet
Pop-Location
Write-Ok "Build complete."

# ── Install binary ────────────────────────────────────────────
if (-not (Test-Path $BinDir)) {
    New-Item -ItemType Directory -Path $BinDir -Force | Out-Null
}

Copy-Item "$InstallDir\target\release\$BinaryName" "$BinDir\$BinaryName" -Force
Write-Ok "Installed to $BinDir\$BinaryName"

# ── Ensure BinDir is on user PATH ─────────────────────────────
$UserPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($UserPath -notlike "*$BinDir*") {
    [Environment]::SetEnvironmentVariable("Path", "$BinDir;$UserPath", "User")
    $env:PATH = "$BinDir;$env:PATH"
    Write-Info "Added $BinDir to your user PATH."
    Write-Warn "You may need to restart your terminal for PATH changes to take effect."
}

# ── Done ──────────────────────────────────────────────────────
Write-Host ""
Write-Ok "GhostShell installed successfully!"
Write-Host ""
Write-Host "  Run:  ghostshell" -ForegroundColor White
Write-Host "  Help: ghostshell --help" -ForegroundColor White
Write-Host ""
