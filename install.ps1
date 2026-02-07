# ============================================================================
#  GHOSTSHELL - Premium Windows Installer
#  Stealth Terminal Multiplexer v0.1.0
#  Compatible with PowerShell 5.1+
# ============================================================================
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File install.ps1
#   powershell -ExecutionPolicy Bypass -File install.ps1 -NoEffects
#
# One-liner:
#   irm https://raw.githubusercontent.com/AcerThyRacer/GhostShell/main/install.ps1 | iex

#Requires -Version 5.1

param(
    [switch]$NoEffects
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

# ── ESC character (PS 5.1 compatible - backtick-e only works in PS 6+) ──
$E = [char]0x1B

# ── Paths & Constants ────────────────────────────────────────────────────
$Script:AppName = "GhostShell"
$Script:AppVersion = "0.1.0"
$Script:AppPublisher = "AcerThyRacer"
$Script:Repo = "https://github.com/AcerThyRacer/GhostShell.git"
$Script:InstallRoot = "$env:LOCALAPPDATA\GhostShell"
$Script:BinDir = "$Script:InstallRoot\bin"
$Script:SourceDir = "$Script:InstallRoot\source"
$Script:DataDir = "$Script:InstallRoot\data"
$Script:ConfigDir = "$env:APPDATA\GhostShell\config"
$Script:PluginsDir = "$Script:InstallRoot\plugins"
$Script:BinaryName = "ghostshell.exe"
$Script:UninstallReg = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\GhostShell"
$Script:StepsDone = 0
$Script:TotalSteps = 9

# ── Color Theme (PowerShell-native blue with ghost accents) ──────────────
$Script:C = @{
    # Core PS-style blues
    PSBlue   = "$E[38;2;56;132;244m"
    PSCyan   = "$E[38;2;86;196;240m"
    # Ghost accent
    Ghost    = "$E[38;2;100;220;255m"
    GhostDim = "$E[38;2;50;90;120m"
    # Status colors
    Green    = "$E[38;2;60;220;140m"
    Red      = "$E[38;2;240;80;90m"
    Yellow   = "$E[38;2;240;200;80m"
    # Neutral
    White    = "$E[38;2;220;225;240m"
    Dim      = "$E[38;2;90;95;115m"
    VDim     = "$E[38;2;55;58;75m"
    Purple   = "$E[38;2;160;120;240m"
    # Formatting
    Bold     = "$E[1m"
    Italic   = "$E[3m"
    Reset    = "$E[0m"
    # Background
    BgDark   = "$E[48;2;12;12;22m"
    BgBlue   = "$E[48;2;20;30;55m"
}

# ── Console Setup ────────────────────────────────────────────────────────
try {
    [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
    $Host.UI.RawUI.WindowTitle = "GhostShell Installer"
}
catch { }

# ============================================================================
#  HELPER FUNCTIONS
# ============================================================================

function Get-TermWidth {
    try { return $Host.UI.RawUI.WindowSize.Width } catch { return 80 }
}

function Write-Centered {
    param($Text, $Color = $C.White)
    $w = Get-TermWidth
    $clean = $Text -replace "$([regex]::Escape($E))\[[0-9;]*m", ''
    $pad = [math]::Max(0, [math]::Floor(($w - $clean.Length) / 2))
    Write-Host "$(' ' * $pad)$Color$Text$($C.Reset)"
}

function Write-Line {
    param($Char = [char]0x2500, $Color = $C.Dim)
    $w = Get-TermWidth
    Write-Host "$Color  $($Char.ToString() * [math]::Min(($w - 4), 64))$($C.Reset)"
}

function Write-Ok {
    param($Msg)
    Write-Host "  $($C.Green)$([char]0x2714) $Msg$($C.Reset)"
}

function Write-Warn {
    param($Msg)
    Write-Host "  $($C.Yellow)! $Msg$($C.Reset)"
}

function Write-Fail {
    param($Msg)
    Write-Host "  $($C.Red)X $Msg$($C.Reset)"
    exit 1
}

function Write-Info {
    param($Msg)
    Write-Host "  $($C.Dim)| $Msg$($C.Reset)"
}

function Write-Step {
    param($Msg)
    $Script:StepsDone++
    $pct = [math]::Round(($Script:StepsDone / $Script:TotalSteps) * 100)
    $barLen = 30
    $filled = [math]::Floor($pct / 100 * $barLen)
    $empty = $barLen - $filled
    $barFill = [string]::new([char]0x2588, $filled)
    $barEmpty = [string]::new([char]0x2591, $empty)
    $bar = "$($C.PSCyan)$barFill$($C.VDim)$barEmpty"

    Write-Host ""
    Write-Host "  $($C.PSBlue)$($C.Bold)[$Script:StepsDone/$Script:TotalSteps]$($C.Reset) $($C.White)$($C.Bold)$Msg$($C.Reset)"
    Write-Host "  $($C.Dim)|$($C.Reset) $bar $($C.Dim)$pct%$($C.Reset)"
}

function Test-CommandExists {
    param($Cmd)
    $null -ne (Get-Command $Cmd -ErrorAction SilentlyContinue)
}

function New-Shortcut {
    param($ShortcutPath, $TargetPath, $Arguments, $IconPath, $WorkingDir, $Description)
    $shell = New-Object -ComObject WScript.Shell
    $shortcut = $shell.CreateShortcut($ShortcutPath)
    $shortcut.TargetPath = $TargetPath
    if ($Arguments) { $shortcut.Arguments = $Arguments }
    if ($IconPath) { $shortcut.IconLocation = $IconPath }
    if ($WorkingDir) { $shortcut.WorkingDirectory = $WorkingDir }
    if ($Description) { $shortcut.Description = $Description }
    $shortcut.WindowStyle = 1
    $shortcut.Save()
    [System.Runtime.Interopservices.Marshal]::ReleaseComObject($shell) | Out-Null
}

# ============================================================================
#  FOGGY GHOST EFFECT
# ============================================================================

function Show-FogLine {
    if ($NoEffects) { return }
    $w = Get-TermWidth
    $ghostChars = @(
        [char]0x2591,   # light shade
        [char]0x2592,   # medium shade
        [char]0x00B7,   # middle dot
        [char]0x2022,   # bullet
        [char]0x2219    # bullet operator
    )
    $fogColors = @($C.VDim, $C.GhostDim, $C.Dim)
    $line = ""
    for ($j = 0; $j -lt [math]::Min($w - 2, 72); $j++) {
        $roll = Get-Random -Maximum 20
        if ($roll -eq 0) {
            $ch = $ghostChars[(Get-Random -Maximum $ghostChars.Count)]
            $cl = $fogColors[(Get-Random -Maximum $fogColors.Count)]
            $line += "$cl$ch$($C.Reset)"
        }
        elseif ($roll -eq 1) {
            $line += "$($C.VDim)~$($C.Reset)"
        }
        else {
            $line += " "
        }
    }
    Write-Host "  $line"
}

function Show-FogBlock {
    param($Lines = 2)
    if ($NoEffects) { return }
    for ($i = 0; $i -lt $Lines; $i++) {
        Show-FogLine
    }
}

function Show-GhostFloat {
    if ($NoEffects) { return }
    $w = Get-TermWidth
    $ghostFrames = @(
        "  $($C.GhostDim).  .  .$($C.Reset)",
        "  $($C.GhostDim)~  $($C.Ghost).o0$($C.GhostDim)  ~$($C.Reset)",
        "  $($C.GhostDim).  $($C.Ghost)$($C.Bold)o$($C.Reset)$($C.GhostDim)  .$($C.Reset)"
    )
    $pick = $ghostFrames[(Get-Random -Maximum $ghostFrames.Count)]
    $pad = Get-Random -Minimum 4 -Maximum ([math]::Max(5, $w - 20))
    Write-Host "$(' ' * $pad)$pick"
}

# ============================================================================
#  SPLASH SCREEN
# ============================================================================

function Show-Splash {
    Clear-Host
    Write-Host ""

    # Fog header
    Show-FogBlock -Lines 2

    # ASCII art - Ghost
    $ghostArt = @(
        "   ______  __               __  _____ __         ____",
        "  / ____/ / /_  ____  _____/ /_/ ___// /_  ___  / / /",
        " / / __  / __ \/ __ \/ ___/ __/\__ \/ __ \/ _ \/ / / ",
        "/ /_/ / / / / / /_/ (__  ) /_ ___/ / / / /  __/ / /  ",
        "\____/ /_/ /_/\____/____/\__//____/_/ /_/\___/_/_/   "
    )

    foreach ($line in $ghostArt) {
        Write-Centered $line $C.PSCyan
        if (-not $NoEffects) { Start-Sleep -Milliseconds 40 }
    }

    Write-Host ""
    Write-Centered ([string]::new([char]0x2550, 52)) $C.Dim
    Write-Centered "Stealth Terminal Multiplexer  $($C.Dim)|  Windows Installer" "$($C.White)$($C.Bold)"
    Write-Centered "v$Script:AppVersion  $($C.Dim)|  by $Script:AppPublisher" $C.Dim
    Write-Centered ([string]::new([char]0x2550, 52)) $C.Dim
    Write-Host ""

    # Feature cards
    $features = @(
        @("$([char]0x25CF) Encrypted Sessions", "ChaCha20-Poly1305 + Argon2id"),
        @("$([char]0x25CF) Decoy Shells", "Panic key instant switch"),
        @("$([char]0x25CF) Intrusion Detection", "Anomaly-based IDS"),
        @("$([char]0x25CF) Process Cloaking", "Anti-forensic stealth"),
        @("$([char]0x25CF) P2P Tunneling", "Noise Protocol tunnels"),
        @("$([char]0x25CF) Secure Clipboard", "Auto-wiping with TTL"),
        @("$([char]0x25CF) Steganography", "Sessions inside PNG images"),
        @("$([char]0x25CF) Dead Man's Switch", "Auto-lock on inactivity")
    )

    foreach ($f in $features) {
        $label = $f[0].PadRight(28)
        Write-Host "    $($C.PSCyan)$label$($C.Dim)$($f[1])$($C.Reset)"
        if (-not $NoEffects) { Start-Sleep -Milliseconds 30 }
    }

    Write-Host ""
    Show-FogBlock -Lines 1

    # Effects toggle notice
    if (-not $NoEffects) {
        Write-Host "    $($C.VDim)Tip: Use $($C.Dim)-NoEffects$($C.VDim) flag to disable animations$($C.Reset)"
    }

    Write-Line
    Write-Host ""
}

# ============================================================================
#  STEP 1: SYSTEM REQUIREMENTS
# ============================================================================

function Test-SystemRequirements {
    Write-Step "System Requirements"

    # OS Version
    $build = 0
    try {
        $build = [int](Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -ErrorAction SilentlyContinue).CurrentBuildNumber
    }
    catch { }

    if ($build -ge 22000) {
        Write-Ok "Windows 11 (Build $build)"
    }
    elseif ($build -ge 10240) {
        Write-Ok "Windows 10 (Build $build)"
    }
    else {
        Write-Warn "Windows build $build may not be fully supported"
    }

    # Architecture
    try {
        $arch = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture
        Write-Ok "Architecture: $arch"
    }
    catch {
        Write-Ok "Architecture: $env:PROCESSOR_ARCHITECTURE"
    }

    # Disk space
    try {
        $drive = (Split-Path $env:LOCALAPPDATA -Qualifier)
        $freeGB = [math]::Round((Get-PSDrive ($drive -replace ':', '') | Select-Object -ExpandProperty Free) / 1GB, 1)
        if ($freeGB -lt 2) {
            Write-Fail "Insufficient disk space: ${freeGB}GB free (need 2GB+)"
        }
        Write-Ok "Disk space: ${freeGB}GB free"
    }
    catch {
        Write-Warn "Could not check disk space"
    }

    # PowerShell version
    Write-Ok "PowerShell: $($PSVersionTable.PSVersion)"
}

# ============================================================================
#  STEP 2: PREREQUISITES
# ============================================================================

function Install-Prerequisites {
    Write-Step "Prerequisites"

    # Git
    if (Test-CommandExists "git") {
        $gitVer = (git --version 2>$null) -replace 'git version ', ''
        Write-Ok "Git $gitVer"
    }
    else {
        Write-Warn "Git not found"
        Write-Info "Installing Git via winget..."
        try {
            $null = winget install --id Git.Git -e --accept-source-agreements --accept-package-agreements --silent 2>$null
            $env:PATH = "$env:ProgramFiles\Git\cmd;$env:PATH"
            if (Test-CommandExists "git") {
                Write-Ok "Git installed"
            }
            else {
                Write-Fail "Git install failed. Get it from https://git-scm.com"
            }
        }
        catch {
            Write-Fail "Git install failed. Get it from https://git-scm.com"
        }
    }

    # Rust
    $CargoBin = "$env:USERPROFILE\.cargo\bin"
    if ($env:PATH -notlike "*$CargoBin*") {
        $env:PATH = "$CargoBin;$env:PATH"
    }

    if (Test-CommandExists "cargo") {
        $rustVer = (rustc --version 2>$null) -replace 'rustc ', ''
        Write-Ok "Rust $rustVer"
    }
    else {
        Write-Warn "Rust not found"
        Write-Info "Installing Rust via rustup..."
        $RustupInit = "$env:TEMP\rustup-init.exe"
        try {
            Invoke-WebRequest -Uri "https://win.rustup.rs/x86_64" -OutFile $RustupInit -UseBasicParsing
            $null = & $RustupInit -y --quiet 2>$null
            Remove-Item $RustupInit -ErrorAction SilentlyContinue
            $env:PATH = "$CargoBin;$env:PATH"
            if (Test-CommandExists "cargo") {
                Write-Ok "Rust installed"
            }
            else {
                Write-Fail "Rust install failed. Visit https://rustup.rs"
            }
        }
        catch {
            Write-Fail "Rust install failed: $_"
        }
    }

    # MSVC
    $hasCC = ($null -ne (Get-Command "cl.exe" -ErrorAction SilentlyContinue)) -or
    (Test-Path "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe")
    if ($hasCC) {
        Write-Ok "C/C++ compiler (MSVC) detected"
    }
    else {
        Write-Warn "VS Build Tools not detected"
        Write-Info "Installing VS Build Tools (may take several minutes)..."
        try {
            $null = winget install --id Microsoft.VisualStudio.2022.BuildTools -e --accept-source-agreements --accept-package-agreements --silent --override "--add Microsoft.VisualStudio.Workload.VCTools --quiet --wait" 2>$null
            Write-Ok "VS Build Tools installed"
        }
        catch {
            Write-Warn "Auto-install failed. If build fails, get VS Build Tools from:"
            Write-Info "https://visualstudio.microsoft.com/visual-cpp-build-tools/"
        }
    }
}

# ============================================================================
#  STEP 3: FETCH SOURCE
# ============================================================================

function Get-Repository {
    Write-Step "Fetching Source"

    if (Test-Path "$Script:SourceDir\.git") {
        Write-Info "Pulling latest changes..."
        Push-Location $Script:SourceDir
        & git pull --quiet 2>$null
        Pop-Location
        Write-Ok "Source updated"
    }
    else {
        if (Test-Path $Script:SourceDir) {
            Remove-Item -Recurse -Force $Script:SourceDir -ErrorAction SilentlyContinue
        }
        Write-Info "Cloning repository..."
        & git clone --quiet --depth 1 $Script:Repo $Script:SourceDir 2>$null
        if ($LASTEXITCODE -ne 0) {
            Write-Fail "Clone failed. Check your internet connection."
        }
        Write-Ok "Source cloned"
    }

    Show-FogBlock -Lines 1
}

# ============================================================================
#  STEP 4: BUILD
# ============================================================================

function Build-GhostShell {
    Write-Step "Building (Release Mode)"
    Write-Info "This may take 2-5 minutes on first build..."

    if (-not (Test-Path "$Script:SourceDir\Cargo.toml")) {
        Write-Fail "Cargo.toml not found in $Script:SourceDir"
    }

    Push-Location $Script:SourceDir

    # Run cargo directly. Do NOT use 2>&1 redirection.
    # Without redirection, stderr goes to the console host directly and
    # bypasses PowerShell's error handling. This is the only reliable way
    # to avoid NativeCommandError in PS 5.1.
    & cargo build --release
    $buildResult = $LASTEXITCODE

    Pop-Location

    if ($buildResult -ne 0) {
        Write-Fail "Build failed (exit $buildResult). See cargo output above."
    }

    $builtBinary = "$Script:SourceDir\target\release\$Script:BinaryName"
    if (-not (Test-Path $builtBinary)) {
        Write-Fail "Binary not found at $builtBinary"
    }

    Write-Ok "Build complete"
    Show-FogBlock -Lines 1
}

# ============================================================================
#  STEP 5: INSTALL APPLICATION
# ============================================================================

function Install-Application {
    Write-Step "Installing Application"

    # Directory structure
    $dirs = @($Script:BinDir, $Script:DataDir, $Script:ConfigDir, $Script:PluginsDir)
    foreach ($d in $dirs) {
        if (-not (Test-Path $d)) {
            New-Item -ItemType Directory -Path $d -Force | Out-Null
        }
    }
    Write-Ok "Directory structure created"

    # Copy binary (stop running instance first if locked)
    $builtBinary = "$Script:SourceDir\target\release\$Script:BinaryName"
    $running = Get-Process -Name "ghostshell" -ErrorAction SilentlyContinue
    if ($running) {
        Write-Info "Stopping running GhostShell instance..."
        $running | Stop-Process -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 1
    }
    try {
        Copy-Item $builtBinary "$Script:BinDir\$Script:BinaryName" -Force
    }
    catch {
        Write-Warn "Binary locked. Scheduling copy on next boot..."
        $copyCmd = "Copy-Item '$builtBinary' '$Script:BinDir\$Script:BinaryName' -Force"
        $null = Register-ScheduledTask -TaskName "GhostShellUpdate" `
            -Action (New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -Command $copyCmd") `
            -Trigger (New-ScheduledTaskTrigger -AtLogOn) `
            -Settings (New-ScheduledTaskSettingsSet -DeleteExpiredTaskAfter 00:01:00) `
            -ErrorAction SilentlyContinue
        Write-Warn "Binary will update on next login"
    }
    Write-Ok "Binary installed to $($C.Dim)$Script:BinDir"

    # Default config
    $defaultConfig = "$Script:SourceDir\config\default.toml"
    $targetConfig = "$Script:ConfigDir\default.toml"
    if ((Test-Path $defaultConfig) -and -not (Test-Path $targetConfig)) {
        Copy-Item $defaultConfig $targetConfig -Force
        Write-Ok "Default config installed"
    }
    elseif (Test-Path $targetConfig) {
        Write-Info "Existing config preserved"
    }

    # PATH
    $UserPath = [Environment]::GetEnvironmentVariable("Path", "User")
    if ($UserPath -notlike "*$($Script:BinDir)*") {
        [Environment]::SetEnvironmentVariable("Path", "$($Script:BinDir);$UserPath", "User")
        $env:PATH = "$($Script:BinDir);$env:PATH"
        Write-Ok "Added to user PATH"
    }
    else {
        Write-Info "Already on PATH"
    }
}

# ============================================================================
#  STEP 6: WINDOWS INTEGRATION
# ============================================================================

function Register-WindowsApp {
    Write-Step "Windows Integration"

    # Icon
    $iconPath = "$Script:InstallRoot\ghostshell.ico"
    New-AppIcon $iconPath
    Write-Ok "App icon generated"

    # Start Menu
    $startMenu = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs"
    New-Shortcut -ShortcutPath "$startMenu\GhostShell.lnk" `
        -TargetPath "pwsh.exe" `
        -Arguments "-NoProfile -ExecutionPolicy Bypass -File `"$Script:InstallRoot\ghostshell-launcher.ps1`"" `
        -IconPath $iconPath `
        -WorkingDir $env:USERPROFILE `
        -Description "GhostShell - Stealth Terminal Multiplexer"
    Write-Ok "Start Menu shortcut"

    # Desktop shortcut prompt
    Write-Host ""
    Write-Host "    $($C.PSCyan)? $($C.White)Create Desktop shortcut? $($C.Dim)(Y/n)$($C.Reset)" -NoNewline
    $choice = Read-Host " "
    if ($choice -ne "n" -and $choice -ne "N") {
        New-Shortcut -ShortcutPath "$env:USERPROFILE\Desktop\GhostShell.lnk" `
            -TargetPath "pwsh.exe" `
            -Arguments "-NoProfile -ExecutionPolicy Bypass -File `"$Script:InstallRoot\ghostshell-launcher.ps1`"" `
            -IconPath $iconPath `
            -WorkingDir $env:USERPROFILE `
            -Description "GhostShell - Stealth Terminal Multiplexer"
        Write-Ok "Desktop shortcut created"
    }

    # Apps & Features
    $uninstallScript = "$Script:InstallRoot\uninstall.ps1"
    $regProps = @{
        DisplayName     = "GhostShell"
        DisplayVersion  = $Script:AppVersion
        Publisher       = $Script:AppPublisher
        InstallLocation = $Script:InstallRoot
        DisplayIcon     = $iconPath
        UninstallString = "pwsh.exe -NoProfile -ExecutionPolicy Bypass -File `"$uninstallScript`""
        NoModify        = 1
        NoRepair        = 1
        EstimatedSize   = [math]::Round((Get-ChildItem $Script:InstallRoot -Recurse -ErrorAction SilentlyContinue | Measure-Object Length -Sum).Sum / 1KB)
        URLInfoAbout    = "https://github.com/AcerThyRacer/GhostShell"
    }
    if (-not (Test-Path $Script:UninstallReg)) {
        New-Item -Path $Script:UninstallReg -Force | Out-Null
    }
    foreach ($key in $regProps.Keys) {
        Set-ItemProperty -Path $Script:UninstallReg -Name $key -Value $regProps[$key]
    }
    Write-Ok "Registered in Apps & Features"

    # File association: .ghost
    $ghostExt = "HKCU:\Software\Classes\.ghost"
    $ghostProg = "HKCU:\Software\Classes\GhostShell.Recording"
    $ghostCmd = "HKCU:\Software\Classes\GhostShell.Recording\shell\open\command"
    $ghostIcon = "HKCU:\Software\Classes\GhostShell.Recording\DefaultIcon"
    New-Item -Path $ghostExt -Force | Out-Null
    Set-ItemProperty -Path $ghostExt -Name "(Default)" -Value "GhostShell.Recording"
    New-Item -Path $ghostProg -Force | Out-Null
    Set-ItemProperty -Path $ghostProg -Name "(Default)" -Value "GhostShell Encrypted Recording"
    New-Item -Path $ghostIcon -Force | Out-Null
    Set-ItemProperty -Path $ghostIcon -Name "(Default)" -Value "$iconPath,0"
    New-Item -Path $ghostCmd -Force | Out-Null
    Set-ItemProperty -Path $ghostCmd -Name "(Default)" -Value "`"$Script:BinDir\$Script:BinaryName`" play `"%1`""
    Write-Ok "File association: .ghost"

    # Context menu
    $ctxKey = "HKCU:\Software\Classes\Directory\Background\shell\GhostShell"
    $ctxCmd = "$ctxKey\command"
    New-Item -Path $ctxKey -Force | Out-Null
    Set-ItemProperty -Path $ctxKey -Name "(Default)" -Value "Open GhostShell Here"
    Set-ItemProperty -Path $ctxKey -Name "Icon" -Value $iconPath
    New-Item -Path $ctxCmd -Force | Out-Null
    Set-ItemProperty -Path $ctxCmd -Name "(Default)" -Value "pwsh.exe -NoProfile -ExecutionPolicy Bypass -Command `"& '$Script:BinDir\$Script:BinaryName'`""
    Write-Ok "Context menu entry"

    # Windows Terminal profile
    Add-TerminalProfile $iconPath
}

# ============================================================================
#  WINDOWS TERMINAL PROFILE
# ============================================================================

function Add-TerminalProfile {
    param($IconPath)

    $wtPaths = @(
        "$env:LOCALAPPDATA\Packages\Microsoft.WindowsTerminal_8wekyb3d8bbwe\LocalState\settings.json",
        "$env:LOCALAPPDATA\Packages\Microsoft.WindowsTerminalPreview_8wekyb3d8bbwe\LocalState\settings.json"
    )

    $profileGuid = "{7f3b2d85-a09c-4e47-b834-gh0st5hell01}"
    $profileObj = @{
        guid              = $profileGuid
        name              = "GhostShell"
        commandline       = "$Script:BinDir\$Script:BinaryName"
        icon              = $IconPath
        startingDirectory = "%USERPROFILE%"
        colorScheme       = "GhostShell"
        useAcrylic        = $true
        opacity           = 85
        font              = @{ face = "Cascadia Code"; size = 11 }
        hidden            = $false
    }
    $schemeObj = @{
        name                = "GhostShell"
        background          = "#0C0C16"
        foreground          = "#B4BEC8"
        cursorColor         = "#50C8FF"
        black               = "#1A1A2E"
        red                 = "#F0505A"
        green               = "#3CDC8C"
        yellow              = "#F0C850"
        blue                = "#3884F4"
        purple              = "#A078F0"
        cyan                = "#56C4F0"
        white               = "#DCE0F0"
        brightBlack         = "#3C3C55"
        brightRed           = "#FF6680"
        brightGreen         = "#66FFB2"
        brightYellow        = "#FFD880"
        brightBlue          = "#80DCFF"
        brightPurple        = "#C89CFF"
        brightCyan          = "#80DCFF"
        brightWhite         = "#FFFFFF"
        selectionBackground = "#2A3A5A"
    }

    foreach ($settingsFile in $wtPaths) {
        if (-not (Test-Path $settingsFile)) { continue }
        try {
            $raw = Get-Content $settingsFile -Raw
            $clean = $raw -replace '(?m)^\s*//.*$', '' -replace ',(\s*[}\]])', '$1'
            $json = $clean | ConvertFrom-Json

            if (-not ($json.schemes | Where-Object { $_.name -eq "GhostShell" })) {
                $json.schemes += [PSCustomObject]$schemeObj
            }

            $profiles = $json.profiles
            $list = if ($profiles.list) { $profiles.list } else { $profiles }
            if (-not ($list | Where-Object { $_.guid -eq $profileGuid })) {
                if ($profiles.list) {
                    $json.profiles.list += [PSCustomObject]$profileObj
                }
                else {
                    $json.profiles += [PSCustomObject]$profileObj
                }
            }

            $json | ConvertTo-Json -Depth 10 | Set-Content $settingsFile -Encoding UTF8
            Write-Ok "Windows Terminal profile injected"
            return
        }
        catch {
            Write-Warn "Could not update Windows Terminal: $_"
        }
    }
    Write-Info "Windows Terminal not found (skipped)"
}

# ============================================================================
#  APP ICON GENERATOR
# ============================================================================

function New-AppIcon {
    param($OutPath)
    Add-Type -AssemblyName System.Drawing -ErrorAction SilentlyContinue

    try {
        $bmp = New-Object System.Drawing.Bitmap(32, 32)
        $g = [System.Drawing.Graphics]::FromImage($bmp)
        $g.Clear([System.Drawing.Color]::FromArgb(12, 12, 22))

        $ghostBrush = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(86, 196, 240))
        $g.FillEllipse($ghostBrush, 6, 2, 20, 18)
        $g.FillRectangle($ghostBrush, 6, 12, 20, 14)

        $eyeBrush = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(12, 12, 22))
        $g.FillEllipse($eyeBrush, 11, 8, 4, 5)
        $g.FillEllipse($eyeBrush, 19, 8, 4, 5)

        $bgBrush = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(12, 12, 22))
        $g.FillEllipse($bgBrush, 5, 22, 8, 8)
        $g.FillEllipse($bgBrush, 14, 22, 8, 8)
        $g.FillEllipse($bgBrush, 22, 22, 8, 8)

        $shineBrush = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(200, 230, 255))
        $g.FillEllipse($shineBrush, 12, 9, 2, 2)
        $g.FillEllipse($shineBrush, 20, 9, 2, 2)

        $g.Dispose()

        $ms = New-Object System.IO.MemoryStream
        $bmp.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
        $pngBytes = $ms.ToArray()
        $ms.Dispose()
        $bmp.Dispose()

        $icoHeader = [byte[]]@(0, 0, 1, 0, 1, 0)
        $dirEntry = [byte[]]@(32, 32, 0, 0, 1, 0, 32, 0)
        $sizeBytes = [BitConverter]::GetBytes([int]$pngBytes.Length)
        $offsetBytes = [BitConverter]::GetBytes([int](6 + 16))

        $ico = $icoHeader + $dirEntry + $sizeBytes + $offsetBytes + $pngBytes
        [System.IO.File]::WriteAllBytes($OutPath, $ico)
    }
    catch {
        Write-Info "Icon fallback (System.Drawing unavailable)"
        $minIco = [byte[]]@(0, 0, 1, 0, 1, 0, 1, 1, 0, 0, 1, 0, 24, 0, 40, 0, 0, 0, 22, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 0, 24, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 80, 200, 255, 0, 0, 0, 0, 0)
        [System.IO.File]::WriteAllBytes($OutPath, $minIco)
    }
}

# ============================================================================
#  STEP 7: LAUNCHER & UNINSTALLER
# ============================================================================

function New-LauncherScripts {
    Write-Step "Generating Scripts"

    # ── Launcher ──
    $launcherContent = @"
# GhostShell Launcher (auto-generated)
`$Host.UI.RawUI.WindowTitle = "GhostShell"
`$env:GHOSTSHELL_HOME = "$Script:InstallRoot"
`$env:GHOSTSHELL_CONFIG = "$Script:ConfigDir\default.toml"
`$env:GHOSTSHELL_DATA = "$Script:DataDir"
if (`$env:PATH -notlike "*$Script:BinDir*") {
    `$env:PATH = "$Script:BinDir;`$env:PATH"
}
& "$Script:BinDir\$Script:BinaryName" --config "$Script:ConfigDir\default.toml" @args
"@
    Set-Content -Path "$Script:InstallRoot\ghostshell-launcher.ps1" -Value $launcherContent -Encoding UTF8
    Write-Ok "Launcher script"

    # ── Uninstaller ──
    New-Uninstaller
    Write-Ok "Uninstaller script"
}

function New-Uninstaller {
    $uninstallContent = @"
#Requires -Version 5.1
`$ErrorActionPreference = "Stop"
`$e = [char]0x1B
`$C = @{
    Blue="`$e[38;2;56;132;244m"; Cyan="`$e[38;2;86;196;240m"
    Green="`$e[38;2;60;220;140m"; Red="`$e[38;2;240;80;90m"
    White="`$e[38;2;220;225;240m"; Dim="`$e[38;2;90;95;115m"; Reset="`$e[0m"
}

Write-Host ""
Write-Host "`$(`$C.Cyan)  GhostShell Uninstaller`$(`$C.Reset)"
Write-Host "`$(`$C.Dim)  $([char]0x2550 * 40)`$(`$C.Reset)"
Write-Host ""
Write-Host "`$(`$C.White)  This will remove GhostShell and all Windows integrations.`$(`$C.Reset)"
Write-Host "`$(`$C.Red)  ! Session data in %LOCALAPPDATA%\GhostShell\data will be deleted.`$(`$C.Reset)"
Write-Host ""
Write-Host "`$(`$C.Cyan)  ? `$(`$C.White)Continue? (y/N)" -NoNewline
`$confirm = Read-Host " "
if (`$confirm -ne "y" -and `$confirm -ne "Y") {
    Write-Host "`$(`$C.Dim)  Cancelled.`$(`$C.Reset)"
    exit 0
}
Write-Host ""

# Start Menu
`$s = "`$env:APPDATA\Microsoft\Windows\Start Menu\Programs\GhostShell.lnk"
if (Test-Path `$s) { Remove-Item `$s -Force; Write-Host "`$(`$C.Green)  $([char]0x2714) Start Menu shortcut removed`$(`$C.Reset)" }

# Desktop
`$d = "`$env:USERPROFILE\Desktop\GhostShell.lnk"
if (Test-Path `$d) { Remove-Item `$d -Force; Write-Host "`$(`$C.Green)  $([char]0x2714) Desktop shortcut removed`$(`$C.Reset)" }

# PATH
`$UserPath = [Environment]::GetEnvironmentVariable("Path", "User")
`$binDir = "$Script:BinDir"
if (`$UserPath -like "*`$binDir*") {
    `$newPath = (`$UserPath -split ';' | Where-Object { `$_ -ne `$binDir }) -join ';'
    [Environment]::SetEnvironmentVariable("Path", `$newPath, "User")
    Write-Host "`$(`$C.Green)  $([char]0x2714) Removed from PATH`$(`$C.Reset)"
}

# Registry
`$reg = "$Script:UninstallReg"
if (Test-Path `$reg) { Remove-Item `$reg -Recurse -Force; Write-Host "`$(`$C.Green)  $([char]0x2714) Apps & Features entry removed`$(`$C.Reset)" }

# File associations
@("HKCU:\Software\Classes\.ghost", "HKCU:\Software\Classes\GhostShell.Recording") | ForEach-Object {
    if (Test-Path `$_) { Remove-Item `$_ -Recurse -Force }
}
Write-Host "`$(`$C.Green)  $([char]0x2714) File associations removed`$(`$C.Reset)"

# Context menu
`$ctx = "HKCU:\Software\Classes\Directory\Background\shell\GhostShell"
if (Test-Path `$ctx) { Remove-Item `$ctx -Recurse -Force; Write-Host "`$(`$C.Green)  $([char]0x2714) Context menu removed`$(`$C.Reset)" }

# Windows Terminal
`$wtPaths = @(
    "`$env:LOCALAPPDATA\Packages\Microsoft.WindowsTerminal_8wekyb3d8bbwe\LocalState\settings.json",
    "`$env:LOCALAPPDATA\Packages\Microsoft.WindowsTerminalPreview_8wekyb3d8bbwe\LocalState\settings.json"
)
foreach (`$wt in `$wtPaths) {
    if (Test-Path `$wt) {
        try {
            `$raw = Get-Content `$wt -Raw
            `$clean = `$raw -replace '(?m)^\s*//.*$','' -replace ',(\\s*[}\\]])', '`$1'
            `$json = `$clean | ConvertFrom-Json
            `$json.profiles.list = @(`$json.profiles.list | Where-Object { `$_.name -ne "GhostShell" })
            `$json.schemes = @(`$json.schemes | Where-Object { `$_.name -ne "GhostShell" })
            `$json | ConvertTo-Json -Depth 10 | Set-Content `$wt -Encoding UTF8
            Write-Host "`$(`$C.Green)  $([char]0x2714) Terminal profile removed`$(`$C.Reset)"
        } catch { }
    }
}

# Config
`$cfgDir = "$Script:ConfigDir"
if (Test-Path `$cfgDir) {
    Write-Host "`$(`$C.Cyan)  ? `$(`$C.White)Delete config? (y/N)" -NoNewline
    `$dc = Read-Host " "
    if (`$dc -eq "y" -or `$dc -eq "Y") {
        Remove-Item `$cfgDir -Recurse -Force
        Write-Host "`$(`$C.Green)  $([char]0x2714) Config removed`$(`$C.Reset)"
    } else {
        Write-Host "`$(`$C.Dim)  | Config preserved`$(`$C.Reset)"
    }
}

Write-Host ""
Write-Host "`$(`$C.Green)  $([char]0x2714) GhostShell uninstalled.`$(`$C.Reset)"
Write-Host "`$(`$C.Dim)  | You can delete: $Script:InstallRoot`$(`$C.Reset)"
Write-Host ""

Start-Process pwsh -ArgumentList "-NoProfile -Command `"Start-Sleep 2; Remove-Item '$Script:InstallRoot' -Recurse -Force -ErrorAction SilentlyContinue`"" -WindowStyle Hidden
"@

    Set-Content -Path "$Script:InstallRoot\uninstall.ps1" -Value $uninstallContent -Encoding UTF8
}

# ============================================================================
#  STEP 9: SUMMARY
# ============================================================================

function Show-Summary {
    Write-Step "Installation Complete!"

    Show-FogBlock -Lines 1

    Write-Host ""
    $line = [string]::new([char]0x2550, 56)
    Write-Centered $line $C.PSCyan
    Write-Host ""
    Write-Centered "$($C.Green)$($C.Bold)GhostShell v$Script:AppVersion installed successfully!$($C.Reset)"
    Write-Host ""

    # Info table
    $rows = @(
        @("Binary", "$Script:BinDir\$Script:BinaryName"),
        @("Config", $Script:ConfigDir),
        @("Data", $Script:DataDir),
        @("Plugins", $Script:PluginsDir),
        @("Uninstaller", "$Script:InstallRoot\uninstall.ps1")
    )

    foreach ($r in $rows) {
        $label = $r[0].PadRight(14)
        Write-Host "    $($C.Dim)$label$($C.PSCyan)$($r[1])$($C.Reset)"
    }

    Write-Host ""
    Write-Line ([char]0x2500) $C.Dim

    # Usage table
    Write-Host ""
    Write-Host "    $($C.White)$($C.Bold)How to Launch$($C.Reset)"
    Write-Host ""

    $cmds = @(
        @("Terminal", "ghostshell"),
        @("Stealth", "ghostshell --stealth"),
        @("Decoy Mode", "ghostshell --decoy"),
        @("Start Menu", "Search 'GhostShell'"),
        @("Right-click", "'Open GhostShell Here' in Explorer"),
        @("Win Terminal", "Select 'GhostShell' profile"),
        @("Help", "ghostshell --help"),
        @("Uninstall", "Settings > Apps > GhostShell")
    )

    foreach ($cmd in $cmds) {
        $label = $cmd[0].PadRight(16)
        Write-Host "    $($C.Dim)$label$($C.PSCyan)$($cmd[1])$($C.Reset)"
    }

    Write-Host ""
    Show-FogBlock -Lines 2

    Write-Host ""
    Write-Centered "Re-open your terminal for PATH changes to take effect." $C.Dim
    Write-Host ""
    Write-Centered "$($C.Purple)$($C.Bold)Stay invisible. Stay encrypted. Stay ghost.$($C.Reset)"
    Write-Host ""

    # Final ghost float
    if (-not $NoEffects) {
        Show-GhostFloat
    }
    Write-Host ""
}

# ============================================================================
#  MAIN EXECUTION
# ============================================================================

Show-Splash
Test-SystemRequirements
Install-Prerequisites
Get-Repository
Build-GhostShell
Install-Application
Register-WindowsApp
New-LauncherScripts
Show-Summary
