# ╔══════════════════════════════════════════════════════════════════════╗
# ║           👻 GhostShell — Premium Windows 11 Installer              ║
# ║        Stealth Terminal Multiplexer · v0.1.0                        ║
# ╚══════════════════════════════════════════════════════════════════════╝
#
# One-liner:  irm https://raw.githubusercontent.com/AcerThyRacer/GhostShell/main/install.ps1 | iex

#Requires -Version 5.1
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

# ESC character for ANSI codes — [char]0x1B works in PS 5.1+ (backtick-e only works in PS 6+)
$Script:E = [char]0x1B

# ─── Paths & Constants ────────────────────────────────────────────────
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

# ─── Color Palette ────────────────────────────────────────────────────
$Script:C = @{
    Ghost  = "$E[38;2;80;200;255m"
    Green  = "$E[38;2;0;255;160m"
    Red    = "$E[38;2;255;60;80m"
    Yellow = "$E[38;2;255;200;80m"
    Purple = "$E[38;2;180;120;255m"
    Dim    = "$E[38;2;90;90;120m"
    White  = "$E[38;2;220;220;240m"
    BgDark = "$E[48;2;10;10;18m"
    Bold   = "$E[1m"
    Reset  = "$E[0m"
}

# ─── Helper Functions ─────────────────────────────────────────────────

function Write-Ghost { param($Msg) Write-Host "$($C.Ghost)  👻 $Msg$($C.Reset)" }
function Write-Ok { param($Msg) Write-Host "$($C.Green)  ✓ $Msg$($C.Reset)" }
function Write-Warn { param($Msg) Write-Host "$($C.Yellow)  ⚠ $Msg$($C.Reset)" }
function Write-Fail { param($Msg) Write-Host "$($C.Red)  ✗ $Msg$($C.Reset)"; exit 1 }
function Write-Info { param($Msg) Write-Host "$($C.Dim)  │ $Msg$($C.Reset)" }
function Write-Step {
    param($Msg)
    $Script:StepsDone++
    $pct = [math]::Round(($Script:StepsDone / $Script:TotalSteps) * 100)
    $bar = ("█" * [math]::Floor($pct / 5)).PadRight(20, "░")
    Write-Host ""
    Write-Host "$($C.Purple)  [$Script:StepsDone/$Script:TotalSteps] $($C.Bold)$($C.White)$Msg$($C.Reset)"
    Write-Host "$($C.Dim)  │ $($C.Ghost)$bar$($C.Dim) $pct%$($C.Reset)"
}

function Write-Section {
    param($Msg)
    $line = "─" * 58
    Write-Host "$($C.Dim)  ┌$line┐$($C.Reset)"
    Write-Host "$($C.Dim)  │ $($C.Ghost)$($C.Bold)$Msg$($C.Reset)$($C.Dim)$(' ' * (57 - $Msg.Length))│$($C.Reset)"
    Write-Host "$($C.Dim)  └$line┘$($C.Reset)"
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

# ─── Animated Splash Screen ──────────────────────────────────────────
function Show-Splash {
    Clear-Host
    $art = @"

$($C.Ghost)$($C.Bold)
              ░██████╗░██╗░░██╗░█████╗░░██████╗████████╗
              ██╔════╝░██║░░██║██╔══██╗██╔════╝╚══██╔══╝
              ██║░░██╗░███████║██║░░██║╚█████╗░░░░██║░░░
              ██║░░╚██╗██╔══██║██║░░██║░╚═══██╗░░░██║░░░
              ╚██████╔╝██║░░██║╚█████╔╝██████╔╝░░░██║░░░
              ░╚═════╝░╚═╝░░╚═╝░╚════╝░╚═════╝░░░░╚═╝░░░
$($C.Purple)
              ░██████╗██╗░░██╗███████╗██╗░░░░░██╗░░░░░
              ██╔════╝██║░░██║██╔════╝██║░░░░░██║░░░░░
              ╚█████╗░███████║█████╗░░██║░░░░░██║░░░░░
              ░╚═══██╗██╔══██║██╔══╝░░██║░░░░░██║░░░░░
              ██████╔╝██║░░██║███████╗███████╗███████╗
              ╚═════╝░╚═╝░░╚═╝╚══════╝╚══════╝╚══════╝
$($C.Reset)
"@
    Write-Host $art
    Write-Host "$($C.Dim)  ═══════════════════════════════════════════════════════════════$($C.Reset)"
    Write-Host "$($C.White)$($C.Bold)           Stealth Terminal Multiplexer · Windows Installer$($C.Reset)"
    Write-Host "$($C.Dim)           v$Script:AppVersion · by $Script:AppPublisher$($C.Reset)"
    Write-Host "$($C.Dim)  ═══════════════════════════════════════════════════════════════$($C.Reset)"
    Write-Host ""
    # Feature highlights
    $features = @(
        "$($C.Ghost)🔐$($C.White) Encrypted Sessions$($C.Dim) — ChaCha20-Poly1305 + Argon2id",
        "$($C.Ghost)🎭$($C.White) Decoy Shells$($C.Dim) — Panic key instant environment switch",
        "$($C.Ghost)🛡️$($C.White) Intrusion Detection$($C.Dim) — Anomaly-based IDS with biometrics",
        "$($C.Ghost)👻$($C.White) Process Cloaking$($C.Dim) — Anti-forensic stealth features",
        "$($C.Ghost)🔗$($C.White) P2P Tunneling$($C.Dim) — Noise Protocol encrypted tunnels",
        "$($C.Ghost)📋$($C.White) Secure Clipboard$($C.Dim) — Auto-wiping with TTL limits",
        "$($C.Ghost)🖼️$($C.White) Steganography$($C.Dim) — Hide sessions inside PNG images",
        "$($C.Ghost)💀$($C.White) Dead Man's Switch$($C.Dim) — Auto-lock on inactivity"
    )
    foreach ($f in $features) {
        Write-Host "  $f$($C.Reset)"
        Start-Sleep -Milliseconds 60
    }
    Write-Host ""
    Write-Host "$($C.Dim)  ───────────────────────────────────────────────────────────────$($C.Reset)"
    Write-Host ""
}

# ─── System Requirements Check ────────────────────────────────────────
function Test-SystemRequirements {
    Write-Step "Checking System Requirements"

    # OS Version
    $os = [System.Environment]::OSVersion
    $build = [int](Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -ErrorAction SilentlyContinue).CurrentBuildNumber
    if ($build -ge 22000) {
        Write-Ok "Windows 11 (Build $build)"
    }
    elseif ($build -ge 10240) {
        Write-Ok "Windows 10 (Build $build)"
    }
    else {
        Write-Warn "Windows version may not be fully supported (Build $build)"
    }

    # Architecture
    $arch = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture
    Write-Ok "Architecture: $arch"

    # Disk space
    $drive = (Split-Path $env:LOCALAPPDATA -Qualifier)
    $freeGB = [math]::Round((Get-PSDrive ($drive -replace ':', '') | Select-Object -ExpandProperty Free) / 1GB, 1)
    if ($freeGB -lt 2) {
        Write-Fail "Insufficient disk space: ${freeGB}GB free (need at least 2GB)"
    }
    Write-Ok "Disk space: ${freeGB}GB free"

    # PowerShell version
    Write-Ok "PowerShell: $($PSVersionTable.PSVersion)"
}

# ─── Prerequisite Installation ────────────────────────────────────────
function Install-Prerequisites {
    Write-Step "Installing Prerequisites"

    # ── Git ──
    if (Test-CommandExists "git") {
        $gitVer = (git --version 2>&1) -replace 'git version ', ''
        Write-Ok "Git $gitVer"
    }
    else {
        Write-Warn "Git not found"
        Write-Info "Installing Git via winget..."
        try {
            winget install --id Git.Git -e --accept-source-agreements --accept-package-agreements --silent 2>&1 | Out-Null
            $env:PATH = "$env:ProgramFiles\Git\cmd;$env:PATH"
            if (Test-CommandExists "git") {
                Write-Ok "Git installed successfully"
            }
            else {
                Write-Fail "Git installation failed. Please install from https://git-scm.com"
            }
        }
        catch {
            Write-Fail "Git installation failed. Please install from https://git-scm.com"
        }
    }

    # ── Rust Toolchain ──
    $CargoBin = "$env:USERPROFILE\.cargo\bin"
    if ($env:PATH -notlike "*$CargoBin*") {
        $env:PATH = "$CargoBin;$env:PATH"
    }

    if (Test-CommandExists "cargo") {
        $rustVer = (rustc --version 2>&1) -replace 'rustc ', ''
        Write-Ok "Rust $rustVer"
    }
    else {
        Write-Warn "Rust toolchain not found"
        Write-Info "Installing Rust via rustup..."
        $RustupInit = "$env:TEMP\rustup-init.exe"
        try {
            Invoke-WebRequest -Uri "https://win.rustup.rs/x86_64" -OutFile $RustupInit -UseBasicParsing
            & $RustupInit -y --quiet 2>&1 | Out-Null
            Remove-Item $RustupInit -ErrorAction SilentlyContinue
            $env:PATH = "$CargoBin;$env:PATH"
            if (Test-CommandExists "cargo") {
                Write-Ok "Rust installed successfully"
            }
            else {
                Write-Fail "Rust installation failed. Visit https://rustup.rs"
            }
        }
        catch {
            Write-Fail "Rust installation failed: $_"
        }
    }

    # ── C/C++ Compiler (MSVC check) ──
    $hasCC = $null -ne (Get-Command "cl.exe" -ErrorAction SilentlyContinue) -or
    (Test-Path "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe")
    if ($hasCC) {
        Write-Ok "C/C++ compiler (MSVC) detected"
    }
    else {
        Write-Warn "Visual Studio Build Tools not detected"
        Write-Info "Installing VS Build Tools (this may take several minutes)..."
        try {
            winget install --id Microsoft.VisualStudio.2022.BuildTools -e --accept-source-agreements --accept-package-agreements --silent --override "--add Microsoft.VisualStudio.Workload.VCTools --quiet --wait" 2>&1 | Out-Null
            Write-Ok "VS Build Tools installed"
        }
        catch {
            Write-Warn "Auto-install failed — Rust may still compile via gnu toolchain"
            Write-Info "If the build fails, install VS Build Tools from https://visualstudio.microsoft.com/visual-cpp-build-tools/"
        }
    }
}

# ─── Clone / Update Repository ────────────────────────────────────────
function Get-Repository {
    Write-Step "Fetching GhostShell Source"

    if (Test-Path "$Script:SourceDir\.git") {
        Write-Info "Updating existing source..."
        Push-Location $Script:SourceDir
        & git pull --quiet 2>&1 | Out-Null
        Pop-Location
        Write-Ok "Source code updated"
    }
    else {
        if (Test-Path $Script:SourceDir) {
            Remove-Item -Recurse -Force $Script:SourceDir -ErrorAction SilentlyContinue
        }
        Write-Info "Cloning repository..."
        & git clone --quiet --depth 1 $Script:Repo $Script:SourceDir 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Fail "Failed to clone repository"
        }
        Write-Ok "Source code cloned"
    }
}

# ─── Build ─────────────────────────────────────────────────────────────
function Build-GhostShell {
    Write-Step "Building GhostShell (Release Mode)"
    Write-Info "This may take 2-5 minutes on first build..."
    Write-Info "[debug] Build function v2 — Start-Process isolation"

    Push-Location $Script:SourceDir

    # Use Start-Process to completely isolate cargo's stderr from PowerShell.
    # PS 5.1 converts stderr to ErrorRecord objects which throw NativeCommandError
    # when $ErrorActionPreference = "Stop". By using Start-Process with file-based
    # redirection, stderr NEVER touches PowerShell's pipeline.
    $buildLog = "$env:TEMP\ghostshell-build-stderr.log"
    $buildStdout = "$env:TEMP\ghostshell-build-stdout.log"
    Remove-Item $buildLog, $buildStdout -ErrorAction SilentlyContinue

    $proc = Start-Process -FilePath "cargo" `
        -ArgumentList "build", "--release" `
        -WorkingDirectory (Get-Location).Path `
        -NoNewWindow -PassThru `
        -RedirectStandardError $buildLog `
        -RedirectStandardOutput $buildStdout

    # Poll the build log for real-time progress
    $lastCrate = ""
    while (-not $proc.HasExited) {
        Start-Sleep -Milliseconds 500
        if (Test-Path $buildLog) {
            $tail = Get-Content $buildLog -Tail 5 -ErrorAction SilentlyContinue
            foreach ($line in $tail) {
                if ($line -match 'Compiling (.+?) v' -and $Matches[1] -ne $lastCrate) {
                    $lastCrate = $Matches[1]
                    Write-Host "`r$($C.Dim)  │ $($C.Ghost)⚙$($C.Dim) Compiling $lastCrate$($C.Reset)              " -NoNewline
                }
            }
        }
    }
    $proc.WaitForExit()
    $buildResult = $proc.ExitCode
    Write-Host ""

    # Show errors if build failed
    if ($buildResult -ne 0 -and (Test-Path $buildLog)) {
        Write-Host ""
        Get-Content $buildLog | ForEach-Object {
            if ($_ -match '^error') {
                Write-Host "$($C.Red)  │ $_$($C.Reset)"
            }
        }
    }

    # Cleanup temp files
    Remove-Item $buildLog, $buildStdout -ErrorAction SilentlyContinue

    Pop-Location

    if ($buildResult -ne 0) {
        Write-Fail "Build failed (exit code: $buildResult). Check errors above."
    }

    $builtBinary = "$Script:SourceDir\target\release\$Script:BinaryName"
    if (-not (Test-Path $builtBinary)) {
        Write-Fail "Binary not found at $builtBinary"
    }

    Write-Host ""
    Write-Ok "Build complete"
}

# ─── Install Binary & Directories ─────────────────────────────────────
function Install-Application {
    Write-Step "Installing Application"

    # Create directory structure
    $dirs = @($Script:BinDir, $Script:DataDir, $Script:ConfigDir, $Script:PluginsDir)
    foreach ($d in $dirs) {
        if (-not (Test-Path $d)) {
            New-Item -ItemType Directory -Path $d -Force | Out-Null
        }
    }
    Write-Ok "Directory structure created"

    # Copy binary
    $builtBinary = "$Script:SourceDir\target\release\$Script:BinaryName"
    Copy-Item $builtBinary "$Script:BinDir\$Script:BinaryName" -Force
    Write-Ok "Binary installed to $Script:BinDir"

    # Copy default config if not already present
    $defaultConfig = "$Script:SourceDir\config\default.toml"
    $targetConfig = "$Script:ConfigDir\default.toml"
    if ((Test-Path $defaultConfig) -and -not (Test-Path $targetConfig)) {
        Copy-Item $defaultConfig $targetConfig -Force
        Write-Ok "Default configuration installed"
    }
    elseif (Test-Path $targetConfig) {
        Write-Info "Existing configuration preserved"
    }

    # Add to PATH
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

# ─── Windows Integration ──────────────────────────────────────────────
function Register-WindowsApp {
    Write-Step "Integrating with Windows 11"

    # ── Generate App Icon (.ico from embedded data) ──
    $iconPath = "$Script:InstallRoot\ghostshell.ico"
    Generate-AppIcon $iconPath
    Write-Ok "App icon generated"

    # ── Start Menu Shortcut ──
    $startMenu = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs"
    $shortcutPath = "$startMenu\GhostShell.lnk"
    New-Shortcut -ShortcutPath $shortcutPath `
        -TargetPath "pwsh.exe" `
        -Arguments "-NoProfile -ExecutionPolicy Bypass -File `"$Script:InstallRoot\ghostshell-launcher.ps1`"" `
        -IconPath $iconPath `
        -WorkingDir $env:USERPROFILE `
        -Description "GhostShell — Stealth Terminal Multiplexer"
    Write-Ok "Start Menu shortcut created"

    # ── Desktop Shortcut (prompt) ──
    Write-Host ""
    Write-Host "$($C.Ghost)  ? $($C.White)Create Desktop shortcut? $($C.Dim)(Y/n)$($C.Reset)" -NoNewline
    $desktopChoice = Read-Host " "
    if ($desktopChoice -ne "n" -and $desktopChoice -ne "N") {
        $desktopShortcut = "$env:USERPROFILE\Desktop\GhostShell.lnk"
        New-Shortcut -ShortcutPath $desktopShortcut `
            -TargetPath "pwsh.exe" `
            -Arguments "-NoProfile -ExecutionPolicy Bypass -File `"$Script:InstallRoot\ghostshell-launcher.ps1`"" `
            -IconPath $iconPath `
            -WorkingDir $env:USERPROFILE `
            -Description "GhostShell — Stealth Terminal Multiplexer"
        Write-Ok "Desktop shortcut created"
    }

    # ── Register in Apps & Features ──
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
        Comments        = "Stealth Terminal Multiplexer with Encrypted Sessions, Decoy Shells & Intrusion Detection"
    }
    if (-not (Test-Path $Script:UninstallReg)) {
        New-Item -Path $Script:UninstallReg -Force | Out-Null
    }
    foreach ($key in $regProps.Keys) {
        Set-ItemProperty -Path $Script:UninstallReg -Name $key -Value $regProps[$key]
    }
    Write-Ok "Registered in Apps & Features"

    # ── .ghost File Association ──
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
    Write-Ok "File association: .ghost → GhostShell"

    # ── Context Menu: "Open GhostShell Here" ──
    $ctxKey = "HKCU:\Software\Classes\Directory\Background\shell\GhostShell"
    $ctxCmd = "$ctxKey\command"
    New-Item -Path $ctxKey -Force | Out-Null
    Set-ItemProperty -Path $ctxKey -Name "(Default)" -Value "Open GhostShell Here 👻"
    Set-ItemProperty -Path $ctxKey -Name "Icon" -Value $iconPath
    New-Item -Path $ctxCmd -Force | Out-Null
    Set-ItemProperty -Path $ctxCmd -Name "(Default)" -Value "pwsh.exe -NoProfile -ExecutionPolicy Bypass -Command `"& '$Script:BinDir\$Script:BinaryName'`""
    Write-Ok "Context menu: 'Open GhostShell Here'"

    # ── Windows Terminal Profile ──
    Inject-WindowsTerminalProfile $iconPath
}

# ─── Windows Terminal Profile Injection ────────────────────────────────
function Inject-WindowsTerminalProfile {
    param($IconPath)

    $wtSettings = "$env:LOCALAPPDATA\Packages\Microsoft.WindowsTerminal_8wekyb3d8bbwe\LocalState\settings.json"
    $wtPreview = "$env:LOCALAPPDATA\Packages\Microsoft.WindowsTerminalPreview_8wekyb3d8bbwe\LocalState\settings.json"

    $profileGuid = "{7f3b2d85-a09c-4e47-b834-gh0st5hell01}"
    $profileObj = @{
        guid              = $profileGuid
        name              = "👻 GhostShell"
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
        background          = "#0A0A12"
        foreground          = "#B4BEC8"
        cursorColor         = "#50C8FF"
        black               = "#1A1A2E"
        red                 = "#FF3C50"
        green               = "#00FFA0"
        yellow              = "#FFC850"
        blue                = "#50C8FF"
        purple              = "#B478FF"
        cyan                = "#50C8FF"
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

    foreach ($settingsFile in @($wtSettings, $wtPreview)) {
        if (-not (Test-Path $settingsFile)) { continue }
        try {
            $raw = Get-Content $settingsFile -Raw
            # Strip single-line comments for JSON parsing
            $clean = $raw -replace '(?m)^\s*//.*$', '' -replace ',(\s*[}\]])', '$1'
            $json = $clean | ConvertFrom-Json

            # Add color scheme if missing
            if (-not ($json.schemes | Where-Object { $_.name -eq "GhostShell" })) {
                $json.schemes += [PSCustomObject]$schemeObj
            }

            # Add profile if missing
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
            Write-Warn "Could not update Windows Terminal settings: $_"
        }
    }
    Write-Info "Windows Terminal not found — skipping profile injection"
}

# ─── Generate App Icon ─────────────────────────────────────────────────
function Generate-AppIcon {
    param($OutPath)
    # Generate a simple .ico file with a ghost-themed design using .NET
    # We create a 32x32 and 16x16 icon programmatically
    Add-Type -AssemblyName System.Drawing -ErrorAction SilentlyContinue

    try {
        $bmp = New-Object System.Drawing.Bitmap(32, 32)
        $g = [System.Drawing.Graphics]::FromImage($bmp)
        $g.Clear([System.Drawing.Color]::FromArgb(10, 10, 18))

        # Ghost body (cyan rounded shape)
        $ghostBrush = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(80, 200, 255))
        $g.FillEllipse($ghostBrush, 6, 2, 20, 18)
        $g.FillRectangle($ghostBrush, 6, 12, 20, 14)

        # Ghost eyes
        $eyeBrush = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(10, 10, 18))
        $g.FillEllipse($eyeBrush, 11, 8, 4, 5)
        $g.FillEllipse($eyeBrush, 19, 8, 4, 5)

        # Ghost bottom waves
        $bgBrush = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(10, 10, 18))
        $g.FillEllipse($bgBrush, 5, 22, 8, 8)
        $g.FillEllipse($bgBrush, 14, 22, 8, 8)
        $g.FillEllipse($bgBrush, 22, 22, 8, 8)

        # Eye shine
        $shineBrush = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(200, 230, 255))
        $g.FillEllipse($shineBrush, 12, 9, 2, 2)
        $g.FillEllipse($shineBrush, 20, 9, 2, 2)

        $g.Dispose()

        # Save as .ico
        $ms = New-Object System.IO.MemoryStream
        $bmp.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
        $pngBytes = $ms.ToArray()
        $ms.Dispose()
        $bmp.Dispose()

        # ICO format: header + directory entry + PNG data
        $icoHeader = [byte[]]@(0, 0, 1, 0, 1, 0)  # reserved, type=icon, count=1
        $dirEntry = [byte[]]@(
            32,  # width
            32,  # height
            0,   # color palette
            0,   # reserved
            1, 0, # color planes
            32, 0 # bits per pixel
        )
        $sizeBytes = [BitConverter]::GetBytes([int]$pngBytes.Length)
        $offsetBytes = [BitConverter]::GetBytes([int](6 + 16))  # header(6) + dir(16)

        $ico = $icoHeader + $dirEntry + $sizeBytes + $offsetBytes + $pngBytes
        [System.IO.File]::WriteAllBytes($OutPath, $ico)
    }
    catch {
        # Fallback: create a simple placeholder
        Write-Info "Icon generation fallback (System.Drawing unavailable)"
        # Write minimal valid .ico
        $minIco = [byte[]]@(0, 0, 1, 0, 1, 0, 1, 1, 0, 0, 1, 0, 24, 0, 40, 0, 0, 0, 22, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 0, 24, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 80, 200, 255, 0, 0, 0, 0, 0)
        [System.IO.File]::WriteAllBytes($OutPath, $minIco)
    }
}

# ─── Generate Launcher Script ─────────────────────────────────────────
function Generate-Launcher {
    Write-Step "Generating Launcher & Uninstaller"

    # ── Launcher ──
    $launcherContent = @"
# GhostShell Launcher — Auto-generated
`$Host.UI.RawUI.WindowTitle = "GhostShell"
`$env:GHOSTSHELL_HOME = "$Script:InstallRoot"
`$env:GHOSTSHELL_CONFIG = "$Script:ConfigDir\default.toml"
`$env:GHOSTSHELL_DATA = "$Script:DataDir"

# Ensure binary is on path
if (`$env:PATH -notlike "*$Script:BinDir*") {
    `$env:PATH = "$Script:BinDir;`$env:PATH"
}

# Launch GhostShell with args passthrough
& "$Script:BinDir\$Script:BinaryName" --config "$Script:ConfigDir\default.toml" @args
"@
    Set-Content -Path "$Script:InstallRoot\ghostshell-launcher.ps1" -Value $launcherContent -Encoding UTF8
    Write-Ok "Launcher script created"

    # ── Uninstaller ──
    Generate-Uninstaller
    Write-Ok "Uninstaller created"
}

# ─── Generate Uninstaller ──────────────────────────────────────────────
function Generate-Uninstaller {
    $uninstallContent = @"
# ╔══════════════════════════════════════════════════════════════╗
# ║           GhostShell — Uninstaller                          ║
# ╚══════════════════════════════════════════════════════════════╝
#Requires -Version 5.1

`$ErrorActionPreference = "Stop"
`$e = [char]0x1B
`$C = @{ Ghost="`$e[38;2;80;200;255m"; Red="`$e[38;2;255;60;80m"; Green="`$e[38;2;0;255;160m"; Dim="`$e[38;2;90;90;120m"; White="`$e[38;2;220;220;240m"; Reset="`$e[0m" }

Write-Host ""
Write-Host "`$(`$C.Ghost)  GhostShell Uninstaller`$(`$C.Reset)"
Write-Host "`$(`$C.Dim)  ═══════════════════════════════════════`$(`$C.Reset)"
Write-Host ""
Write-Host "`$(`$C.White)  This will remove GhostShell and all Windows integrations.`$(`$C.Reset)"
Write-Host "`$(`$C.Red)  ⚠ Session data in %LOCALAPPDATA%\GhostShell\data will be DELETED.`$(`$C.Reset)"
Write-Host ""
Write-Host "`$(`$C.Ghost)  ? `$(`$C.White)Continue? (y/N)" -NoNewline
`$confirm = Read-Host " "
if (`$confirm -ne "y" -and `$confirm -ne "Y") {
    Write-Host "`$(`$C.Dim)  Cancelled.`$(`$C.Reset)"
    exit 0
}

Write-Host ""

# Remove Start Menu shortcut
`$startShortcut = "`$env:APPDATA\Microsoft\Windows\Start Menu\Programs\GhostShell.lnk"
if (Test-Path `$startShortcut) { Remove-Item `$startShortcut -Force; Write-Host "`$(`$C.Green)  ✓ Start Menu shortcut removed`$(`$C.Reset)" }

# Remove Desktop shortcut
`$deskShortcut = "`$env:USERPROFILE\Desktop\GhostShell.lnk"
if (Test-Path `$deskShortcut) { Remove-Item `$deskShortcut -Force; Write-Host "`$(`$C.Green)  ✓ Desktop shortcut removed`$(`$C.Reset)" }

# Remove from PATH
`$UserPath = [Environment]::GetEnvironmentVariable("Path", "User")
`$binDir = "$Script:BinDir"
if (`$UserPath -like "*`$binDir*") {
    `$newPath = (`$UserPath -split ';' | Where-Object { `$_ -ne `$binDir }) -join ';'
    [Environment]::SetEnvironmentVariable("Path", `$newPath, "User")
    Write-Host "`$(`$C.Green)  ✓ Removed from PATH`$(`$C.Reset)"
}

# Remove Apps & Features registration
`$uninstReg = "$Script:UninstallReg"
if (Test-Path `$uninstReg) { Remove-Item `$uninstReg -Recurse -Force; Write-Host "`$(`$C.Green)  ✓ Apps & Features entry removed`$(`$C.Reset)" }

# Remove file association
@("HKCU:\Software\Classes\.ghost", "HKCU:\Software\Classes\GhostShell.Recording") | ForEach-Object {
    if (Test-Path `$_) { Remove-Item `$_ -Recurse -Force }
}
Write-Host "`$(`$C.Green)  ✓ File associations removed`$(`$C.Reset)"

# Remove context menu
`$ctxKey = "HKCU:\Software\Classes\Directory\Background\shell\GhostShell"
if (Test-Path `$ctxKey) { Remove-Item `$ctxKey -Recurse -Force; Write-Host "`$(`$C.Green)  ✓ Context menu entry removed`$(`$C.Reset)" }

# Remove Windows Terminal profile
`$wtPaths = @(
    "`$env:LOCALAPPDATA\Packages\Microsoft.WindowsTerminal_8wekyb3d8bbwe\LocalState\settings.json",
    "`$env:LOCALAPPDATA\Packages\Microsoft.WindowsTerminalPreview_8wekyb3d8bbwe\LocalState\settings.json"
)
foreach (`$wt in `$wtPaths) {
    if (Test-Path `$wt) {
        try {
            `$raw = Get-Content `$wt -Raw
            `$clean = `$raw -replace '(?m)^\s*//.*$','' -replace ',(\s*[}\]])', '`$1'
            `$json = `$clean | ConvertFrom-Json
            `$json.profiles.list = @(`$json.profiles.list | Where-Object { `$_.name -ne "👻 GhostShell" })
            `$json.schemes = @(`$json.schemes | Where-Object { `$_.name -ne "GhostShell" })
            `$json | ConvertTo-Json -Depth 10 | Set-Content `$wt -Encoding UTF8
            Write-Host "`$(`$C.Green)  ✓ Windows Terminal profile removed`$(`$C.Reset)"
        } catch { }
    }
}

# Remove config directory
`$configDir = "$Script:ConfigDir"
if (Test-Path `$configDir) {
    Write-Host "`$(`$C.Ghost)  ? `$(`$C.White)Delete configuration? (y/N)" -NoNewline
    `$delConfig = Read-Host " "
    if (`$delConfig -eq "y" -or `$delConfig -eq "Y") {
        Remove-Item `$configDir -Recurse -Force
        Write-Host "`$(`$C.Green)  ✓ Configuration removed`$(`$C.Reset)"
    } else {
        Write-Host "`$(`$C.Dim)  │ Config preserved at `$configDir`$(`$C.Reset)"
    }
}

# Remove install directory (schedule because we're running from it)
Write-Host ""
Write-Host "`$(`$C.Green)  ✓ GhostShell uninstalled successfully`$(`$C.Reset)"
Write-Host "`$(`$C.Dim)  │ Installation directory will be removed on next reboot or you can`$(`$C.Reset)"
Write-Host "`$(`$C.Dim)  │ manually delete: $Script:InstallRoot`$(`$C.Reset)"
Write-Host ""

# Try to remove install dir
Start-Process pwsh -ArgumentList "-NoProfile -Command `"Start-Sleep 2; Remove-Item '$Script:InstallRoot' -Recurse -Force -ErrorAction SilentlyContinue`"" -WindowStyle Hidden
"@

    Set-Content -Path "$Script:InstallRoot\uninstall.ps1" -Value $uninstallContent -Encoding UTF8
}

# ─── Installation Summary ─────────────────────────────────────────────
function Show-Summary {
    Write-Step "Installation Complete!"

    Write-Host ""
    $line = "═" * 58
    Write-Host "$($C.Ghost)  $line$($C.Reset)"
    Write-Host ""
    Write-Host "$($C.Green)$($C.Bold)  ✓ GhostShell v$Script:AppVersion installed successfully!$($C.Reset)"
    Write-Host ""
    Write-Host "$($C.Dim)  ┌──────────────────────────────────────────────────────────┐$($C.Reset)"
    Write-Host "$($C.Dim)  │$($C.White)  Binary:        $($C.Ghost)$Script:BinDir\$Script:BinaryName$($C.Dim)     │$($C.Reset)"
    Write-Host "$($C.Dim)  │$($C.White)  Config:        $($C.Ghost)$Script:ConfigDir$($C.Dim)     │$($C.Reset)"
    Write-Host "$($C.Dim)  │$($C.White)  Data:          $($C.Ghost)$Script:DataDir$($C.Dim)     │$($C.Reset)"
    Write-Host "$($C.Dim)  │$($C.White)  Plugins:       $($C.Ghost)$Script:PluginsDir$($C.Dim)     │$($C.Reset)"
    Write-Host "$($C.Dim)  │$($C.White)  Uninstaller:   $($C.Ghost)$Script:InstallRoot\uninstall.ps1$($C.Dim)     │$($C.Reset)"
    Write-Host "$($C.Dim)  └──────────────────────────────────────────────────────────┘$($C.Reset)"
    Write-Host ""
    Write-Host "$($C.Dim)  ┌──────────────── How to Launch ──────────────────────────┐$($C.Reset)"
    Write-Host "$($C.Dim)  │$($C.Reset)                                                          $($C.Dim)│$($C.Reset)"
    Write-Host "$($C.Dim)  │$($C.White)  Terminal:     $($C.Ghost)ghostshell$($C.Dim)                               │$($C.Reset)"
    Write-Host "$($C.Dim)  │$($C.White)  Stealth:      $($C.Ghost)ghostshell --stealth$($C.Dim)                     │$($C.Reset)"
    Write-Host "$($C.Dim)  │$($C.White)  Decoy Mode:   $($C.Ghost)ghostshell --decoy$($C.Dim)                       │$($C.Reset)"
    Write-Host "$($C.Dim)  │$($C.White)  Start Menu:   $($C.Ghost)Search for 'GhostShell'$($C.Dim)                  │$($C.Reset)"
    Write-Host "$($C.Dim)  │$($C.White)  Right-click:  $($C.Ghost)'Open GhostShell Here' in Explorer$($C.Dim)       │$($C.Reset)"
    Write-Host "$($C.Dim)  │$($C.White)  Win Terminal: $($C.Ghost)Select '👻 GhostShell' profile$($C.Dim)           │$($C.Reset)"
    Write-Host "$($C.Dim)  │$($C.Reset)                                                          $($C.Dim)│$($C.Reset)"
    Write-Host "$($C.Dim)  │$($C.White)  Help:         $($C.Ghost)ghostshell --help$($C.Dim)                        │$($C.Reset)"
    Write-Host "$($C.Dim)  │$($C.White)  Uninstall:    $($C.Ghost)Settings → Apps → GhostShell$($C.Dim)             │$($C.Reset)"
    Write-Host "$($C.Dim)  │$($C.Reset)                                                          $($C.Dim)│$($C.Reset)"
    Write-Host "$($C.Dim)  └──────────────────────────────────────────────────────────┘$($C.Reset)"
    Write-Host ""
    Write-Host "$($C.Dim)  Re-open your terminal for PATH changes to take effect.$($C.Reset)"
    Write-Host ""
    Write-Host "$($C.Purple)  👻 Stay invisible. Stay encrypted. Stay ghost.$($C.Reset)"
    Write-Host ""
}

# ═══════════════════════════════════════════════════════════════════════
# ║                       MAIN EXECUTION                               ║
# ═══════════════════════════════════════════════════════════════════════

Show-Splash
Test-SystemRequirements
Install-Prerequisites
Get-Repository
Build-GhostShell
Install-Application
Register-WindowsApp
Generate-Launcher
Show-Summary
