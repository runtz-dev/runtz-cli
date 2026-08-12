#!/usr/bin/env pwsh
#
# runtz CLI installer for Windows.
#
#   irm https://runtz.dev/install.ps1 | iex
#
# This script:
#   - Detects your CPU architecture.
#   - Downloads the matching release binary from GitHub Releases.
#   - Verifies its SHA-256 against the release's checksums.txt.
#   - Installs it to $env:LOCALAPPDATA\runtz (or $env:RUNTZ_INSTALL_DIR)
#     and adds that folder to your user PATH.
#
# Environment overrides (set before piping into iex):
#   $env:RUNTZ_VERSION      Release tag to install (default: latest)
#   $env:RUNTZ_INSTALL_DIR  Install directory (default: $env:LOCALAPPDATA\runtz)
#   $env:RUNTZ_REPO         GitHub repository (default: runtz-dev/runtz-cli)
#
# Source code: https://github.com/runtz-dev/runtz-cli/blob/main/install.ps1

$ErrorActionPreference = "Stop"

# Windows PowerShell 5.1 (still the OS default on many machines) doesn't
# negotiate TLS 1.2 by default, and GitHub requires it.
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

$Repo       = if ($env:RUNTZ_REPO)        { $env:RUNTZ_REPO }        else { "runtz-dev/runtz-cli" }
$Version    = if ($env:RUNTZ_VERSION)     { $env:RUNTZ_VERSION }     else { "latest" }
$InstallDir = if ($env:RUNTZ_INSTALL_DIR) { $env:RUNTZ_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA "runtz" }
$Binary     = "runtz.exe"

function Write-Info($msg) { Write-Host "==> $msg" -ForegroundColor Cyan }
# throw, not exit: this script normally runs via `irm | iex`, and `exit`
# inside code executed that way closes the user's entire PowerShell window,
# not just the install — throw stops the script and leaves the shell open.
function Fail($msg) { throw $msg }

# ARCHITEW6432 is only set under WOW64 (32-bit PowerShell on 64-bit Windows);
# checking it first avoids misdetecting arch in that case.
$ArchEnv = if ($env:PROCESSOR_ARCHITEW6432) { $env:PROCESSOR_ARCHITEW6432 } else { $env:PROCESSOR_ARCHITECTURE }
switch ($ArchEnv) {
    "AMD64"   { $Arch = "amd64" }
    "ARM64"   { $Arch = "arm64" }
    default   { Fail "unsupported architecture: $ArchEnv (runtz supports amd64 and arm64)" }
}

$Asset = "runtz_windows_${Arch}.exe"
$ReleaseUrl = if ($Version -eq "latest") {
    "https://github.com/$Repo/releases/latest/download"
} else {
    "https://github.com/$Repo/releases/download/$Version"
}

function Resolve-NewestTag {
    # GitHub's "latest" only covers stable releases; runtz also ships
    # release candidates (1.0.0-rcN), so fall back to the newest release,
    # prereleases included. Invoke-RestMethod parses the JSON for us.
    $release = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases?per_page=1"
    return $release[0].tag_name
}

function Get-ReleaseAsset($Url, $OutFile) {
    for ($i = 0; $i -lt 2; $i++) {
        try {
            Invoke-WebRequest -Uri $Url -OutFile $OutFile -UseBasicParsing
            return $true
        } catch {
            if ($i -eq 0) { Start-Sleep -Seconds 1 }
        }
    }
    return $false
}

$TmpDir = Join-Path $env:TEMP "runtz-install-$([guid]::NewGuid())"
New-Item -ItemType Directory -Path $TmpDir -Force | Out-Null
try {
    $BinaryPath = Join-Path $TmpDir $Binary

    Write-Info "Downloading runtz (windows/$Arch, $Version)..."
    if (-not (Get-ReleaseAsset "$ReleaseUrl/$Asset" $BinaryPath)) {
        if ($Version -eq "latest") {
            $Tag = Resolve-NewestTag
            if (-not $Tag) { Fail "download failed: $ReleaseUrl/$Asset" }
            Write-Info "No stable release yet; using newest release $Tag..."
            $ReleaseUrl = "https://github.com/$Repo/releases/download/$Tag"
            if (-not (Get-ReleaseAsset "$ReleaseUrl/$Asset" $BinaryPath)) {
                Fail "download failed: $ReleaseUrl/$Asset"
            }
        } else {
            Fail "download failed: $ReleaseUrl/$Asset"
        }
    }

    Write-Info "Verifying checksum..."
    $ChecksumsPath = Join-Path $TmpDir "checksums.txt"
    if (-not (Get-ReleaseAsset "$ReleaseUrl/checksums.txt" $ChecksumsPath)) {
        Fail "download failed: $ReleaseUrl/checksums.txt"
    }
    $Pattern = " " + [regex]::Escape($Asset) + "$"
    $WantLine = Select-String -Path $ChecksumsPath -Pattern $Pattern
    if (-not $WantLine) { Fail "checksum for $Asset not found in checksums.txt" }
    $Want = ($WantLine.Line -split '\s+')[0]
    $Got = (Get-FileHash -Path $BinaryPath -Algorithm SHA256).Hash.ToLower()
    if ($Got -ne $Want) { Fail "checksum mismatch for ${Asset}: got $Got, want $Want" }

    Write-Info "Installing to $InstallDir\$Binary..."
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    Copy-Item -Path $BinaryPath -Destination (Join-Path $InstallDir $Binary) -Force

    # Persist to the user PATH if it isn't there yet. [Environment]::Set...
    # writes HKCU\Environment correctly, unlike setx.exe, which silently
    # truncates values over 1024 chars.
    $UserPath = [Environment]::GetEnvironmentVariable("Path", "User")
    if (-not ($UserPath -split ";" -contains $InstallDir)) {
        $NewPath = if ($UserPath) { "$UserPath;$InstallDir" } else { $InstallDir }
        [Environment]::SetEnvironmentVariable("Path", $NewPath, "User")
        Write-Info "Added $InstallDir to your user PATH."
    }
    # Make it usable immediately in *this* session too.
    if (-not ($env:Path -split ";" -contains $InstallDir)) {
        $env:Path = "$env:Path;$InstallDir"
    }

    Write-Info "Installed $(& (Join-Path $InstallDir $Binary) version)"
    Write-Info "Open a new terminal window, then run 'runtz --help' to get started."
} finally {
    Remove-Item -Path $TmpDir -Recurse -Force -ErrorAction SilentlyContinue
}
