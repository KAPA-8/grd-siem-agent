#Requires -RunAsAdministrator
<#
.SYNOPSIS
    GRD SIEM Agent - Installer for Windows Server
.DESCRIPTION
    Installs the GRD SIEM Agent as a Windows Service (NSSM).
    Must be run as Administrator.
.PARAMETER BinaryPath
    Path to the grd-siem-agent.exe binary
.EXAMPLE
    .\install.ps1
    .\install.ps1 -BinaryPath .\grd-siem-agent.exe
#>

param(
    [string]$BinaryPath = ""
)

$ErrorActionPreference = "Stop"

# --- Configuration ---
$ServiceName     = "GRDSIEMAgent"
$ServiceDisplay  = "GRD SIEM Agent"
$ServiceDesc     = "On-premises SIEM collector for GRD platform"
$InstallDir      = "C:\Program Files\GRD SIEM Agent"
$ConfigDir       = "C:\ProgramData\GRD SIEM Agent"
$DataDir         = "$ConfigDir\data"
$LogDir          = "$ConfigDir\logs"

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "  GRD SIEM Agent Installer (Windows)"      -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

# --- Step 1: Find binary ---
if (-not $BinaryPath) {
    $candidates = @(
        ".\grd-siem-agent.exe",
        ".\grd-siem-agent-windows-amd64.exe",
        ".\bin\grd-siem-agent-windows-amd64.exe",
        ".\bin\grd-siem-agent.exe"
    )
    foreach ($c in $candidates) {
        if (Test-Path $c) {
            $BinaryPath = $c
            break
        }
    }
}

if (-not $BinaryPath -or -not (Test-Path $BinaryPath)) {
    Write-Host "Error: Binary not found. Use -BinaryPath .\grd-siem-agent.exe" -ForegroundColor Red
    exit 1
}

Write-Host "[1/5] Binary found: $BinaryPath" -ForegroundColor Green
$versionOutput = & $BinaryPath version 2>&1 | Select-Object -First 1
Write-Host "       Version: $versionOutput"

# --- Step 2: Create directories ---
Write-Host "[2/5] Creating directories..." -ForegroundColor Green

foreach ($dir in @($InstallDir, $ConfigDir, $DataDir, $LogDir)) {
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Force -Path $dir | Out-Null
        Write-Host "       Created: $dir"
    } else {
        Write-Host "       Exists:  $dir"
    }
}

# --- Step 3: Install binary ---
Write-Host "[3/5] Installing binary..." -ForegroundColor Green
Copy-Item $BinaryPath "$InstallDir\grd-siem-agent.exe" -Force
Write-Host "       Installed to $InstallDir\grd-siem-agent.exe"

# Install update apply script
foreach ($c in @(".\scripts\apply-update.ps1", ".\apply-update.ps1")) {
    if (Test-Path $c) {
        Copy-Item $c "$InstallDir\apply-update.ps1" -Force
        Write-Host "       Installed update script: $InstallDir\apply-update.ps1"
        break
    }
}

# Create update staging directory
$updateDir = "$ConfigDir\update"
if (-not (Test-Path $updateDir)) {
    New-Item -ItemType Directory -Force -Path $updateDir | Out-Null
    Write-Host "       Created update staging dir: $updateDir"
}

# --- Step 4: Install config ---
Write-Host "[4/5] Setting up configuration..." -ForegroundColor Green

$configFile = "$ConfigDir\config.yaml"
if (Test-Path $configFile) {
    Write-Host "       Config already exists, not overwriting"
    Write-Host "       ($configFile)"
} else {
    # Look for example config
    $exampleConfig = $null
    foreach ($c in @(".\configs\config.example.yaml", ".\config.example.yaml")) {
        if (Test-Path $c) {
            $exampleConfig = $c
            break
        }
    }

    if ($exampleConfig) {
        Copy-Item $exampleConfig $configFile
    } else {
        # Generate minimal config
        @"
# GRD SIEM Agent Configuration
# Edit this file with your actual values, then start the service.
#
# Register the agent from the GRD Dashboard first, then copy
# the agent_id and agent_token into this file.

agent:
  id: ""                    # From GRD Dashboard
  name: "GRD SIEM Agent"
  hostname: ""

platform:
  url: ""                   # Your GRD platform URL
  agent_token: ""           # Token from GRD Dashboard

siem:
  type: "qradar"
  connection_id: ""
  api_url: ""
  credentials:
    api_key: ""
    validate_ssl: false
    api_version: "19.0"

sync:
  interval_minutes: 15
  lookback_days: 7
  max_alerts_per_sync: 1000
  filters:
    min_severity: "medium"

buffer:
  enabled: true
  path: "$($DataDir -replace '\\', '/')/buffer.db"
  max_size_mb: 500

logging:
  level: "info"
  path: "$($LogDir -replace '\\', '/')/agent.log"
  max_size_mb: 100

heartbeat:
  interval_seconds: 60

update:
  enabled: true
  check_interval_minutes: 10
  github_repo: "KAPA-8/grd-siem-agent"
  allow_prerelease: false
"@ | Set-Content $configFile -Encoding UTF8
    }
    Write-Host "       Config created: $configFile"
}

# --- Step 5: Install as Windows Service ---
Write-Host "[5/5] Installing Windows Service..." -ForegroundColor Green

# Check if service already exists
$existingService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue

if ($existingService) {
    Write-Host "       Service already exists. Stopping..."
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    # Remove existing service
    sc.exe delete $ServiceName | Out-Null
    Start-Sleep -Seconds 2
}

# Create the Windows Service using sc.exe
$binPathArg = "`"$InstallDir\grd-siem-agent.exe`" run --config `"$ConfigDir\config.yaml`""

# Use New-Service (native PowerShell)
New-Service -Name $ServiceName `
    -BinaryPathName $binPathArg `
    -DisplayName $ServiceDisplay `
    -Description $ServiceDesc `
    -StartupType Automatic | Out-Null

# Configure recovery: restart on failure
sc.exe failure $ServiceName reset= 86400 actions= restart/10000/restart/30000/restart/60000 | Out-Null

Write-Host "       Service '$ServiceName' installed" -ForegroundColor Green

# --- Done ---
Write-Host ""
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "  Installation complete!" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Yellow
Write-Host ""
Write-Host "  1. Edit the config file:"
Write-Host "     notepad `"$ConfigDir\config.yaml`"" -ForegroundColor White
Write-Host ""
Write-Host "  2. Register the agent from the GRD Dashboard:"
Write-Host "       Copy the agent_id and agent_token into config.yaml"
Write-Host ""
Write-Host "  3. Set SIEM connection details (api_url, api_key, connection_id)"
Write-Host ""
Write-Host "  4. Validate config:"
Write-Host "     & `"$InstallDir\grd-siem-agent.exe`" validate --config `"$ConfigDir\config.yaml`"" -ForegroundColor White
Write-Host ""
Write-Host "  5. Start the service:"
Write-Host "     Start-Service $ServiceName" -ForegroundColor White
Write-Host ""
Write-Host "  6. Check status:"
Write-Host "     Get-Service $ServiceName" -ForegroundColor White
Write-Host "     Get-Content `"$LogDir\agent.log`" -Tail 50 -Wait" -ForegroundColor White
Write-Host ""
