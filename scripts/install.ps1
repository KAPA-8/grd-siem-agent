#Requires -RunAsAdministrator
<#
.SYNOPSIS
    GRD SIEM Agent - Installer for Windows Server
.DESCRIPTION
    Installs the GRD SIEM Agent as a native Windows Service.
    Must be run as Administrator.
.PARAMETER BinaryPath
    Path to the grd-siem-agent.exe binary
.PARAMETER SiemType
    Config template written on a first install: qradar (default) or stellar_cyber.
    An existing config.yaml is never overwritten.
.PARAMETER PrintConfig
    Print the config template for -SiemType and exit without installing.
.EXAMPLE
    .\install.ps1
    .\install.ps1 -BinaryPath .\grd-siem-agent.exe
    .\install.ps1 -BinaryPath .\grd-siem-agent.exe -SiemType stellar_cyber
#>

param(
    [string]$BinaryPath = "",
    [ValidateSet("qradar", "stellar_cyber")]
    [string]$SiemType = "qradar",
    [switch]$PrintConfig
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

# --- Config templates (one siem: block per SIEM type) ---
function Get-SiemSection([string]$Type) {
    if ($Type -eq "stellar_cyber") {
        return @"
siem:
  type: "stellar_cyber"
  connection_id: ""         # Connection UUID from the GRD Dashboard
  api_url: ""               # SaaS: https://<tenant>.stellarcyber.cloud / on-prem: https://<data-processor>
  deployment: "saas"        # saas | onprem
  data_source: "alerts"     # alerts (root All-Access token, or scoped key on 6.3+) | cases
  credentials:
    auth_mode: "api_token"  # api_token (All-Access token + username) | scoped_key (5.5+)
    username: ""            # api_token only: API account email (case-sensitive)
    api_key: ""             # token or scoped key (or GRD_SIEM_CREDENTIALS_API_KEY)
    tenant_id: ""           # optional: limit to one tenant (cust_id)
    validate_ssl: true      # on-prem only; SaaS certificates are always verified
    ca_cert_file: ""        # on-prem: PEM bundle of the Data Processor's CA
"@
    }
    return @"
siem:
  type: "qradar"
  connection_id: ""         # Connection UUID from the GRD Dashboard
  api_url: ""               # QRadar URL (e.g., https://192.168.1.50)
  credentials:
    api_key: ""             # QRadar SEC token (or GRD_SIEM_CREDENTIALS_API_KEY)
    validate_ssl: false     # true if the console has a valid certificate (or use ca_cert_file)
    ca_cert_file: ""        # optional PEM bundle of the console's CA
    api_version: "19.0"
"@
}

function Get-ConfigTemplate([string]$Type) {
    $siem = Get-SiemSection $Type
    return @"
# GRD SIEM Agent Configuration
# Edit this file with your actual values, then start the service.
#
# Register the agent from the GRD Dashboard first, then copy
# the agent_id and agent_token into this file. Every key can also be
# set with an environment variable, e.g. GRD_PLATFORM_AGENT_TOKEN.

agent:
  id: ""                    # From GRD Dashboard
  name: "GRD SIEM Agent"
  hostname: ""

platform:
  url: ""                   # Your GRD platform URL
  agent_token: ""           # Token from GRD Dashboard

$siem

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
"@
}

if ($PrintConfig) {
    Get-ConfigTemplate $SiemType
    exit 0
}

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
    Get-ConfigTemplate $SiemType | Set-Content $configFile -Encoding UTF8
    Write-Host "       Template: $SiemType"
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
if ($SiemType -eq "stellar_cyber") {
    Write-Host "  3. Set the Stellar Cyber connection: connection_id, api_url, deployment,"
    Write-Host "     data_source, auth_mode, username (api_token mode) and api_key."
    Write-Host "     For a self-signed on-prem Data Processor, set ca_cert_file."
} else {
    Write-Host "  3. Set SIEM connection details (api_url, api_key, connection_id)"
}
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
