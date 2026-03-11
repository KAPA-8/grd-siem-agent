# C:\Program Files\GRD SIEM Agent\apply-update.ps1
# Called before service start to apply pending updates.

$ErrorActionPreference = "Stop"

$InstallDir = "C:\Program Files\GRD SIEM Agent"
$StagingDir = "C:\ProgramData\GRD SIEM Agent\update"
$PendingFile = "$StagingDir\pending.json"
$BinaryPath = "$InstallDir\grd-siem-agent.exe"

# No pending update — nothing to do
if (-not (Test-Path $PendingFile)) {
    exit 0
}

try {
    # Register event source if not already registered
    if (-not [System.Diagnostics.EventLog]::SourceExists("GRDSIEMAgent")) {
        New-EventLog -LogName Application -Source "GRDSIEMAgent"
    }
} catch {
    # Ignore if source already exists or insufficient permissions
}

function Write-UpdateLog($EventId, $Message) {
    try {
        Write-EventLog -LogName Application -Source "GRDSIEMAgent" -EventId $EventId -EntryType Information -Message $Message
    } catch {
        Write-Host $Message
    }
}

Write-UpdateLog 1000 "Applying pending update..."

$pending = Get-Content $PendingFile | ConvertFrom-Json
$stagedBinary = "$StagingDir\grd-siem-agent.new"

if (-not (Test-Path $stagedBinary)) {
    Write-UpdateLog 1001 "Staged binary not found, removing pending marker"
    Remove-Item $PendingFile -Force
    exit 0
}

# Verify SHA256 checksum
$hash = (Get-FileHash -Path $stagedBinary -Algorithm SHA256).Hash.ToLower()
if ($hash -ne $pending.sha256) {
    Write-UpdateLog 1001 "Checksum mismatch! Expected $($pending.sha256), got $hash"
    Remove-Item $PendingFile, $stagedBinary -Force -ErrorAction SilentlyContinue
    exit 0
}

# Smoke test
try {
    $versionOutput = & $stagedBinary version 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Non-zero exit code"
    }
} catch {
    Write-UpdateLog 1001 "New binary failed smoke test"
    Remove-Item $PendingFile, $stagedBinary -Force -ErrorAction SilentlyContinue
    exit 0
}

# Backup current binary
$backupPath = "$StagingDir\grd-siem-agent.backup"
Copy-Item $BinaryPath $backupPath -Force
Write-UpdateLog 1000 "Backed up current binary to $backupPath"

# Replace binary
Copy-Item $stagedBinary $BinaryPath -Force

Write-UpdateLog 1002 "Updated to $($pending.version) (sha256: $hash)"

# Cleanup
Remove-Item $PendingFile, $stagedBinary -Force -ErrorAction SilentlyContinue

Write-UpdateLog 1002 "Update applied successfully"
exit 0
