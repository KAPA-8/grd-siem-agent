#Requires -RunAsAdministrator
<#
.SYNOPSIS
    GRD SIEM Agent - Uninstaller for Windows
.PARAMETER Purge
    Also remove config, data, and logs
.EXAMPLE
    .\uninstall.ps1
    .\uninstall.ps1 -Purge
#>

param(
    [switch]$Purge
)

$ErrorActionPreference = "Stop"

$ServiceName = "GRDSIEMAgent"
$InstallDir  = "C:\Program Files\GRD SIEM Agent"
$ConfigDir   = "C:\ProgramData\GRD SIEM Agent"

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "  GRD SIEM Agent Uninstaller"               -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

# Stop service
Write-Host "[1/3] Stopping service..." -ForegroundColor Green
$svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($svc) {
    if ($svc.Status -eq "Running") {
        Stop-Service -Name $ServiceName -Force
        Write-Host "       Service stopped"
    }
    sc.exe delete $ServiceName | Out-Null
    Write-Host "       Service removed"
} else {
    Write-Host "       Service not found"
}

# Remove binary
Write-Host "[2/3] Removing binary..." -ForegroundColor Green
if (Test-Path $InstallDir) {
    Remove-Item $InstallDir -Recurse -Force
    Write-Host "       Removed $InstallDir"
} else {
    Write-Host "       Not found"
}

# Remove data (if purge)
Write-Host "[3/3] Cleaning up..." -ForegroundColor Green
if ($Purge) {
    if (Test-Path $ConfigDir) {
        Remove-Item $ConfigDir -Recurse -Force
        Write-Host "       Removed $ConfigDir (config + data + logs)"
    }
} else {
    Write-Host "       Config and data preserved at: $ConfigDir"
    Write-Host "       To remove everything: .\uninstall.ps1 -Purge"
}

Write-Host ""
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "  Uninstallation complete"                   -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
