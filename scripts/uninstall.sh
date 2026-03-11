#!/bin/bash
set -euo pipefail

# ============================================================
# GRD SIEM Agent - Uninstaller for Ubuntu/Debian
# ============================================================
# Usage:
#   sudo ./uninstall.sh
#   sudo ./uninstall.sh --purge    (also removes config and data)
# ============================================================

AGENT_USER="grd-agent"
INSTALL_DIR="/opt/grd-siem-agent"
CONFIG_DIR="/etc/grd-siem-agent"
DATA_DIR="/var/lib/grd-siem-agent"
LOG_DIR="/var/log/grd-siem-agent"
SERVICE_NAME="grd-siem-agent"

PURGE=false

if [[ "${1:-}" == "--purge" ]]; then
    PURGE=true
fi

if [[ $EUID -ne 0 ]]; then
    echo "Error: This script must be run as root (sudo)"
    exit 1
fi

echo "=========================================="
echo "  GRD SIEM Agent Uninstaller"
echo "=========================================="
echo ""

# Stop and disable service
echo "[1/4] Stopping service..."
if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
    systemctl stop "$SERVICE_NAME"
    echo "       Service stopped"
else
    echo "       Service not running"
fi

if systemctl is-enabled --quiet "$SERVICE_NAME" 2>/dev/null; then
    systemctl disable "$SERVICE_NAME"
fi

# Remove service file
echo "[2/4] Removing systemd service..."
rm -f /etc/systemd/system/grd-siem-agent.service
systemctl daemon-reload
echo "       Service removed"

# Remove binary
echo "[3/4] Removing binary..."
rm -rf "$INSTALL_DIR"
echo "       Removed $INSTALL_DIR"

# Remove user
echo "[4/4] Removing system user..."
if id "$AGENT_USER" &>/dev/null; then
    userdel "$AGENT_USER" 2>/dev/null || true
    echo "       User removed"
else
    echo "       User not found"
fi

if $PURGE; then
    echo ""
    echo "Purging config and data..."
    rm -rf "$CONFIG_DIR"
    rm -rf "$DATA_DIR"
    rm -rf "$LOG_DIR"
    echo "  Removed $CONFIG_DIR"
    echo "  Removed $DATA_DIR"
    echo "  Removed $LOG_DIR"
fi

echo ""
echo "=========================================="
echo "  Uninstallation complete"
echo "=========================================="

if ! $PURGE; then
    echo ""
    echo "Config and data preserved at:"
    echo "  $CONFIG_DIR"
    echo "  $DATA_DIR"
    echo "  $LOG_DIR"
    echo ""
    echo "To remove everything: sudo ./uninstall.sh --purge"
fi
