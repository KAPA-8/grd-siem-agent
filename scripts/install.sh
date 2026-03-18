#!/bin/bash
set -euo pipefail

# ============================================================
# GRD SIEM Agent - Installer for Ubuntu/Debian
# ============================================================
# Usage:
#   sudo ./install.sh
#   sudo ./install.sh --binary /path/to/grd-siem-agent
# ============================================================

AGENT_USER="grd-agent"
AGENT_GROUP="grd-agent"
INSTALL_DIR="/opt/grd-siem-agent"
CONFIG_DIR="/etc/grd-siem-agent"
DATA_DIR="/var/lib/grd-siem-agent"
LOG_DIR="/var/log/grd-siem-agent"
SERVICE_NAME="grd-siem-agent"

BINARY_PATH=""

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --binary)
            BINARY_PATH="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Must run as root
if [[ $EUID -ne 0 ]]; then
    echo "Error: This script must be run as root (sudo)"
    exit 1
fi

echo "=========================================="
echo "  GRD SIEM Agent Installer"
echo "=========================================="
echo ""

# --- Step 1: Find binary ---
if [[ -z "$BINARY_PATH" ]]; then
    # Look for binary in common locations
    for candidate in \
        "./grd-siem-agent" \
        "./grd-siem-agent-linux-amd64" \
        "./bin/grd-siem-agent-linux-amd64" \
        "./bin/grd-siem-agent"; do
        if [[ -f "$candidate" ]]; then
            BINARY_PATH="$candidate"
            break
        fi
    done
fi

if [[ -z "$BINARY_PATH" || ! -f "$BINARY_PATH" ]]; then
    echo "Error: Binary not found. Use --binary /path/to/grd-siem-agent"
    exit 1
fi

echo "[1/6] Binary found: $BINARY_PATH"
AGENT_VERSION=$("$BINARY_PATH" version 2>/dev/null | head -1 || echo "unknown")
echo "       Version: $AGENT_VERSION"

# --- Step 2: Create system user ---
echo "[2/6] Creating system user '$AGENT_USER'..."
if id "$AGENT_USER" &>/dev/null; then
    echo "       User already exists, skipping"
else
    useradd --system --shell /usr/sbin/nologin --home-dir "$DATA_DIR" --create-home "$AGENT_USER"
    echo "       User created"
fi

# --- Step 3: Create directories ---
echo "[3/6] Creating directories..."
mkdir -p "$INSTALL_DIR" "$CONFIG_DIR" "$DATA_DIR" "$LOG_DIR"

chown root:root "$INSTALL_DIR"
chown "$AGENT_USER:$AGENT_GROUP" "$DATA_DIR" "$LOG_DIR"
chmod 755 "$INSTALL_DIR" "$CONFIG_DIR"
chmod 750 "$DATA_DIR" "$LOG_DIR"

echo "       $INSTALL_DIR  (binary)"
echo "       $CONFIG_DIR   (config)"
echo "       $DATA_DIR     (data/buffer)"
echo "       $LOG_DIR      (logs)"

# --- Step 4: Install binary ---
echo "[4/6] Installing binary..."
cp "$BINARY_PATH" "$INSTALL_DIR/grd-siem-agent"
chmod 755 "$INSTALL_DIR/grd-siem-agent"
echo "       Installed to $INSTALL_DIR/grd-siem-agent"

# Install update apply script
for candidate in \
    "./scripts/apply-update.sh" \
    "./apply-update.sh"; do
    if [[ -f "$candidate" ]]; then
        cp "$candidate" "$INSTALL_DIR/apply-update.sh"
        chmod 755 "$INSTALL_DIR/apply-update.sh"
        chown root:root "$INSTALL_DIR/apply-update.sh"
        echo "       Installed update script: $INSTALL_DIR/apply-update.sh"
        break
    fi
done

# Create update staging directory
mkdir -p "$DATA_DIR/.update"
chown "$AGENT_USER:$AGENT_GROUP" "$DATA_DIR/.update"
chmod 750 "$DATA_DIR/.update"
echo "       Created update staging dir: $DATA_DIR/.update"

# --- Step 5: Install config ---
echo "[5/6] Setting up configuration..."
if [[ -f "$CONFIG_DIR/config.yaml" ]]; then
    echo "       Config already exists, not overwriting"
    echo "       (existing: $CONFIG_DIR/config.yaml)"
else
    # Find example config
    EXAMPLE_CONFIG=""
    for candidate in \
        "./configs/config.example.yaml" \
        "./config.example.yaml"; do
        if [[ -f "$candidate" ]]; then
            EXAMPLE_CONFIG="$candidate"
            break
        fi
    done

    if [[ -n "$EXAMPLE_CONFIG" ]]; then
        cp "$EXAMPLE_CONFIG" "$CONFIG_DIR/config.yaml"
    else
        # Generate minimal config
        cat > "$CONFIG_DIR/config.yaml" << 'YAML'
# GRD SIEM Agent Configuration
# Edit this file with your actual values, then run:
#   sudo systemctl start grd-siem-agent
#
# Register from the GRD Dashboard (recommended) or via CLI:
#   CLI: grd-siem-agent register --config config.yaml

agent:
  id: ""                    # From GRD Dashboard or CLI registration
  name: "GRD SIEM Agent"
  hostname: ""

platform:
  url: ""                   # Your GRD platform URL (e.g., https://app.example.com)
  agent_token: ""           # Token from dashboard or CLI registration
  org_api_key: ""           # Org API key (only needed for CLI registration)

siem:
  type: "qradar"
  connection_id: ""         # Connection UUID from the platform dashboard
  api_url: ""               # QRadar URL (e.g., https://192.168.1.50)
  credentials:
    api_key: ""             # QRadar SEC token
    validate_ssl: false

sync:
  interval_minutes: 15
  lookback_days: 7
  max_alerts_per_sync: 1000
  filters:
    min_severity: "medium"

buffer:
  enabled: true
  path: "/var/lib/grd-siem-agent/buffer.db"
  max_size_mb: 500

logging:
  level: "info"
  path: "/var/log/grd-siem-agent/agent.log"
  max_size_mb: 100

heartbeat:
  interval_seconds: 60

update:
  enabled: true
  check_interval_hours: 6
  github_repo: "KAPA-8/grd-siem-agent"
  allow_prerelease: false
YAML
    fi

    # Secure config file (contains API keys)
    chown root:"$AGENT_GROUP" "$CONFIG_DIR/config.yaml"
    chmod 640 "$CONFIG_DIR/config.yaml"
    echo "       Config created: $CONFIG_DIR/config.yaml"
fi

# --- Step 6: Install systemd service ---
echo "[6/6] Installing systemd service..."

# Find service file
SERVICE_FILE=""
for candidate in \
    "./scripts/grd-siem-agent.service" \
    "./grd-siem-agent.service"; do
    if [[ -f "$candidate" ]]; then
        SERVICE_FILE="$candidate"
        break
    fi
done

if [[ -n "$SERVICE_FILE" ]]; then
    cp "$SERVICE_FILE" /etc/systemd/system/grd-siem-agent.service
else
    # Generate service file inline
    cat > /etc/systemd/system/grd-siem-agent.service << 'SERVICE'
[Unit]
Description=GRD SIEM Agent - On-premises SIEM collector
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=grd-agent
Group=grd-agent
ExecStartPre=/opt/grd-siem-agent/apply-update.sh
ExecStart=/opt/grd-siem-agent/grd-siem-agent run --config /etc/grd-siem-agent/config.yaml
Restart=on-failure
RestartSec=10
LimitNOFILE=65536
StandardOutput=journal
StandardError=journal
SyslogIdentifier=grd-siem-agent
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/grd-siem-agent /var/log/grd-siem-agent /opt/grd-siem-agent
PrivateTmp=true
MemoryMax=200M
MemoryHigh=100M

[Install]
WantedBy=multi-user.target
SERVICE
fi

systemctl daemon-reload
systemctl enable grd-siem-agent
echo "       Service installed and enabled"

# --- Done ---
echo ""
echo "=========================================="
echo "  Installation complete!"
echo "=========================================="
echo ""
echo "Next steps:"
echo ""
echo "  1. Edit the config file:"
echo "     sudo nano $CONFIG_DIR/config.yaml"
echo ""
echo "  2. Register the agent (choose one):"
echo ""
echo "     Option A - From GRD Dashboard (recommended):"
echo "       Register in the web interface, then copy the agent_id"
echo "       and agent_token into config.yaml"
echo ""
echo "     Option B - Via CLI:"
echo "       Set platform.url and platform.org_api_key, then run:"
echo "       sudo -u $AGENT_USER $INSTALL_DIR/grd-siem-agent register \\"
echo "         --config $CONFIG_DIR/config.yaml"
echo ""
echo "  3. Set the SIEM connection details (api_url, api_key, connection_id)"
echo ""
echo "  4. Validate config:"
echo "     sudo -u $AGENT_USER $INSTALL_DIR/grd-siem-agent validate \\"
echo "       --config $CONFIG_DIR/config.yaml"
echo ""
echo "  5. Start the agent:"
echo "     sudo systemctl start grd-siem-agent"
echo ""
echo "  6. Check status:"
echo "     sudo systemctl status grd-siem-agent"
echo "     sudo journalctl -u grd-siem-agent -f"
echo ""
