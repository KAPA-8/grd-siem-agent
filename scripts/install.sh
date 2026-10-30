#!/bin/bash
set -euo pipefail

# ============================================================
# GRD SIEM Agent - Installer for Ubuntu/Debian
# ============================================================
# Usage:
#   sudo ./install.sh
#   sudo ./install.sh --binary /path/to/grd-siem-agent
#   sudo ./install.sh --siem-type stellar_cyber
#   ./install.sh --siem-type stellar_cyber --print-config   # print the config template only
#
# --siem-type selects the config template written to
# /etc/grd-siem-agent/config.yaml on a first install: qradar (default)
# or stellar_cyber. An existing config is never overwritten.
# ============================================================

AGENT_USER="grd-agent"
AGENT_GROUP="grd-agent"
INSTALL_DIR="/opt/grd-siem-agent"
CONFIG_DIR="/etc/grd-siem-agent"
DATA_DIR="/var/lib/grd-siem-agent"
LOG_DIR="/var/log/grd-siem-agent"
SERVICE_NAME="grd-siem-agent"

BINARY_PATH=""
SIEM_TYPE="qradar"
PRINT_CONFIG=false

usage() {
    echo "Usage: $0 [--binary PATH] [--siem-type qradar|stellar_cyber] [--print-config]"
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --binary)
            if [[ $# -lt 2 ]]; then echo "Error: --binary needs a path"; exit 1; fi
            BINARY_PATH="$2"
            shift 2
            ;;
        --siem-type)
            if [[ $# -lt 2 ]]; then echo "Error: --siem-type needs a value"; exit 1; fi
            SIEM_TYPE="$2"
            shift 2
            ;;
        --print-config)
            PRINT_CONFIG=true
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            usage
            exit 1
            ;;
    esac
done

case "$SIEM_TYPE" in
    qradar|stellar_cyber) ;;
    *)
        echo "Error: --siem-type must be qradar or stellar_cyber (got: $SIEM_TYPE)"
        exit 1
        ;;
esac

# siem_section prints the siem: block of the config template for a SIEM type.
siem_section() {
    case "$1" in
        qradar)
            cat << 'YAML'
siem:
  type: "qradar"
  connection_id: ""         # Connection UUID from the GRD Dashboard
  api_url: ""               # QRadar URL (e.g., https://192.168.1.50)
  credentials:
    api_key: ""             # QRadar SEC token (or GRD_SIEM_CREDENTIALS_API_KEY)
    validate_ssl: false     # true if the console has a valid certificate (or use ca_cert_file)
    ca_cert_file: ""        # optional PEM bundle of the console's CA
    api_version: "19.0"
YAML
            ;;
        stellar_cyber)
            cat << 'YAML'
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
YAML
            ;;
    esac
}

# config_template prints a complete config.yaml for a SIEM type.
config_template() {
    cat << 'YAML'
# GRD SIEM Agent Configuration
# Edit this file with your actual values, then run:
#   sudo systemctl start grd-siem-agent
#
# Register the agent from the GRD Dashboard first, then copy
# the agent_id and agent_token into this file. Every key can also be
# set with an environment variable, e.g. GRD_PLATFORM_AGENT_TOKEN.

agent:
  id: ""                    # From GRD Dashboard
  name: "GRD SIEM Agent"
  hostname: ""

platform:
  url: ""                   # Your GRD platform URL (e.g., https://app.example.com)
  agent_token: ""           # Token from GRD Dashboard

YAML
    siem_section "$1"
    cat << 'YAML'

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
  check_interval_minutes: 10
  github_repo: "KAPA-8/grd-siem-agent"
  allow_prerelease: false
YAML
}

if [[ "$PRINT_CONFIG" == true ]]; then
    config_template "$SIEM_TYPE"
    exit 0
fi

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
    config_template "$SIEM_TYPE" > "$CONFIG_DIR/config.yaml"
    echo "       Template: $SIEM_TYPE"

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
ExecStartPre=+/opt/grd-siem-agent/apply-update.sh
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
echo "  2. Register the agent from the GRD Dashboard:"
echo "       Copy the agent_id and agent_token into config.yaml"
echo ""
if [[ "$SIEM_TYPE" == "stellar_cyber" ]]; then
    echo "  3. Set the Stellar Cyber connection: connection_id, api_url, deployment,"
    echo "     data_source, auth_mode, username (api_token mode) and api_key"
    echo "     (or GRD_SIEM_CREDENTIALS_API_KEY). For a self-signed on-prem"
    echo "     Data Processor, set ca_cert_file (or validate_ssl: false)."
else
    echo "  3. Set the SIEM connection details (api_url, api_key, connection_id)"
fi
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
