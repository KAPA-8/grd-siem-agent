#!/bin/bash
# /opt/grd-siem-agent/apply-update.sh
# Called by systemd ExecStartPre (runs as root before User= takes effect).
# Checks for a pending self-update and applies it atomically.

set -euo pipefail

INSTALL_DIR="/opt/grd-siem-agent"
STAGING_DIR="/var/lib/grd-siem-agent/.update"
PENDING_FILE="$STAGING_DIR/pending.json"
BINARY_PATH="$INSTALL_DIR/grd-siem-agent"
LOG_TAG="grd-update"

log_info()  { logger -t "$LOG_TAG" "INFO: $*";  }
log_error() { logger -t "$LOG_TAG" "ERROR: $*"; }

# No pending update — nothing to do
if [[ ! -f "$PENDING_FILE" ]]; then
    exit 0
fi

log_info "Pending update found, applying..."

# Parse pending.json using grep (no python3/jq dependency)
EXPECTED_SHA256=$(grep -o '"sha256"[[:space:]]*:[[:space:]]*"[^"]*"' "$PENDING_FILE" | grep -o '"[^"]*"$' | tr -d '"')
UPDATE_VERSION=$(grep -o '"version"[[:space:]]*:[[:space:]]*"[^"]*"' "$PENDING_FILE" | grep -o '"[^"]*"$' | tr -d '"')

if [[ -z "$EXPECTED_SHA256" || -z "$UPDATE_VERSION" ]]; then
    log_error "Failed to parse pending.json, removing invalid update"
    rm -f "$PENDING_FILE" "$STAGING_DIR/grd-siem-agent.new"
    exit 0
fi

STAGED_BINARY="$STAGING_DIR/grd-siem-agent.new"

# Verify staged binary exists
if [[ ! -f "$STAGED_BINARY" ]]; then
    log_error "Staged binary not found at $STAGED_BINARY"
    rm -f "$PENDING_FILE"
    exit 0
fi

# Verify SHA256 checksum
ACTUAL_SHA256=$(sha256sum "$STAGED_BINARY" | awk '{print $1}')
if [[ "$ACTUAL_SHA256" != "$EXPECTED_SHA256" ]]; then
    log_error "Checksum mismatch! Expected $EXPECTED_SHA256, got $ACTUAL_SHA256"
    rm -f "$PENDING_FILE" "$STAGED_BINARY"
    exit 0
fi

# Smoke test: verify the new binary can at least print its version
if ! "$STAGED_BINARY" version &>/dev/null; then
    log_error "New binary failed smoke test (version command)"
    rm -f "$PENDING_FILE" "$STAGED_BINARY"
    exit 0
fi

# Backup current binary
BACKUP_PATH="$STAGING_DIR/grd-siem-agent.backup"
cp "$BINARY_PATH" "$BACKUP_PATH"
log_info "Backed up current binary to $BACKUP_PATH"

# Atomic replace: copy to temp in same filesystem, then mv
TEMP_PATH="$INSTALL_DIR/grd-siem-agent.tmp"
cp "$STAGED_BINARY" "$TEMP_PATH"
chmod 755 "$TEMP_PATH"
chown root:root "$TEMP_PATH"
mv "$TEMP_PATH" "$BINARY_PATH"

log_info "Binary updated to $UPDATE_VERSION (sha256: $ACTUAL_SHA256)"

# Clean up staging
rm -f "$PENDING_FILE" "$STAGED_BINARY"

log_info "Update applied successfully"
exit 0
