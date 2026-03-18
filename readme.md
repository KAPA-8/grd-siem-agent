# GRD SIEM Agent

On-premises agent that collects security alerts from your SIEM (QRadar, Splunk, Sentinel) and sends them to the [GRD Cyber Risk](https://grd.com) platform for centralized risk management.

## Features

- **QRadar integration** - Collects offenses via REST API with MITRE ATT&CK mapping
- **Offline resilience** - SQLite buffer stores alerts locally when the platform is unreachable
- **Auto-updates** - Automatically downloads and applies new versions from GitHub Releases
- **Heartbeat monitoring** - Periodic health checks reported to the platform
- **Cross-platform** - Linux (amd64/arm64), macOS (Intel/Apple Silicon), Windows (amd64)
- **Lightweight** - Single static binary, ~12 MB, no runtime dependencies
- **Secure** - Runs as unprivileged user, systemd hardening, SHA256 checksum verification

## Quick Start

### 1. Download

Get the latest binary from [Releases](https://github.com/KAPA-8/grd-siem-agent/releases):

```bash
# Linux (amd64)
curl -Lo grd-siem-agent https://github.com/KAPA-8/grd-siem-agent/releases/latest/download/grd-siem-agent-linux-amd64
chmod +x grd-siem-agent

# macOS (Apple Silicon)
curl -Lo grd-siem-agent https://github.com/KAPA-8/grd-siem-agent/releases/latest/download/grd-siem-agent-darwin-arm64
chmod +x grd-siem-agent
```

### 2. Install (Linux)

Download the install script and run it:

```bash
curl -Lo install.sh https://raw.githubusercontent.com/KAPA-8/grd-siem-agent/main/scripts/install.sh
sudo bash install.sh --binary ./grd-siem-agent
```

> **Note:** The binary is a standalone executable with no file extension — this is normal for Linux/macOS. Do not attempt to unzip it.

This creates:
| Path | Purpose |
|------|---------|
| `/opt/grd-siem-agent/` | Binary |
| `/etc/grd-siem-agent/config.yaml` | Configuration |
| `/var/lib/grd-siem-agent/` | Data (buffer, checkpoint) |
| `/var/log/grd-siem-agent/` | Logs |

### 3. Configure

```bash
sudo nano /etc/grd-siem-agent/config.yaml
```

#### Option A: Register from the GRD Dashboard (recommended)

Register the agent from the GRD platform web interface. The dashboard will provide you with an `agent_id` and `agent_token`. Then set them in the config:

```yaml
agent:
  id: "agent-id-from-dashboard"

platform:
  url: "https://your-platform.example.com"
  agent_token: "token-from-dashboard"

siem:
  type: "qradar"
  connection_id: "uuid-from-dashboard"
  api_url: "https://192.168.1.50"
  credentials:
    api_key: "your-qradar-sec-token"
```

#### Option B: Register via CLI

If you prefer to register from the command line, set `platform.url` and `platform.org_api_key` in the config, then run:

```bash
sudo -u grd-agent /opt/grd-siem-agent/grd-siem-agent register \
  --config /etc/grd-siem-agent/config.yaml
```

Copy the returned `agent_id` and `agent_token` into your `config.yaml`.

> **Important:** The token is shown only once. Save it immediately.

### 4. Start

```bash
sudo systemctl start grd-siem-agent
sudo systemctl status grd-siem-agent
```

## Windows Installation

```powershell
# Run as Administrator
.\scripts\install.ps1 -BinaryPath .\grd-siem-agent-windows-amd64.exe
```

The agent installs as a Windows Service (`GRDSIEMAgent`) using NSSM. Configuration and data are stored under `C:\ProgramData\GRD SIEM Agent\`.

## Configuration Reference

| Section | Key | Default | Description |
|---------|-----|---------|-------------|
| `agent.name` | | `""` | Human-readable name for this agent |
| `agent.hostname` | | auto-detected | Override hostname |
| `platform.url` | | **required** | GRD platform URL |
| `platform.agent_token` | | **required** | Token from registration |
| `siem.type` | | `"qradar"` | SIEM type: `qradar`, `splunk`, `sentinel` |
| `siem.connection_id` | | **required** | Connection UUID from platform dashboard |
| `siem.api_url` | | **required** | SIEM console URL (internal network) |
| `siem.credentials.api_key` | | **required** | SIEM API key/token |
| `siem.credentials.validate_ssl` | | `false` | Validate SIEM SSL certificate |
| `siem.credentials.api_version` | | `"19.0"` | QRadar API version |
| `sync.interval_minutes` | | `15` | Polling interval |
| `sync.lookback_days` | | `7` | First-run lookback window |
| `sync.max_alerts_per_sync` | | `1000` | Max alerts per cycle |
| `sync.filters.min_severity` | | `"medium"` | Minimum severity filter |
| `buffer.enabled` | | `true` | Enable offline SQLite buffer |
| `buffer.path` | | `"./buffer.db"` | Buffer file path |
| `buffer.max_size_mb` | | `500` | Max buffer size |
| `logging.level` | | `"info"` | Log level: `debug`, `info`, `warn`, `error` |
| `logging.path` | | `""` | Log file path (empty = stderr) |
| `heartbeat.interval_seconds` | | `60` | Heartbeat frequency |
| `update.enabled` | | `true` | Enable auto-updates |
| `update.check_interval_hours` | | `6` | Update check frequency |
| `update.github_repo` | | `"KAPA-8/grd-siem-agent"` | GitHub repo for releases |
| `update.allow_prerelease` | | `false` | Install pre-release versions |

### Environment Variables

All configuration keys can be set via environment variables with the `GRD_` prefix. Dots become underscores:

```bash
export GRD_PLATFORM_AGENT_TOKEN="your-token"
export GRD_SIEM_CREDENTIALS_API_KEY="your-qradar-key"
export GRD_SYNC_INTERVAL_MINUTES=30
```

## CLI Commands

```bash
grd-siem-agent run       # Start the agent (foreground or service mode)
grd-siem-agent register  # Register with the GRD platform (one-time)
grd-siem-agent validate  # Validate configuration file
grd-siem-agent update    # Check for and stage updates
grd-siem-agent version   # Print version information
```

### Flags

```
--config, -c    Path to config file (default: config.yaml)
```

#### `register` flags
```
--name          Agent name (default: from config)
--hostname      Agent hostname (default: system hostname)
--siem-type     SIEM type: qradar, splunk, sentinel (default: from config)
```

#### `update` flags
```
--check         Only check for updates, don't download
```

## Auto-Updates

The agent automatically checks GitHub Releases for new versions every 6 hours (configurable). When an update is found:

1. Downloads the binary for the current platform
2. Verifies SHA256 checksum against `checksums.txt`
3. Stages the update in `/var/lib/grd-siem-agent/.update/`
4. Exits to trigger a service restart
5. On restart, `apply-update.sh` verifies and replaces the binary

To check manually:

```bash
# Check if an update is available
grd-siem-agent update --check --config /etc/grd-siem-agent/config.yaml

# Download and stage update
grd-siem-agent update --config /etc/grd-siem-agent/config.yaml

# Apply by restarting the service
sudo systemctl restart grd-siem-agent
```

To disable auto-updates:

```yaml
update:
  enabled: false
```

## Architecture

```
grd-siem-agent
├── Collector (SIEM-specific)
│   └── QRadar: polls /api/siem/offenses, maps to MITRE ATT&CK
├── Sender (HTTPS to GRD platform)
│   ├── /api/v1/siem-agent/sync       → send alerts
│   ├── /api/v1/siem-agent/heartbeat  → health status
│   └── /api/v1/siem-agent/register   → one-time registration
├── Buffer (SQLite, offline resilience)
│   └── Stores failed batches, drains on next cycle
├── Heartbeat (background, every 60s)
│   └── Reports uptime, memory, version, status
└── Updater (background, every 6h)
    └── Checks GitHub Releases, downloads, verifies, stages
```

### Alert Flow

```
SIEM (QRadar) ──poll──> Collector ──normalize──> Sender ──HTTPS──> GRD Platform
                                        │
                                   (on failure)
                                        │
                                     Buffer (SQLite)
                                        │
                                   (next cycle)
                                        │
                                     Drain ──retry──> GRD Platform
```

## Building from Source

Requirements: Go 1.25+

```bash
# Build for current platform
make build

# Cross-compile for all platforms
make build-all

# Run tests
make test

# Generate checksums
make checksums
```

## Supported SIEMs

| SIEM | Status | API Version |
|------|--------|-------------|
| IBM QRadar | Available | 19.0 - 26.0 |
| Splunk Enterprise | Planned | - |
| Microsoft Sentinel | Planned | - |

## Security

- Runs as unprivileged system user `grd-agent`
- systemd hardening: `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`
- Config files secured with `640` permissions (readable only by owner/group)
- Memory limits enforced: 200 MB max
- Update binaries verified with SHA256 checksums before installation
- All platform communication over HTTPS with Bearer token authentication

## Troubleshooting

### Check agent status

```bash
sudo systemctl status grd-siem-agent
```

### View logs

```bash
# Real-time logs
sudo journalctl -u grd-siem-agent -f

# Last 100 lines
sudo journalctl -u grd-siem-agent -n 100 --no-pager
```

### Validate configuration

```bash
sudo -u grd-agent /opt/grd-siem-agent/grd-siem-agent validate \
  --config /etc/grd-siem-agent/config.yaml
```

### Common issues

| Issue | Solution |
|-------|----------|
| `registration failed (401)` | Check `platform.org_api_key` is correct |
| `collector init: connection refused` | Verify `siem.api_url` is reachable from this server |
| `sync failed (403)` | Check `platform.agent_token` is valid |
| `certificate verify failed` | Set `siem.credentials.validate_ssl: false` or install the CA cert |
| Agent not collecting alerts | Check `sync.filters.min_severity` — may be filtering too aggressively |
| Buffer growing large | Platform may be unreachable — check network/firewall |

### Uninstall

```bash
# Linux
sudo ./scripts/uninstall.sh

# Windows (Administrator PowerShell)
.\scripts\uninstall.ps1
```

## License

Proprietary - GRD Platform. All rights reserved.
