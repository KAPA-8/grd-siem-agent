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

## Quick Start (Linux)

> **All installation and management commands require root privileges (`sudo`).** Make sure you are logged in as root or have sudo access before proceeding.

### 1. Download

Get the latest binary from [Releases](https://github.com/KAPA-8/grd-siem-agent/releases):

```bash
# Linux (amd64)
curl -Lo grd-siem-agent https://github.com/KAPA-8/grd-siem-agent/releases/latest/download/grd-siem-agent-linux-amd64
chmod +x grd-siem-agent

# Linux (arm64)
curl -Lo grd-siem-agent https://github.com/KAPA-8/grd-siem-agent/releases/latest/download/grd-siem-agent-linux-arm64
chmod +x grd-siem-agent
```

> **Note:** The binary is a standalone executable with no file extension — this is normal for Linux/macOS. Do not attempt to unzip it. You can verify it with `file ./grd-siem-agent` (should show `ELF 64-bit`).

### 2. Install

Download the install script and run it. You do **not** need to clone the repository:

```bash
curl -Lo install.sh https://raw.githubusercontent.com/KAPA-8/grd-siem-agent/main/scripts/install.sh
sudo bash install.sh --binary ./grd-siem-agent
```

This creates:

| Path | Owner | Purpose |
|------|-------|---------|
| `/opt/grd-siem-agent/` | `root` | Binary + update script |
| `/etc/grd-siem-agent/config.yaml` | `root:grd-agent` (640) | Configuration (contains secrets) |
| `/var/lib/grd-siem-agent/` | `grd-agent` (750) | Data: buffer, checkpoint, update staging |
| `/var/log/grd-siem-agent/` | `grd-agent` (750) | Log files |

### 3. Configure

```bash
sudo nano /etc/grd-siem-agent/config.yaml
```

Register the agent from the GRD platform web interface. The dashboard will provide you with an `agent_id` and `agent_token`. Set them in the config along with your SIEM connection details:

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
    validate_ssl: false
```

### 4. Validate

```bash
sudo -u grd-agent /opt/grd-siem-agent/grd-siem-agent validate \
  --config /etc/grd-siem-agent/config.yaml
```

### 5. Start

```bash
sudo systemctl start grd-siem-agent
sudo systemctl status grd-siem-agent
```

## Windows Installation

> **All commands must be run in an Administrator PowerShell session.** Right-click PowerShell and select "Run as Administrator".

```powershell
# 1. Download binary from GitHub Releases
Invoke-WebRequest -Uri "https://github.com/KAPA-8/grd-siem-agent/releases/latest/download/grd-siem-agent-windows-amd64.exe" -OutFile "grd-siem-agent.exe"

# 2. Download install script
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/KAPA-8/grd-siem-agent/main/scripts/install.ps1" -OutFile "install.ps1"

# 3. Run as Administrator
.\install.ps1 -BinaryPath .\grd-siem-agent.exe
```

This creates:

| Path | Purpose |
|------|---------|
| `C:\Program Files\GRD SIEM Agent\` | Binary + update script |
| `C:\ProgramData\GRD SIEM Agent\config.yaml` | Configuration |
| `C:\ProgramData\GRD SIEM Agent\data\` | Buffer, checkpoint |
| `C:\ProgramData\GRD SIEM Agent\logs\` | Log files |

The agent installs as a Windows Service (`GRDSIEMAgent`) with automatic startup and restart-on-failure recovery.

```powershell
# Configure
notepad "C:\ProgramData\GRD SIEM Agent\config.yaml"

# Start / Stop / Status
Start-Service GRDSIEMAgent
Stop-Service GRDSIEMAgent
Get-Service GRDSIEMAgent

# View logs
Get-Content "C:\ProgramData\GRD SIEM Agent\logs\agent.log" -Tail 50 -Wait

# Check version
& "C:\Program Files\GRD SIEM Agent\grd-siem-agent.exe" version

# Uninstall
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/KAPA-8/grd-siem-agent/main/scripts/uninstall.ps1" -OutFile "uninstall.ps1"
.\uninstall.ps1          # Keeps config and data
.\uninstall.ps1 -Purge   # Removes everything
```

## Configuration Reference

| Section | Key | Default | Description |
|---------|-----|---------|-------------|
| `agent.name` | | `"GRD SIEM Agent"` | Human-readable name for this agent |
| `agent.hostname` | | auto-detected | Override hostname |
| `platform.url` | | **required** | GRD platform URL |
| `platform.agent_token` | | **required** | Token from GRD Dashboard registration |
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
| `buffer.path` | | `"/var/lib/grd-siem-agent/buffer.db"` | Buffer file path |
| `buffer.max_size_mb` | | `500` | Max buffer size |
| `logging.level` | | `"info"` | Log level: `debug`, `info`, `warn`, `error` |
| `logging.path` | | `""` | Log file path (empty = stderr) |
| `logging.max_size_mb` | | `100` | Max log file size |
| `heartbeat.interval_seconds` | | `60` | Heartbeat frequency |
| `update.enabled` | | `true` | Enable auto-updates |
| `update.check_interval_minutes` | | `10` | Update check frequency in minutes (takes priority over hours) |
| `update.check_interval_hours` | | `0` | Update check frequency in hours (used if minutes is 0) |
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
grd-siem-agent validate  # Validate configuration file
grd-siem-agent update    # Check for and stage updates
grd-siem-agent version   # Print version information
```

### Flags

```
--config, -c    Path to config file (default: config.yaml)
```

#### `update` flags
```
--check         Only check for updates, don't download
```

## Auto-Updates

The agent automatically checks GitHub Releases for new versions every 10 minutes (configurable). When an update is found:

1. Downloads the binary for the current platform
2. Verifies SHA256 checksum against `checksums.txt`
3. Stages the update in `/var/lib/grd-siem-agent/.update/`
4. Exits to trigger a service restart
5. On restart, `apply-update.sh` verifies and replaces the binary

To trigger an update manually:

```bash
# Check if an update is available
sudo -u grd-agent /opt/grd-siem-agent/grd-siem-agent update --check \
  --config /etc/grd-siem-agent/config.yaml

# Download and stage update
sudo -u grd-agent /opt/grd-siem-agent/grd-siem-agent update \
  --config /etc/grd-siem-agent/config.yaml

# Apply by restarting the service
sudo systemctl restart grd-siem-agent

# Verify new version
/opt/grd-siem-agent/grd-siem-agent version
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
│   └── /api/v1/siem-agent/heartbeat  → health status
├── Buffer (SQLite, offline resilience)
│   └── Stores failed batches, drains on next cycle
├── Heartbeat (background, every 60s)
│   └── Reports uptime, memory, version, status
└── Updater (background, every 10min)
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

### Directory Layout (Linux production)

```
/opt/grd-siem-agent/
├── grd-siem-agent              # Main binary (root:root, 755)
└── apply-update.sh             # Update applier (root:root, 755)

/etc/grd-siem-agent/
└── config.yaml                 # Configuration (root:grd-agent, 640)

/var/lib/grd-siem-agent/        # Data directory (grd-agent:grd-agent, 750)
├── buffer.db                   # SQLite offline buffer
├── .grd-agent-checkpoint       # Last sync checkpoint
└── .update/                    # Update staging area
    └── pending.json            # Pending update metadata

/var/log/grd-siem-agent/        # Logs (grd-agent:grd-agent, 750)
└── agent.log
```

## Production Deployment

> **Requires root/sudo access.** All commands below must be executed as root or with `sudo`.

### Complete step-by-step

```bash
# 1. Download binary
curl -Lo grd-siem-agent https://github.com/KAPA-8/grd-siem-agent/releases/latest/download/grd-siem-agent-linux-amd64
chmod +x grd-siem-agent

# 2. Download and run installer (no need to clone the repo)
curl -Lo install.sh https://raw.githubusercontent.com/KAPA-8/grd-siem-agent/main/scripts/install.sh
sudo bash install.sh --binary ./grd-siem-agent

# 3. Configure (use values from GRD Dashboard)
sudo nano /etc/grd-siem-agent/config.yaml

# 4. Validate configuration
sudo -u grd-agent /opt/grd-siem-agent/grd-siem-agent validate \
  --config /etc/grd-siem-agent/config.yaml

# 5. Start and verify
sudo systemctl start grd-siem-agent
sudo systemctl status grd-siem-agent
sudo journalctl -u grd-siem-agent -f
```

### Minimal production config.yaml

This is the minimum config needed to run the agent after registering from the GRD Dashboard:

```yaml
agent:
  id: "agent-id-from-dashboard"
  name: "GRD SIEM Agent"

platform:
  url: "https://your-platform.example.com"
  agent_token: "grd_agent_xxxxx"

siem:
  type: "qradar"
  connection_id: "uuid-from-dashboard"
  api_url: "https://10.1.11.61"
  credentials:
    api_key: "your-qradar-sec-token"
    validate_ssl: false

sync:
  interval_minutes: 5
  lookback_days: 7
  max_alerts_per_sync: 1000
  filters:
    min_severity: "low"

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
```

> **Important:** Always include the `update` section — without it, auto-updates will not work. With `check_interval_minutes: 10`, the agent will detect and apply new releases within 10 minutes of publishing.

### File permissions summary

| Path | Owner | Mode | Notes |
|------|-------|------|-------|
| `/opt/grd-siem-agent/grd-siem-agent` | `root:root` | `755` | Binary, read-only for agent |
| `/opt/grd-siem-agent/apply-update.sh` | `root:root` | `755` | Runs as ExecStartPre (root) |
| `/etc/grd-siem-agent/config.yaml` | `root:grd-agent` | `640` | Contains secrets, readable by agent |
| `/var/lib/grd-siem-agent/` | `grd-agent:grd-agent` | `750` | Writable by agent (buffer, checkpoint) |
| `/var/log/grd-siem-agent/` | `grd-agent:grd-agent` | `750` | Writable by agent (logs) |

### Systemd service details

The service runs with the following security hardening:

- **User/Group:** `grd-agent` (unprivileged, no login shell)
- **NoNewPrivileges:** `true`
- **ProtectSystem:** `strict` (filesystem is read-only except allowed paths)
- **ProtectHome:** `true`
- **PrivateTmp:** `true`
- **MemoryMax:** `200M` / **MemoryHigh:** `100M`
- **ReadWritePaths:** `/var/lib/grd-siem-agent`, `/var/log/grd-siem-agent`, `/opt/grd-siem-agent`
- **Restart:** `on-failure` with 10s delay

### Verifying the installation

```bash
# Check service status
sudo systemctl status grd-siem-agent

# View real-time logs
sudo journalctl -u grd-siem-agent -f

# View agent log file
sudo tail -f /var/log/grd-siem-agent/agent.log

# Check current version
/opt/grd-siem-agent/grd-siem-agent version

# Verify binary architecture
file /opt/grd-siem-agent/grd-siem-agent
# Expected: ELF 64-bit LSB executable, x86-64 (for amd64)
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

- Runs as unprivileged system user `grd-agent` (no login shell)
- systemd hardening: `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`
- Config file permissions `640` — contains API keys, readable only by root and grd-agent group
- Memory limits enforced: 200 MB max
- Update binaries verified with SHA256 checksums before installation
- All platform communication over HTTPS with Bearer token authentication
- Checkpoint and buffer stored in `/var/lib/grd-siem-agent/` (writable only by grd-agent)

## Troubleshooting

> **All troubleshooting commands require root/sudo (Linux) or Administrator (Windows).**

### Check agent status

```bash
sudo systemctl status grd-siem-agent
```

### View logs

```bash
# Real-time logs (systemd journal)
sudo journalctl -u grd-siem-agent -f

# Last 100 lines
sudo journalctl -u grd-siem-agent -n 100 --no-pager

# Log file
sudo tail -100 /var/log/grd-siem-agent/agent.log
```

### Validate configuration

```bash
sudo -u grd-agent /opt/grd-siem-agent/grd-siem-agent validate \
  --config /etc/grd-siem-agent/config.yaml
```

### Common issues

| Issue | Cause | Solution |
|-------|-------|----------|
| `status=203/EXEC` in systemd | `apply-update.sh` missing or not executable | Download it: `sudo curl -Lo /opt/grd-siem-agent/apply-update.sh https://raw.githubusercontent.com/KAPA-8/grd-siem-agent/main/scripts/apply-update.sh && sudo chmod 755 /opt/grd-siem-agent/apply-update.sh` |
| `cp: no se puede crear el fichero` in apply-update | `ExecStartPre` runs as `grd-agent` but `/opt/` is owned by root | Update to v0.1.3+ (uses `ExecStartPre=+` to run as root). Manual fix: change `ExecStartPre=/opt/...` to `ExecStartPre=+/opt/...` in the service file |
| `permission denied` on checkpoint | Checkpoint written to read-only `/etc/` | Update to v0.1.1+ (writes to `/var/lib/grd-siem-agent/`). Manual fix: `sudo chown grd-agent:grd-agent /etc/grd-siem-agent/` |
| `no releases found` on update | Missing `update` section in config | Add `update:` section with `github_repo: "KAPA-8/grd-siem-agent"` to config.yaml |
| `registration failed` | Invalid credentials | Verify `agent.id` and `platform.agent_token` match what the GRD Dashboard provided |
| `collector init: connection refused` | Can't reach SIEM | Verify `siem.api_url` is reachable: `curl -k https://SIEM_IP/api/help/versions` |
| `sync failed (403)` | Invalid agent token | Verify `platform.agent_token` matches what dashboard/registration returned |
| `certificate verify failed` | Self-signed SIEM cert | Set `siem.credentials.validate_ssl: false` |
| QRadar `/system/about` returns 403 | API key lacks permission for that endpoint | Safe to ignore — the agent works via the offenses endpoint |
| Agent not collecting alerts | Severity filter too strict | Lower `sync.filters.min_severity` (e.g., `"low"` or `"info"`) |
| Buffer growing large | Platform unreachable | Check network/firewall to platform URL |
| Binary won't execute | Wrong architecture | Run `file ./grd-siem-agent` — must show `ELF 64-bit` for Linux, not `Mach-O` (macOS) |
| `unzip: cannot find zipfile` | Tried to unzip the binary | The binary is not a zip — run it directly with `./grd-siem-agent` |

### Force manual update

```bash
sudo -u grd-agent /opt/grd-siem-agent/grd-siem-agent update \
  --config /etc/grd-siem-agent/config.yaml
sudo systemctl restart grd-siem-agent
/opt/grd-siem-agent/grd-siem-agent version
```

### Uninstall

```bash
# Linux
curl -Lo uninstall.sh https://raw.githubusercontent.com/KAPA-8/grd-siem-agent/main/scripts/uninstall.sh
sudo bash uninstall.sh          # Keeps config and data
sudo bash uninstall.sh --purge  # Removes everything
```

```powershell
# Windows (Administrator PowerShell)
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/KAPA-8/grd-siem-agent/main/scripts/uninstall.ps1" -OutFile "uninstall.ps1"
.\uninstall.ps1          # Keeps config and data
.\uninstall.ps1 -Purge   # Removes everything
```

## Tested and Verified

The following features have been validated in production environments:

**Linux (Ubuntu Server + QRadar SIEM):**

- [x] Binary download and installation without cloning the repo
- [x] Systemd service with security hardening (ProtectSystem=strict, NoNewPrivileges, MemoryMax)
- [x] Agent registration from GRD Dashboard
- [x] QRadar offense collection via REST API
- [x] Alert sync to GRD platform (34 alerts imported successfully)
- [x] Heartbeat monitoring (60s interval)
- [x] SQLite buffer for offline resilience
- [x] Auto-update from GitHub Releases (v0.1.0 → v0.1.2 verified)
- [x] Checkpoint persistence in `/var/lib/grd-siem-agent/`
- [x] `apply-update.sh` running as root via `ExecStartPre=+`

**Windows Server + QRadar SIEM:**

- [x] Binary download and installation via PowerShell
- [x] Windows Service (GRDSIEMAgent) with automatic startup and restart-on-failure
- [x] QRadar offense collection via REST API
- [x] Alert sync to GRD platform
- [x] Heartbeat monitoring
- [x] SQLite buffer for offline resilience

**General:**

- [x] Cross-compilation for 5 platforms via GitHub Actions
- [x] SHA256 checksum verification on updates
- [x] Auto-update check every 10 minutes

## License

Proprietary - GRD Platform. All rights reserved.
