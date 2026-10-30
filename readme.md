# GRD SIEM Agent

On-premises agent that collects security alerts from your SIEM (IBM QRadar, Stellar Cyber Open XDR) and sends them to the [GRD Cyber Risk](https://grd.com) platform for centralized risk management.

## Features

- **QRadar integration** - Collects offenses via REST API with MITRE ATT&CK mapping
- **Stellar Cyber integration** - Collects alerts or cases from Stellar Cyber SaaS or on-prem, with native MITRE ATT&CK data ([details](#stellar-cyber-open-xdr))
- **No duplicates, no gaps** - Each alert carries its SIEM ID (the platform deduplicates on it), and the checkpoint only advances once the platform imported every alert
- **Offline resilience** - SQLite buffer stores undelivered alerts locally until the platform accepts them
- **Proxy and private CAs** - Honours `HTTPS_PROXY`/`NO_PROXY`; trusts an extra CA bundle (`ca_cert_file`)
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
sudo bash install.sh --binary ./grd-siem-agent                              # QRadar
sudo bash install.sh --binary ./grd-siem-agent --siem-type stellar_cyber    # Stellar Cyber
```

`--siem-type` only selects the config template written on a first install (an existing `config.yaml` is never overwritten). `bash install.sh --siem-type stellar_cyber --print-config` prints the template without installing.

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

For Stellar Cyber, see [Stellar Cyber Open XDR](#stellar-cyber-open-xdr).

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

# 3. Run as Administrator (add -SiemType stellar_cyber for a Stellar Cyber template)
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

## Stellar Cyber Open XDR

The `stellar_cyber` collector works with Stellar Cyber SaaS and with on-prem Data Processors (5.x and later; pre-5.x builds without a token endpoint are handled with per-call Basic authentication).

### SaaS or on-prem

| | SaaS | On-prem |
|---|---|---|
| `siem.deployment` | `saas` (default) | `onprem` |
| `siem.api_url` | `https://<tenant>.stellarcyber.cloud` | `https://<data-processor-host>` (the DP management address, port 443) |
| TLS | Always verified; `validate_ssl` is ignored | Verified by default. For a self-signed DP certificate set `ca_cert_file` to the CA (or the certificate) in PEM, or as a last resort `validate_ssl: false` |
| Network | Outbound HTTPS to `*.stellarcyber.cloud`, usually through the corporate proxy | HTTPS from the agent host to the DP |

Paste the URL you open in the browser; a trailing `/` or a `/connect/api/...` suffix is removed.

### Creating the API credential

Stellar Cyber only allows API access for **local accounts** (not SSO). Use a dedicated service account.

| `credentials.auth_mode` | Credential | How to create it | Needs `username` |
|---|---|---|---|
| `api_token` (default) | All-Access API token | As a **root-scope Super Admin**: System → Organization Management → Users → edit the user → **API Access → Generate New Token** | Yes: the account **email**, case-sensitive |
| `scoped_key` | User API key (Stellar Cyber 5.5+) | Any user, for their own account: User Profile (or Edit User) → **API Keys** → **Create API Key**. It has that user's privileges and tenants | No |

The agent exchanges the credential for a 10-minute access token (`POST /connect/api/v1/access_token`) and refreshes it automatically.

### Choosing the data source

| `siem.data_source` | Reads | Requires | Use when |
|---|---|---|---|
| `alerts` (default, recommended) | Every alert in the `aella-ser-*` index | A root All-Access `api_token`, or a `scoped_key` on Stellar Cyber 6.3+ | You want all detections |
| `cases` | The alerts attached to cases | Any key with permission to read cases | You only have a scoped key on an older version, or you only want alerts that became cases |

A `403` during startup with `data_source: alerts` means the key cannot read the alert index: switch to `cases` or use a root All-Access token.

What is collected:

- **Alerts mode** queries alerts by ingestion time (`write_time`) since the last checkpoint, up to 2 minutes before now so late writes are not missed, sorted oldest first. Alerts marked **Ignored** (false positives) are skipped.
- **Cases mode** reads the cases modified since the last checkpoint, one query per status (**New, In Progress, Escalated, Resolved**; **Cancelled** is skipped), then each case's alerts. An alert in several cases is sent once, with the first case's ID and name.
- `sync.filters.min_severity` filters on the Stellar Cyber score (0-100): `info` 0, `low` 20, `medium` 40, `high` 60, `critical` 80. The same bands set each alert's severity.
- `credentials.tenant_id` limits collection to one tenant (`cust_id`), for MSSP/multi-tenant platforms.
- Each cycle reads up to `sync.max_alerts_per_sync` alerts (at most 10000) and posts them in batches of 500. A larger backlog continues on the next cycle.

### Example

```yaml
siem:
  type: "stellar_cyber"
  connection_id: "uuid-from-dashboard"
  api_url: "https://acme.stellarcyber.cloud"
  deployment: "saas"
  data_source: "alerts"
  credentials:
    auth_mode: "api_token"
    username: "grd-api@acme.com"
    api_key: ""               # set GRD_SIEM_CREDENTIALS_API_KEY instead of storing it here
    tenant_id: ""
```

On-prem with a private CA:

```yaml
siem:
  type: "stellar_cyber"
  connection_id: "uuid-from-dashboard"
  api_url: "https://10.20.0.15"
  deployment: "onprem"
  data_source: "cases"
  credentials:
    auth_mode: "scoped_key"
    api_key: "scoped-key"
    validate_ssl: true
    ca_cert_file: "/etc/grd-siem-agent/stellar-dp-ca.pem"
```

### Proxy

The agent uses the standard `HTTPS_PROXY`, `HTTP_PROXY` and `NO_PROXY` variables for both the SIEM and the GRD platform. With systemd:

```bash
sudo systemctl edit grd-siem-agent
# [Service]
# Environment=HTTPS_PROXY=http://proxy.corp.local:3128
# Environment=NO_PROXY=10.0.0.0/8,localhost
sudo systemctl restart grd-siem-agent
```

## Configuration Reference

| Section | Key | Default | Description |
|---------|-----|---------|-------------|
| `agent.name` | | `"GRD SIEM Agent"` | Human-readable name for this agent |
| `agent.hostname` | | auto-detected | Override hostname |
| `platform.url` | | **required** | GRD platform URL |
| `platform.agent_token` | | **required** | Token from GRD Dashboard registration |
| `siem.type` | | **required** | SIEM type: `qradar`, `stellar_cyber` |
| `siem.connection_id` | | **required** | Connection UUID from platform dashboard |
| `siem.api_url` | | **required** | SIEM console/API URL |
| `siem.deployment` | | `"saas"` | Stellar Cyber: `saas` or `onprem` |
| `siem.data_source` | | `"alerts"` | Stellar Cyber: `alerts` or `cases` |
| `siem.credentials.api_key` | | **required** | QRadar SEC token, Stellar Cyber API token or scoped key |
| `siem.credentials.auth_mode` | | `"api_token"` | Stellar Cyber: `api_token` or `scoped_key` |
| `siem.credentials.username` | | | Stellar Cyber `api_token` mode: the API account email (case-sensitive) |
| `siem.credentials.tenant_id` | | | Stellar Cyber: only collect this tenant |
| `siem.credentials.validate_ssl` | | `true` | Validate the SIEM certificate (always on for Stellar Cyber SaaS) |
| `siem.credentials.ca_cert_file` | | | PEM bundle trusted in addition to the system CAs |
| `siem.credentials.api_version` | | `"19.0"` | QRadar API version |
| `sync.interval_minutes` | | `15` | Polling interval |
| `sync.lookback_days` | | `7` | First-run lookback window |
| `sync.max_alerts_per_sync` | | `1000` | Max alerts per cycle (1-10000; posted in batches of 500) |
| `sync.filters.min_severity` | | `"low"` | Minimum severity: `info`, `low`, `medium`, `high`, `critical` |
| `buffer.enabled` | | `true` | Enable offline SQLite buffer |
| `buffer.path` | | `"./buffer.db"` | Buffer file path (the installers set `/var/lib/grd-siem-agent/buffer.db`). The checkpoint is stored in the same directory |
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

All configuration keys can be set via environment variables with the `GRD_` prefix. Dots become underscores. A variable works even when the key is absent from `config.yaml`, which keeps secrets out of the file:

```bash
export GRD_PLATFORM_AGENT_TOKEN="your-token"
export GRD_SIEM_CREDENTIALS_API_KEY="your-siem-key"
export GRD_SYNC_INTERVAL_MINUTES=30
```

### Validation

`grd-siem-agent validate` (and every start) checks the whole configuration and reports every problem at once: the platform URL must use `https` (plain `http` is only accepted for `localhost`), `agent_token`, `connection_id` (a UUID), `api_url` and `api_key` are required, intervals must be greater than 0, and `max_alerts_per_sync` must be between 1 and 10000. Stellar Cyber settings are checked too (deployment, data source, auth mode, username, `https` for SaaS, a readable `ca_cert_file`).

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
├── Collector (SIEM-specific, selected by siem.type)
│   ├── QRadar: polls /api/siem/offenses, maps to MITRE ATT&CK
│   └── Stellar Cyber: alert index or cases, native MITRE ATT&CK data
├── Sender (HTTPS to GRD platform)
│   ├── /api/v1/siem-agent/sync       → send alerts (batches of 500)
│   │   └── Retried with backoff (about 1s, 2s, 4s ... up to 30s apart,
│   │       each wait randomized by ±50%, so 0.5s to 45s) for up to 2
│   │       minutes; each request times out after 90s. 4xx answers other
│   │       than 408/429 (400, 401, 403, 404, 422 ...) are not retried: the
│   │       batch goes to the buffer at once
│   └── /api/v1/siem-agent/heartbeat  → health status
├── Buffer (SQLite, offline resilience)
│   └── Stores the batches still undelivered when the retries run out (at
│       most ~3.5 min after the first attempt) or that got a non-retried
│       4xx, and keeps them until the platform accepts them; each cycle
│       tries them again first, and its collection then skips the alerts
│       just delivered, so a window is not posted twice. While the
│       platform is down, the window re-collected every cycle replaces its
│       buffered copy instead of piling up. A batch the platform refuses 5
│       times (e.g. its connection was deleted) is dropped, since the
│       checkpoint never passes undelivered alerts
├── Heartbeat (background, every 60s)
│   └── Reports uptime, memory, version and status (the SIEM health check
│       runs every 5 min, never while a collection is running):
│       healthy, degraded (delivery problems, reported from the first
│       failed attempt; buffered batches) or error (SIEM unreachable,
│       collector not initialized)
└── Updater (background, every 10min)
    └── Checks GitHub Releases, downloads, verifies, stages
```

### Alert Flow

```
SIEM (QRadar) ──poll──> Collector ──normalize──> Sender ──HTTPS──> GRD Platform
                                        │
                (still failing after 2 min of retries, or a 4xx
                 other than 408/429, which is not retried)
                                        │
                                     Buffer (SQLite)
                                        │
                                   (next cycle)
                                        │
                                     Drain ──resend──> GRD Platform
                                        │
                  (then collect, skipping the alerts just delivered)
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
├── .grd-agent-checkpoint-<id>  # Last delivered checkpoint, per connection
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
| Stellar Cyber Open XDR | Available | SaaS and on-prem 5.x - 7.x |
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
| `certificate verify failed` / `TLS certificate verification failed` | Self-signed or private-CA SIEM certificate | Set `siem.credentials.ca_cert_file` to the CA in PEM (preferred), or `validate_ssl: false`. Stellar Cyber SaaS is always verified: check the system CA store or the proxy |
| Stellar Cyber `access_token: HTTP 401` | Wrong credential | Check `api_key` and, with `auth_mode: api_token`, that `username` is the API account **email** with the exact case |
| Stellar Cyber `aella-ser-*/_search: HTTP 403` | The key cannot read the alert index | Use `data_source: cases`, or a root All-Access `api_token` (scoped keys need 6.3+) |
| Stellar Cyber `token endpoint not found` | Wrong `api_url`, or a pre-5.x build | Check the URL; for an old on-prem DP use `deployment: onprem` with `auth_mode: api_token` |
| Agent shows **error** in the dashboard | The collector cannot reach or log into the SIEM | The heartbeat detail and the agent log show the cause; the agent keeps retrying |
| QRadar `/system/about` returns 403 | API key lacks permission for that endpoint | Safe to ignore — the agent works via the offenses endpoint |
| Agent not collecting alerts | Severity filter too strict | Lower `sync.filters.min_severity` (e.g., `"low"` or `"info"`) |
| Agent shows **degraded** with `delivery to the platform failed` | `/sync` failed (5xx, 408, 429, timeout or connection error; or another 4xx, which is not retried). Shown from the first failed attempt | Check network/firewall/proxy to `platform.url`. After 2 minutes of retries (waits of about 1s to 30s, randomized by ±50%), or at once for a non-retried 4xx, the alerts are buffered and re-sent at the start of every cycle; the checkpoint does not advance until they are delivered |
| Buffer growing large | Platform unreachable | Check network/firewall to platform URL |
| `platform keeps refusing a buffered batch; dropping it` | A batch stored during an outage was refused 5 times (e.g. its SIEM connection was deleted or re-created) | Nothing to do: the batch is dropped and the alerts of the current connection are collected again from the checkpoint |
| Stellar Cyber `results are not sorted by write_time` | The alert search ignored `sort`, which incremental collection needs | Use `data_source: cases` and report the Stellar Cyber version |
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
