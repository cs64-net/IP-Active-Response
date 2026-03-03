<p align="center">
  <img src="static/logo.svg" alt="IP Active Response" width="120">
</p>

<h1 align="center">IP Active Response</h1>
<p align="center"><strong>Cyber Membrane Suite</strong></p>
<p align="center">
  Rapid-response IP blocking for SOC teams. Push blocks across your entire network in seconds, deploy honeypots that automatically block attackers, and enforce geo-level IP restrictions — all from one interface.
</p>

---

## Screenshots

| Dashboard | Honeypot Dashboard |
|:-:|:-:|
| ![Dashboard](demo/demo1-dashboard.png) | ![Honeypot Dashboard](demo/demo2-honeypot-dashboard.png) |

| Honeypot Findings | DNS & Geo Blocking |
|:-:|:-:|
| ![Honeypot Findings](demo/demo2.1-honeypot-findings.png) | ![DNS & Geo Blocking](demo/demo3-dns-geo.png) |

<p align="center">
  <img src="demo/demo4-add-device.png" alt="Add Device" width="700">
</p>

---

## Key Features

- **Instant Network-Wide IP Blocking** — Push IP blocks to every managed device simultaneously using concurrent execution
- **Honeypot Integration (OpenCanary)** — Deploy honeypots that report back and automatically block attackers across the entire network
- **Geo-Blocking** — Block traffic from entire countries using aggregated IP blocklists from ipdeny.com
- **External Threat Feeds** — Subscribe to community blocklists (Spamhaus DROP, Feodo Tracker, etc.) with automatic refresh
- **DNS-Based Blocking** — Resolve malicious domains and block resolved IPs on devices that don't support native DNS filtering
- **SIEM Forwarding** — Forward honeypot alerts to Elasticsearch or Syslog
- **Reconciliation Engine** — Automatically detects and fixes drift between the blocklist and device state
- **Operation Queue** — Reliable background processing with retry logic for all device operations
- **Audit Logging** — Full audit trail of all blocking actions, feed updates, and configuration changes

## Supported Devices

| Device | Status |
|---|---|
| pfSense | Supported |
| Cisco IOS | Supported |
| Cisco ASA | Supported |
| Linux (SSH) | Beta |
| Fortinet FortiGate | Beta |
| Palo Alto Networks | Beta |
| Juniper SRX | Beta |
| Juniper MX | Beta |
| Check Point | Beta |
| Ubiquiti UniFi | Beta |
| AWS WAF | Beta |
| Azure NSG | Beta |
| GCP Firewall | Beta |
| OCI NSG | Beta |

## Quick Start (Docker)

```bash
# Clone the repository
git clone https://github.com/cs64-net/IP-Active-Response && cd ip-active-response

# Generate a secret key
export SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")

# Start
docker compose up -d

# Access the dashboard
open http://localhost:8000
```

Default credentials: `admin` / `admin` — you'll be prompted to change the password on first login.

## Manual Setup

```bash
pip install -r requirements.txt
python app.py
```

Runs on `http://localhost:5000` with debug mode.

## Configuration

| Variable | Default | Description |
|---|---|---|
| `SECRET_KEY` | `change-me-in-production` | Flask session secret |
| `DATABASE_PATH` | `/data/soc_ip_blocker.db` | SQLite database path |

## Architecture

```
IP Active Response 
├── Auth (session-based, rate-limited)
├── Blocklist Service (IP validation, CRUD)
├── Push Engine (ThreadPoolExecutor, concurrent push)
├── Device Clients (pfSense, Cisco, Fortinet, Palo Alto, Juniper, Check Point, Cloud)
├── Honeypot Manager (OpenCanary integration, auto-block)
├── Feed Manager (external blocklists, NDJSON/text parsing)
├── DNS Block Manager (domain resolution, stale IP cleanup)
├── Geo-Blocking (country-level IP feeds via ipdeny.com)
├── SIEM Forwarder (Elasticsearch, Syslog)
├── Reconciliation Engine (drift detection & correction)
├── Operation Queue (reliable background processing)
└── SQLite Database (WAL mode, connection pooling)
```

---

<p align="center"><strong>Lab Edition</strong> — Not for commercial use.<br>
