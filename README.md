# SOC IP Blocker

Centralized IP blocklist management tool for Security Operations Centers. Push IP blocks to pfSense firewalls (via web interface) and Linux devices (via SSH) from a single dashboard.

## Features

- Central IP blocklist with push to all managed devices
- pfSense support via web interface (null route or floating rule)
- Linux support via SSH (`ip route add blackhole`)
- Concurrent push to 50+ devices
- Background device health monitoring
- Bootstrap 5 responsive dashboard

## Quick Start with Docker

```bash
# Clone and start
docker compose up -d

# Access the dashboard
open http://localhost:5000
```

Default credentials: `admin` / `admin`

## Configuration

Set environment variables in `docker-compose.yml` or via a `.env` file:

| Variable | Default | Description |
|---|---|---|
| `SECRET_KEY` | `change-me-in-production` | Flask session secret key |
| `DATABASE_PATH` | `/data/soc_ip_blocker.db` | SQLite database location |

## Production Deployment

1. Generate a strong secret key:

```bash
python3 -c "import secrets; print(secrets.token_hex(32))"
```

2. Create a `.env` file:

```
SECRET_KEY=your-generated-secret-key
```

3. Start the stack:

```bash
docker compose up -d --build
```

The SQLite database is persisted in a Docker volume (`soc-data`). Data survives container restarts and rebuilds.

## Running Without Docker

```bash
pip install -r requirements.txt
python app.py
```

The app runs on `http://localhost:5000` with debug mode enabled.

## Running Tests

```bash
pip install -r requirements.txt
python -m pytest tests/ -v
```

## Architecture

```
Flask App
├── Auth (session-based login)
├── Blocklist Service (IP validation, CRUD)
├── Push Engine (ThreadPoolExecutor, concurrent push)
├── pfSense Client (HTTP form submission, CSRF tokens)
├── Linux Client (Paramiko SSH)
├── Status Monitor (APScheduler background checks)
└── SQLite Database (blocklist, devices, push logs, settings)
```
