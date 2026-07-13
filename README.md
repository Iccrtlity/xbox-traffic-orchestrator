# Xbox Screen-Time Orchestrator

DNS-based Xbox screen-time control via AdGuard Home rewrite rules.
Blocks Xbox Live auth and Family Safety domains with fast atomic switching
and state caching to avoid flooding the AdGuard API.

## Quick Start

```bash
git clone https://github.com/Iccrtlity/xbox-traffic-orchestrator.git
cd xbox-traffic-orchestrator
chmod +x install.sh
./install.sh
```

The installer will:
1. Check that Docker is installed.
2. Ask for your AdGuard Home credentials (written to `.env`).
3. Create a `config.yaml` with sensible defaults.
4. Build and start the services via Docker Compose.

## Configuration

Edit `config.yaml` to customise:

| Parameter | Description |
|---|---|
| `xbox_domain` | List of domains to monitor and block |
| `bypass_duration` | Seconds to block after activity detection (default: `3600`) |
| `poll_interval` | Query-log polling interval in seconds (default: `30`) |
| `xbox_client_ip` | Optional: restrict to a specific Xbox IP |
| `startup_timeout` | Seconds to wait for AdGuard at boot (default: `120`) |

Sensitive fields (`adguard_user`, `adguard_pass`) are overridden by the
`.env` file when running in Docker – no need to put passwords in YAML.

After editing, restart the orchestrator:

```bash
docker compose restart orchestrator
```

## Architecture

```
┌──────────────┐   DNS queries   ┌──────────────┐
│  Xbox / LAN  │ ──────────────▸ │  AdGuard Home │
└──────────────┘                 └──────┬───────┘
                                        │ query log
                                 ┌──────▼───────┐
                                 │  Orchestrator │
                                 └──────┬───────┘
                                        │ /control/rewrite/*
                                 ┌──────▼───────┐
                                 │  AdGuard Home │
                                 └──────────────┘
```

The orchestrator polls the AdGuard DNS query log for Xbox-related domain
lookups.  When activity is detected it adds DNS rewrite rules
(`0.0.0.0`) via `/control/rewrite/add` to block those domains.
After `bypass_duration` seconds the rules are removed again.

State caching ensures the API is only called when the blocking state
actually changes – no redundant requests.

## Stopping / Bypass

To manually bypass blocking:

```bash
docker exec traffic-orchestrator touch /app/bypass
```

To remove a manual bypass:

```bash
docker exec traffic-orchestrator rm -f /app/bypass
```

## Logs

```bash
docker compose logs -f orchestrator
```
