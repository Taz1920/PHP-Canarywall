# PHP Sentinel

A reverse proxy that defends PHP applications against CVE-2026-109618, CVE-2026-109619, and the broader class of PHP SAPI parsing exploits. Two layers of protection:

1. **Upload-progress filter** (primary) — blocks any multipart request containing `PHP_SESSION_UPLOAD_PROGRESS`, the root attack surface for CVE-2026-109618. Deterministic, no latency cost.
2. **Canary array** (defense in depth) — replays every request through 11 isolated PHP-FPM instances (PHP 5.6–8.4) in parallel. If any canary worker crashes, OOMs, or hangs, the request is blocked before production sees it. Catches unknown parser bugs that the filter doesn't cover.

**Designed as a compensating control for EOL PHP versions (5.6, 7.x, 8.0, 8.1) where no vendor patch exists.**

## How It Works

```
                          Client Request
                               │
                               ▼
                       ┌───────────────┐
                       │   Sentinel    │   Port 8080
                       │    Proxy      │   (Python / aiohttp)
                       └───────┬───────┘
                               │
              ┌── Upload-progress field? ── YES → Block (403)
              │
              NO
              │
              Fan out to ALL canaries in parallel
              ┌────────┬───────┼───────┬────────┐
              ▼        ▼       ▼       ▼        ▼
          ┌───────┐┌───────┐┌─────┐┌───────┐┌───────┐
          │PHP 8.4││PHP 8.3││ ... ││PHP 7.0││PHP 5.6│
          │Canary ││Canary ││     ││Canary ││Canary │
          └───┬───┘└───┬───┘└──┬──┘└───┬───┘└───┬───┘
              │        │       │       │        │
              └────────┴───────┼───────┴────────┘
                               │
                  ALL survived? ─► YES → Forward to production
                               └─► ANY died → Block (403)
                               │
                               ▼
                       ┌───────────────┐
                       │  Production   │
                       │   Backend     │
                       └───────────────┘
```

Every canary runs in isolation: no database, no secrets, no network egress. Its only job is to parse the request through PHP's SAPI code paths. An exploit that targets PHP 7.4's parser but not 8.4's still gets caught, and vice versa.

### Limitations

- The canary array detects exploits that **crash** PHP workers. A successful RCE that runs without crashing is not caught by the canaries — the upload-progress filter is the primary defense against CVE-2026-109619's use-after-free.
- Canaries run `memory_limit=16M`, not production's config. OOM thresholds can differ. The canaries are a safety net, not a guarantee.
- CVE-2026-109619 corrupts worker state across multiple requests. Single-request canary replay does not reproduce multi-request heap grooming. The upload-progress filter covers this gap.
- Adds latency per request (parallel canary replay, bounded by the slowest canary). The upload-progress filter adds none.

## Request Size Limits

Canaries run with `memory_limit=16M`, so uploads larger than ~15MB will OOM the canary workers and be blocked. The proxy's `SENTINEL_MAX_REPLAY_BODY` (default 32MB) sets the maximum body size accepted; requests exceeding it are rejected with HTTP 413.

## Features

- **Multi-version canary array** — ships with 11 PHP versions (5.6 through 8.4), all running in parallel
- **Admin API + built-in dashboard** — enable/disable canaries at runtime, view health and attack metrics at `/__sentinel/dashboard`
- **Defense in depth** — deterministic upload-progress filter plus canary crash detection for unknown parser bugs
- **Block logging** — every blocked request is logged with method, path, and sanitized headers (JSONL). Sensitive headers (Cookie, Authorization) are redacted.
- **Per-canary metrics** — errors, timeouts, and crashes tracked per PHP version

## Quick Start

```bash
git clone https://github.com/Taz1920/php-sentinel.git
cd php-sentinel

# Build all canary images (first run takes a few minutes)
docker compose build

# Start the full stack
docker compose up -d

# Verify — clean request passes through
curl http://localhost:8080/

# Health check
curl http://localhost:8080/__sentinel/health

# Admin API — list all canaries
curl http://localhost:8080/__sentinel/admin/canaries

# Open the dashboard
# → http://localhost:8080/__sentinel/dashboard
```

### Building Individual Canary Images

If you only need specific PHP versions:

```bash
# Build a single version
docker build -t php-sentinel-canary-74:latest \
  --build-arg PHP_IMAGE=php:7.4-fpm ./canary

# Build all 11 versions
for ver in 84 83 82 81 80 74 73 72 71 70 56; do
  case $ver in
    84) img=php:8.4-fpm ;; 83) img=php:8.3-fpm ;;
    82) img=php:8.2-fpm ;; 81) img=php:8.1-fpm ;;
    80) img=php:8.0-fpm ;; 74) img=php:7.4-fpm ;;
    73) img=php:7.3-fpm ;; 72) img=php:7.2-fpm ;;
    71) img=php:7.1-fpm ;; 70) img=php:7.0-fpm ;;
    56) img=php:5.6-fpm ;;
  esac
  docker build -t php-sentinel-canary-$ver:latest \
    --build-arg PHP_IMAGE=$img ./canary
done
```

## Configuration

All settings are environment variables on the `sentinel` container:

| Variable | Default | Description |
|---|---|---|
| `SENTINEL_CANARY_URLS` | `http://canary:9080` | Comma-separated canary URLs |
| `SENTINEL_BACKEND_URL` | `http://backend:80` | Production backend URL |
| `SENTINEL_PORT` | `8080` | Proxy listen port |
| `SENTINEL_CANARY_TIMEOUT` | `5` | Seconds to wait for canary response |
| `SENTINEL_MAX_REPLAY_BODY` | `33554432` | Max body size to replay (32MB). Larger requests bypass canaries. |
| `SENTINEL_BLOCK_LOG` | `/var/log/sentinel/blocked.jsonl` | Path for blocked request log |
| `SENTINEL_BLOCK_UPLOAD_PROGRESS` | `true` | Block any multipart request containing `PHP_SESSION_UPLOAD_PROGRESS`. This is the attack surface for CVE-2026-109618/109619. Set to `false` only if your app uses PHP's session upload progress feature. |
| `SENTINEL_WEBHOOK_URL` | *(empty)* | URL to POST block events to (SIEM, Slack, CrowdStrike, Splunk HEC, etc.). Each blocked request sends a JSON payload with client IP, method, path, headers, and which canaries were killed. |
| `SENTINEL_ADMIN_KEY` | *(random)* | API key for admin/dashboard access. If not set, a random key is generated and printed to the container logs on startup. |
| `SENTINEL_VERBOSE` | `false` | Log every request |

## Authentication

The admin API, dashboard, and metrics endpoints are all protected by an API key. Set your key in the environment:

```bash
# Option 1: Set in docker-compose.yml or .env file
SENTINEL_ADMIN_KEY=your-secret-key-here

# Option 2: Let Sentinel generate a random key (check the logs)
docker logs php-sentinel 2>&1 | grep ADMIN_KEY
```

The dashboard at `/__sentinel/dashboard` will prompt you for the key on first visit. For API calls, pass the key via header:

```bash
curl -H "X-Sentinel-Key: your-key" http://localhost:8080/__sentinel/admin/canaries
```

The health endpoint (`/__sentinel/health`) remains public for load balancer health checks.

## Webhook / SIEM Integration

Send block alerts to any HTTP endpoint — CrowdStrike, Splunk, Elastic, Datadog, Slack, or any webhook receiver:

```bash
# Set in docker-compose.yml or .env
SENTINEL_WEBHOOK_URL=https://your-siem.example.com/api/events

# Splunk HEC example
SENTINEL_WEBHOOK_URL=https://splunk.example.com:8088/services/collector/event

# Slack incoming webhook
SENTINEL_WEBHOOK_URL=https://hooks.slack.com/services/T.../B.../xxx
```

Every blocked request POSTs a JSON payload:

```json
{
  "event": "request_blocked",
  "source": "php-sentinel",
  "ts": "2026-10-22T15:30:00+0000",
  "client_ip": "203.0.113.42",
  "method": "POST",
  "path": "/index.php",
  "content_type": "multipart/form-data",
  "content_length": 15728640,
  "killed_canaries": ["canary-81", "canary-74"],
  "headers": { "..." },
  "body_preview": "..."
}
```

Webhooks fire asynchronously and never block request handling. Failed deliveries are logged but don't affect proxy operation.

## Admin API

Manage canaries at runtime without restarting the stack.

```bash
# List all canaries with health and metrics
curl http://localhost:8080/__sentinel/admin/canaries

# Disable a canary
curl -X POST http://localhost:8080/__sentinel/admin/canaries/canary-56/disable

# Enable a canary
curl -X POST http://localhost:8080/__sentinel/admin/canaries/canary-56/enable

# Bulk update — enable only EOL versions
curl -X POST http://localhost:8080/__sentinel/admin/canaries/bulk \
  -H "Content-Type: application/json" \
  -d '{"enabled": ["canary-81","canary-80","canary-74","canary-73","canary-72","canary-71","canary-70","canary-56"]}'

# Metrics
curl http://localhost:8080/__sentinel/metrics
```

## Detection Signals

| Canary Response | Meaning | Proxy Action |
|---|---|---|
| 200 | Request parsed cleanly | Forward to backend |
| 500 | PHP fatal error (OOM, etc.) | **Block** |
| 502 | FPM worker segfaulted | **Block** |
| 503 | FPM pool exhausted | **Block** |
| 504 / timeout | Worker hung | **Block** |
| Connection reset | Worker died mid-response | **Block** |

## Testing

Two test suites are included:

```bash
# Kill test — targeted attacks that actually crash canary workers
pip install aiohttp
python tests/kill_test.py

# Stress test — 17 payload types + sustained flood
python tests/stress_test.py --flood-duration 10
```

The kill test exercises:
- SIGKILL / timeout / OOM via test headers
- 20MB body OOM attacks via `php://input`
- Concurrent worker kills (4x 15MB simultaneous)
- Session upload progress spam (20x 17MB multipart)

## Connecting to Your App

PHP Sentinel sits between the internet and your PHP application. You have two options:

### Option 1: Point Sentinel at your existing server

Edit `docker-compose.yml` and change the `SENTINEL_BACKEND_URL` to your app's address:

```yaml
environment:
  SENTINEL_BACKEND_URL: "http://your-php-server:80"  # your real app
```

Then remove or ignore the `backend` service — you don't need it. Start the stack and route traffic through port 8080 instead of directly to your app.

### Option 2: Run your app inside the Compose stack

Replace the `backend` service in `docker-compose.yml` with your own PHP container:

```yaml
backend:
  image: your-app-image:latest
  # or build: ./your-app
  expose:
    - "80"
  networks:
    - sentinel-net
```

### Putting it in front of a live site

1. Deploy the Sentinel stack on the same server (or a server that can reach your app)
2. Point your load balancer / reverse proxy / DNS at Sentinel's port (8080) instead of directly at your PHP app
3. Sentinel forwards clean traffic to your app automatically

```
Internet → Load Balancer → Sentinel (:8080) → Your PHP App (:80)
```

Works with any PHP application: WordPress, Laravel, Drupal, CodeIgniter, custom apps — anything served by PHP over HTTP.

## Deployment

### Docker Compose (included)

The default `docker-compose.yml` runs all 11 canaries plus the proxy.

```bash
docker compose build   # build canary images
docker compose up -d   # start everything
```

### Standalone (no Compose)

```bash
# Build and run a single canary
docker build -t canary --build-arg PHP_IMAGE=php:8.1-fpm ./canary
docker run -d --name canary -p 9080:9080 canary

# Run the proxy (Python 3.8+)
pip install aiohttp
SENTINEL_CANARY_URLS=http://localhost:9080 \
SENTINEL_BACKEND_URL=http://your-app:80 \
python proxy/sentinel.py
```

### Cloud / VPS

Same Docker Compose stack — just set `SENTINEL_BACKEND_URL` to your app's internal address. Works on any host that runs Docker: EC2, DigitalOcean, Linode, Vultr, Hetzner, etc.

### Kubernetes

Deploy each canary as a sidecar or as separate services in the same namespace. Point `SENTINEL_CANARY_URLS` at all of them. The proxy is stateless and horizontally scalable.

## Architecture

- **Canary isolation** — no database, no secrets, dangerous functions disabled, `memory_limit=16M`, `pm.max_children=4`
- **Bind-mounted configs** — `index.php`, `php.ini`, `fpm.conf`, and `nginx.conf` are shared across all canary versions via volume mounts
- **Archived repo support** — the Dockerfile automatically handles EOL Debian distributions (jessie, stretch, buster, bullseye) whose apt repos have moved to `archive.debian.org`
- **PHP 5.6 compatibility** — the canary PHP script uses `isset()` ternary instead of `??` for compatibility back to 5.6

## License

MIT
