# PHP CanaryWall: Blocking php2shell Without Patching PHP

## The Problem

On October 21, 2026, two critical RCE vulnerabilities were disclosed in PHP — **CVE-2026-109618** and **CVE-2026-109619**, collectively known as **php2shell**. CVSS 9.2. Every PHP version from 5.4 through 8.5.11 is affected.

Patches exist for PHP 8.2.35, 8.3.36, 8.4.27, and 8.5.12. But PHP 8.1 and earlier? End of life. **No patch is coming.** A significant share of PHP deployments still run EOL versions with no upgrade path.

The standard mitigation is to disable `session.upload_progress.enabled`, but that only covers one of the two attack paths. The OOM corruption vector in CVE-2026-109618 has no PHP config-level fix.

## The Solution

**PHP CanaryWall** is a reverse proxy with two layers of protection:

1. **Upload-progress filter** — blocks any multipart request containing `PHP_SESSION_UPLOAD_PROGRESS`, the root attack surface for CVE-2026-109618. Deterministic, no latency cost.
2. **Canary array** — replays every request through 11 isolated PHP-FPM instances (PHP 5.6–8.4) in parallel. If any canary worker crashes, OOMs, or hangs, the request is blocked before production sees it.

```
Client Request
       |
       v
   Sentinel Proxy (Python/aiohttp)
       |
       Upload-progress field? --> YES --> Block (403)
       |
       NO --> Fan out to ALL canaries in parallel
       |
  [PHP 8.4] [PHP 8.3] [PHP 8.2] ... [PHP 7.0] [PHP 5.6]
       |
       ALL survived? --> Forward to production
       ANY died?     --> Block (403)
```

The upload-progress filter is deterministic. The canary array uses behavioral detection — no signatures, no pattern matching, no rule updates.

## Why It Works

The upload-progress filter directly blocks the CVE-2026-109618 attack surface. The canary array provides defense in depth: PHP parser exploits — OOM corruption, boundary parsing crashes — trigger during request parsing in the SAPI layer. The canary instances run in isolation on an internal Docker network: no database, no secrets, no egress to the backend. Their only job is to parse the request. If parsing kills the worker, the request is blocked.

The canary array catches:
- **Known crash-inducing exploits** like the OOM vectors in php2shell
- **Unknown future parser bugs** that crash PHP workers
- **Version-specific bugs** — an exploit targeting PHP 7.4's parser but not 8.4's still gets caught because 7.4 is in the canary array

**Limitations of the canary approach:**
- Exploits that succeed without crashing the worker (silent RCE) are not detected by the canaries. The upload-progress filter is the primary defense against CVE-2026-109618.
- CVE-2026-109619's cross-request state corruption requires grooming across multiple requests. Single-request canary replay does not reproduce this.
- Canaries run `memory_limit=16M`, not production's config. OOM thresholds can differ.

## Test Results

### Kill Test Suite

Built-in test suite covering worker crashes, memory pressure, and CVE exploit vectors.

```
PASS     Clean GET                                    HTTP 200
PASS     Clean POST                                   HTTP 200
BLOCKED  SIGKILL worker                               HTTP 403
BLOCKED  Timeout (hung worker)                        HTTP 403
BLOCKED  OOM (memory bomb)                            HTTP 403
BLOCKED  CVE vector: session upload + truncated multipart  HTTP 403 (filter)
BLOCKED  20MB body -> php://input OOM                 HTTP 403
BLOCKED  4x concurrent 15MB worker kills              HTTP 403 (4/4)
BLOCKED  20x session upload progress spam             HTTP 403 (20/20)

Per-canary breakdown: 24 errors each across all 11 versions (264 total).
```

All attack vectors blocked. Clean requests forwarded.

### Real CVE-2026-109618 PoC Exploit (Blocked)

Ran the public proof-of-concept exploit (`eness/php2shell-CVE-2026-109618-CVE-2026-109619-PoC`) against Sentinel. This is a full 3-stage exploit chain:

1. **Stage 1** — Heap leak via OOM + session upload progress (leaks Zend MM chunk base)
2. **Stage 2** — libphp base leak via HashTable page corruption
3. **Stage 3** — Fake HashTable + zif_system RCE

Result:

```
[*] target http://localhost:8080/ (cmd='id>/out/p1')
[*] rotating worker over HTTP
[*] stage 1: heap leak (attempt 1/2)
[-] heap leak missed
[*] stage 1: heap leak (attempt 2/2)
[-] heap leak missed
HEAP_LEAK_FAILED
```

**The exploit couldn't even complete stage 1.** Sentinel's canaries crashed on the OOM payloads and returned 403 instead of the session cookie containing the leaked heap addresses. Without those addresses, the entire exploit chain is dead. It didn't just block the RCE — it blocked the reconnaissance.

Dashboard after the attack:

```
Requests: 10 | Forwarded: 5 | Blocked: 5 | Block Rate: 50%
All 11 canaries: healthy, 5 errors each
```

## How It Differs From a WAF

Traditional WAFs (ModSecurity, Cloudflare WAF, etc.) use signature matching — they look for known attack patterns. This means:

- They can't catch zero-days they've never seen
- Rules need constant updates as new exploits emerge
- Evasion techniques can bypass pattern matching

Sentinel's canary array uses **behavioral detection**. It doesn't look at what the request contains — it observes what the request *does* to a PHP parser. If the parser dies, the request is blocked. This catches crash-inducing exploits that signatures haven't been written for yet.

The tradeoff: exploits that succeed without crashing the worker are invisible to the canaries. That's why the upload-progress filter exists as the primary deterministic layer.

Sentinel and WAFs complement each other. Use both.

## Deployment

Three commands:

```bash
git clone https://github.com/Taz1920/php-canarywall.git
cd php-canarywall
docker compose build && docker compose up -d
```

Change `SENTINEL_BACKEND_URL` in `docker-compose.yml` to point at your PHP app. Dashboard at `/__sentinel/dashboard`, protected by API key auth (key prints to container logs on first start).

Works with any PHP application: WordPress, Laravel, Drupal, custom apps — anything served over HTTP. Stacks with Cloudflare, nginx, or any existing load balancer.

## Who This Is For

- Anyone running **EOL PHP** (5.6, 7.x, 8.0, 8.1) that will never get a php2shell patch
- Anyone who wants **defense-in-depth** on top of the patch
- Anyone who wants protection against **the next PHP parser zero-day**, not just this one

## Links

- **GitHub:** https://github.com/Taz1920/php-canarywall
- **License:** MIT

Built by Ryan TJ. Open source. Free forever.
