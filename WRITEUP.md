# PHP Sentinel: Blocking php2shell Without Patching PHP

## The Problem

On October 21, 2026, two critical RCE vulnerabilities were disclosed in PHP — **CVE-2026-109618** and **CVE-2026-109619**, collectively known as **php2shell**. CVSS 9.2. Every PHP version from 5.4 through 8.5.11 is affected.

Patches exist for PHP 8.2.35, 8.3.36, 8.4.27, and 8.5.12. But PHP 8.1 and earlier? End of life. **No patch is coming.** That's roughly 40% of all PHP websites — millions of servers that are permanently vulnerable.

The standard mitigation is to disable `session.upload_progress.enabled`, but that only covers one of the two attack paths. The OOM corruption vector in CVE-2026-109618 has no PHP config-level fix.

## The Solution

**PHP Sentinel** is a reverse proxy that sits in front of your PHP application and replays every HTTP request through an array of 11 isolated "canary" PHP-FPM instances (PHP 5.6 through 8.4) running in parallel. If **any** canary worker crashes, OOMs, or hangs — the request is blocked before production ever sees it.

```
Client Request
       |
       v
   Sentinel Proxy (Python/aiohttp)
       |
       Fan out to ALL canaries in parallel
       |
  [PHP 8.4] [PHP 8.3] [PHP 8.2] ... [PHP 7.0] [PHP 5.6]
       |
       ALL survived? --> Forward to production
       ANY died?     --> Block (403)
```

No signatures. No pattern matching. No rule updates. The PHP parser itself is the detector.

## Why It Works

PHP parser exploits — use-after-free, OOM corruption, boundary parsing crashes — all trigger during request parsing in the SAPI layer. The canary instances run in complete isolation: no database, no secrets, no network egress. Their only job is to parse the request. If parsing kills the worker, the request is malicious.

This catches:
- **Known exploits** like php2shell (both CVEs)
- **Unknown future exploits** targeting the PHP parser — zero-days get caught on day zero
- **Version-specific bugs** — an exploit targeting PHP 7.4's parser but not 8.4's still gets caught because 7.4 is in the canary array

## Test Results

### Kill Test Suite (28/28 blocked)

Built-in test suite covering multiple attack vectors:

```
PASS     Clean GET                                    HTTP 200
PASS     Clean POST                                   HTTP 200
BLOCKED  SIGKILL worker                               HTTP 403
BLOCKED  Timeout (hung worker)                        HTTP 403
BLOCKED  OOM (memory bomb)                            HTTP 403
BLOCKED  20MB body -> php://input OOM                 HTTP 403
BLOCKED  4x concurrent 15MB worker kills              HTTP 403 (4/4)
BLOCKED  20x session upload progress spam             HTTP 403 (20/20)

Per-canary breakdown:
  canary-84: errors=28  canary-83: errors=28  canary-82: errors=28
  canary-81: errors=28  canary-80: errors=28  canary-74: errors=28
  canary-73: errors=28  canary-72: errors=28  canary-71: errors=28
  canary-70: errors=28  canary-56: errors=28
```

308 total canary errors = 28 attacks x 11 PHP versions. Every attack caught across every version.

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

Sentinel uses **behavioral detection**. It doesn't look at what the request contains — it observes what the request *does* to a PHP parser. If the parser dies, the request is bad. This is fundamentally unforgeable: you can't craft a request that crashes PHP but somehow doesn't crash PHP.

Sentinel and WAFs complement each other. Use both.

## Deployment

Three commands:

```bash
git clone https://github.com/Taz1920/php-sentinel.git
cd php-sentinel
docker compose build && docker compose up -d
```

Change `SENTINEL_BACKEND_URL` in `docker-compose.yml` to point at your PHP app. Dashboard at `/__sentinel/dashboard`, protected by API key auth (key prints to container logs on first start).

Works with any PHP application: WordPress, Laravel, Drupal, custom apps — anything served over HTTP. Stacks with Cloudflare, nginx, or any existing load balancer.

## Who This Is For

- Anyone running **EOL PHP** (5.6, 7.x, 8.0, 8.1) that will never get a php2shell patch
- Anyone who wants **defense-in-depth** on top of the patch
- Anyone who wants protection against **the next PHP parser zero-day**, not just this one

## Links

- **GitHub:** https://github.com/Taz1920/php-sentinel
- **License:** MIT

Built by Ryan TJ. Open source. Free forever.
