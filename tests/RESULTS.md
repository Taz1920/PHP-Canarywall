# PHP CanaryWall — Test Results

**Date:** 2026-10-23
**Version:** v0.3.0 (post-hardening)
**Environment:** Docker Compose, 11 canaries (PHP 5.6–8.4), default configuration

## Kill Test Suite

Tests simulated worker crashes, memory pressure attacks, and CVE exploit vectors.

```
  --- Baseline (should pass through) ---

  PASS  Clean GET                                          HTTP 200       16ms
  PASS  Clean POST                                         HTTP 200       15ms

  --- Simulated kills (requires SENTINEL_TEST_MODE=1) ---

  BLOCKED  SIGKILL worker                                     HTTP 403
  BLOCKED  Timeout (hung worker)                              HTTP 403   3641ms
  BLOCKED  OOM (memory bomb)                                  HTTP 403

  --- Real attack payloads ---

  BLOCKED  CVE vector: session upload + truncated multipart   HTTP 403
           (caught by upload-progress filter before canaries)

  --- Memory pressure attacks ---

  BLOCKED  20MB body -> php://input OOM (500->block)          HTTP 403    266ms

  --- Concurrent worker kills (4x 15MB simultaneous) ---

  BLOCKED  4/4 blocked                                        HTTP 403

  --- Rapid session upload progress spam (20 requests) ---

  BLOCKED  20/20 blocked                                      HTTP 403
```

**Result:** All attack vectors blocked. Clean requests forwarded.

### Per-Canary Breakdown

All 11 canaries reported identical error counts (24 errors each, 264 total = 24 attacks x 11 versions).

| Canary | PHP | Errors | Timeouts | Crashes |
|--------|-----|--------|----------|---------|
| canary-84 | 8.4 | 24 | 0 | 0 |
| canary-83 | 8.3 | 24 | 0 | 0 |
| canary-82 | 8.2 | 24 | 0 | 0 |
| canary-81 | 8.1 | 24 | 0 | 0 |
| canary-80 | 8.0 | 24 | 0 | 0 |
| canary-74 | 7.4 | 24 | 0 | 0 |
| canary-73 | 7.3 | 24 | 0 | 0 |
| canary-72 | 7.2 | 24 | 0 | 0 |
| canary-71 | 7.1 | 24 | 0 | 0 |
| canary-70 | 7.0 | 24 | 0 | 0 |
| canary-56 | 5.6 | 24 | 0 | 0 |

## Stress Test Suite

17 crafted payloads testing multipart parsing edge cases, header limits, and upload-progress blocking.

```
  Payload                                       Status  Blocked     Time
  --------------------------------------------- ------ -------- --------
  [+] oversized_boundary                            404     PASS     31ms
  [+] null_in_body                                  404     PASS      0ms
  [+] nested_multipart_200_deep                     404     PASS     62ms
  [+] boundary_in_content                           404     PASS     16ms
  [+] incomplete_multipart_no_close                 404     PASS     47ms
  [+] 5000_tiny_multipart_parts                     404     PASS     78ms
  [!] session_upload_progress_basic                 403  BLOCKED     31ms
  [!] session_upload_progress_malformed             403  BLOCKED      0ms
  [!] session_upload_many_session_ids               403  BLOCKED      0ms
  [+] header_overflow_64KB                          400     PASS     16ms
  [+] crlf_injection_in_multipart                   404     PASS      0ms
  [+] 500_headers                                   400     PASS      0ms
  [+] urlencoded_200_deep_nesting                   404     PASS      0ms
  [+] urlencoded_5000_vars                          404     PASS     62ms
  [+] raw_binary_as_urlencoded                      404     PASS     16ms
  [+] empty_multipart_parts                         404     PASS      0ms
  [+] clean_GET_baseline                            404     PASS     16ms
```

**[+] PASS** = request forwarded to backend (not an attack)
**[!] BLOCKED** = request blocked by Sentinel (attack vector detected)

### Flood Test

50 requests/second sustained for 10 seconds, 8 concurrent workers.

| Metric | Value |
|--------|-------|
| Total requests | 404 |
| Passed (2xx) | 342 |
| Blocked (403) | 62 |
| Errors | 0 |
| Avg latency | 16ms |

## Public PoC Exploit Results

Tested against four independent public PoC exploit tools. Two test configurations: with the upload-progress filter enabled (default), and with the filter disabled to verify canary-only detection.

### With upload-progress filter ON (default)

| PoC | Attack Type | Result |
|-----|-------------|--------|
| eness/php2shell-PoC | Full 3-stage heap exploit chain | Blocked (HEAP_LEAK_FAILED — stage 1 reconnaissance killed) |
| murrez/php2shell | CVE-2026-109618 UAF trigger | Neutered (could not arm exploit) |
| ikow/php2shell-poc | 4-tier scanner + active OOM probe | Blocked |
| ikow/php2shell-poc | OOM header bomb (5000 headers) | Blocked (403) |
| ikow/php2shell-poc | Session filename injection | Blocked (upload-progress filter) |
| **cozybear/cve-2026-109619** | **CVE-2026-109619 stale session global state → RCE (3-stage: heap leak, libphp leak, forged HashTable)** | **Blocked (upload-progress filter) — all 6 requests blocked before reaching canaries** |

### With upload-progress filter OFF (canary-only detection)

Upload-progress filter disabled to verify the canary array catches real exploit payloads independently.

| PoC | Attack Type | Canary Result | Outcome |
|-----|-------------|---------------|---------|
| eness/php2shell-PoC | 3-stage heap exploit (stage 1 heap leak) | **502 across all 11 canaries** — FPM workers crashed | Blocked. Exploit failed at stage 1: Sentinel returned 403 instead of leaked heap addresses. |
| eness/php2shell-PoC | Stage 1 repeated attempts (3 rounds) | **502 on every attempt, all versions** | Blocked. Every stage 1 payload killed every canary. HEAP_LEAK_FAILED. |
| ikow/php2shell-poc | OOM header bomb (5000 headers x 500 bytes) | **502 on canary-81, canary-80, canary-74, canary-73** | Blocked (403). |
| ikow/php2shell-poc | Session LFI chain (chain_a) | Session plant: 200 (clean request). LFI read: 404 (no LFI path). | Not blocked — session plant is a clean request. Exploit failed (no LFI endpoint). |
| ikow/php2shell-poc | Handler mismatch RCE (chain_c) | Pollution: 200. Gadget injection: 200. Trigger: 404. | Not blocked — requests are individually clean. Exploit failed (no matching endpoints). |
| murrez/php2shell | UAF fingerprint + exploit | Fingerprint: 200 (identified PHP 8.1.34). Exploit: WEAK-SIGNAL. | Not blocked — fingerprint is a clean request. Exploit could not confirm UAF. |
| **cozybear/cve-2026-109619** | **CVE-2026-109619 stale session state → RCE (rotate + 3-stage heap exploit)** | **502 across all 11 canaries** — OOM payload crashed every FPM worker | **Blocked (403).** Exploit failed at stage 1: heap leak failed. Canaries crashed from the 12MB OOM-triggering upload-progress payload. |

**Key finding:** The eness PoC's stage 1 heap leak payloads caused **real PHP-FPM worker crashes (HTTP 502)** across all 11 canary versions. These are actual parser-level crashes from real CVE exploit payloads, not simulated failures. The canary array detected and blocked them without the upload-progress filter.

**CVE-2026-109619 finding:** The cozybear exploit (the only public working RCE for CVE-2026-109619) sends `PHP_SESSION_UPLOAD_PROGRESS` in every request — the upload-progress attack surface used by all known public exploits for both CVEs. With the filter ON, all requests are blocked before reaching canaries. With the filter OFF, the exploit's 12MB OOM payload crashes all 11 canary FPM workers (502), and Sentinel blocks the request.

**Positive control (Test 0) — CONFIRMED:** The cozybear PoC achieves reliable RCE on the pinned `php:8.4.26-apache` image. Verified on both native Linux Docker and Docker Desktop (WSL2, x86_64).

Native Linux Docker output (stock exploit, unmodified):

```
[+] Zend MM chunk base = 0x7194f7c00000
[+] libphp base = 0x7194f98f0000
[+] executed on attempt 1
PROOF: uid=33(www-data) gid=33(www-data) groups=33(www-data)
RESULT: CONFIRMED
  PHP 8.4.26: code execution as the Apache worker
  PHP 8.4.27: no code execution (patched)
```

Vulnerable target logs (native Linux Docker):

```
vuln-1  | zend_mm_heap corrupted
vuln-1  | [core:notice] child pid 19 exit signal Abort (6)
vuln-1  | zend_mm_heap corrupted
vuln-1  | [core:notice] child pid 266 exit signal Abort (6)
vuln-1  | zend_mm_heap corrupted
vuln-1  | [core:notice] child pid 274 exit signal Abort (6)
vuln-1  | [core:notice] child pid 282 exit signal Segmentation fault (11)
```

Patched target logs (native Linux Docker): All requests return 200, no heap corruption, no crashes.

The exploit completes the full 3-stage chain (heap leak → libphp leak → forged HashTable → `zif_system`) and writes a proof file as `www-data`. The patched PHP 8.4.27 correctly rejects the exploit at stage 1 (heap leak fails). This confirms that Sentinel **stopped a working RCE**, not just blocked an untested attack vector.

**Note:** On WSL2, the exploit's `is_user_pointer()` filter needs its lower bound changed from `0x7F0000000000` to `0x400000000000` because WSL2's kernel maps the heap at lower addresses (0x7C range vs 0x7F on stock Linux). On native Linux Docker the stock exploit works unmodified.

**What we verified:**
- **Test 0 (positive control):** Full RCE without Sentinel — `id>/out/p` executed as www-data on PHP 8.4.26, proof file confirmed
- **Test 1 (filter ON):** All 6 cozybear requests blocked by upload-progress filter before reaching canaries — no RCE, no proof file
- **Test 2 (filter OFF):** All 11 canaries crashed (502) on every exploit request — Sentinel returned 403, no RCE, no proof file
- The stale-session bug fires: `zend_mm_heap corrupted` on every exploit attempt, Apache workers abort (SIGABRT)
- The Set-Cookie leak channel works: 4KB of heap data in the cookie, valid user-space pointers present
- Every cozybear request contains `PHP_SESSION_UPLOAD_PROGRESS` and is caught by both detection layers
- The exploit also requires `display_errors=On`, single Apache prefork worker, and mod_php — conditions Sentinel's FPM-based canary architecture does not provide

**Post-test verification:** Backend container inspected after all exploit runs. No `rce_proof.txt`, no injected code, no compromised processes. Empty session files (0 bytes) from exploit session rotation were cleaned up. All canaries clean — no session files or artifacts.

```
Proxy log excerpt (eness exploit, filter OFF):

CANARY FAIL [canary-84] status=502 POST /
CANARY FAIL [canary-83] status=502 POST /
...
CANARY FAIL [canary-56] status=502 POST /
BLOCKED POST / — killed: [canary-84, ..., canary-56]
```

```
Proxy log excerpt (cozybear CVE-2026-109619, filter ON):

BLOCKED 172.19.0.1 POST /index.php — PHP_SESSION_UPLOAD_PROGRESS in multipart body (CVE-2026-109618/109619 vector)
BLOCKED 172.19.0.1 POST /index.php — PHP_SESSION_UPLOAD_PROGRESS in multipart body (CVE-2026-109618/109619 vector)
BLOCKED 172.19.0.1 POST /index.php — PHP_SESSION_UPLOAD_PROGRESS in multipart body (CVE-2026-109618/109619 vector)
(6 requests total, all blocked at filter — none reached canaries)
```

```
Proxy log excerpt (cozybear CVE-2026-109619, filter OFF):

CANARY FAIL [canary-84] status=502 POST /index.php
CANARY FAIL [canary-83] status=502 POST /index.php
...
CANARY FAIL [canary-56] status=502 POST /index.php
BLOCKED POST /index.php — killed: [canary-84, ..., canary-56]
(3 rounds of requests, all 11 canaries crashed each round)
```

## What These Tests Cover

- **Upload-progress filter:** Deterministic blocking of `PHP_SESSION_UPLOAD_PROGRESS` multipart payloads (used by CVE-2026-109618 and all known public CVE-2026-109619 exploits; CVE-2026-109619 has other confirmed trigger paths not covered by this filter)
- **Canary crash detection:** Worker SIGKILL, OOM, and timeout detection across all 11 PHP versions
- **Memory pressure:** Bodies exceeding canary `memory_limit=16M` trigger OOM and block
- **Concurrency:** Multiple simultaneous attacks don't bypass the canary array
- **False positives:** Clean GET/POST requests, edge-case multipart bodies, and malformed-but-benign payloads all pass through

## What These Tests Do NOT Cover

- Exploits that succeed without crashing the PHP worker (silent RCE)
- CVE-2026-109619 cross-request state corruption without `PHP_SESSION_UPLOAD_PROGRESS` (no known exploit achieves this — the cozybear PoC, the only working 109619 RCE, requires upload progress in every request)
- False positive rate under production traffic patterns
- Latency under sustained production load
- Custom `session.upload_progress.name` values (now configurable via `SENTINEL_UPLOAD_PROGRESS_NAME` env var)

## Running the Tests

```bash
# Kill test (requires SENTINEL_TEST_MODE=1 in canary environment)
SENTINEL_ADMIN_KEY=<your-key> python tests/kill_test.py

# Stress test
python tests/stress_test.py

# Stress test with longer flood
python tests/stress_test.py --flood-duration 30

# WordPress false-positive pilot (requires WordPress stack running —
# see tests/wordpress-pilot/docker-compose.yml)
python tests/wordpress-pilot/crawl_wordpress.py

# Attack simulation (CVE-2026-109618 + canary OOM tripwire)
python tests/wordpress-pilot/attack_test.py
```

### Reproducing the cozybear/cve-2026-109619 PoC results

The cozybear exploit is the only public working RCE for CVE-2026-109619.
It sends `PHP_SESSION_UPLOAD_PROGRESS` in every request, so both the
upload-progress filter and the canary OOM tripwire can catch it independently.

**PoC version tested:** [`Taz1920/cve-2026-109619`](https://github.com/Taz1920/cve-2026-109619) commit `7a73bb5`

**Prerequisites:**
- Clone [`Taz1920/cve-2026-109619`](https://github.com/Taz1920/cve-2026-109619) and checkout `7a73bb5`
- **Native Linux Docker** (Docker Desktop/WSL2 changes the heap layout
  enough that the exploit's stage 1 heap leak fails — the bug triggers
  but the pointer spray doesn't land)
- Sentinel stack running (`docker compose up -d`)
- Python 3 with `requests` installed

**Test 0 — positive control (exploit WITHOUT Sentinel):**

This must succeed before Tests 1–2 mean anything. If the exploit can't
get RCE without Sentinel, blocking it proves nothing.

```bash
# Start the cozybear lab (vulnerable PHP 8.4.26 + patched 8.4.27)
cd /path/to/cozybear/cve-2026-109619
docker compose up --build --abort-on-container-exit --exit-code-from attacker

# Expected output (on native Linux Docker):
#   [+] Zend MM chunk base = 0x...
#   [+] libphp base = 0x...
#   [+] executed on attempt 1
#   PROOF: uid=33(www-data) gid=33(www-data) groups=33(www-data)
#   RESULT: CONFIRMED
#
# If this prints INCONCLUSIVE or heap leak failed, the exploit doesn't
# work in your environment and Tests 1–2 cannot validate Sentinel's
# protection against a working RCE.

# Verify the proof file exists
docker compose exec vuln cat /out/p
# Should print: uid=33(www-data) ...
```

**Test 1 — upload-progress filter ON (default):**

```bash
# Connect the cozybear vulnerable target to Sentinel's network
docker network connect php-canarywall_sentinel-net cve-2026-109619-vuln-1

# Point Sentinel at the vulnerable target
# Set SENTINEL_BACKEND_URL=http://cve-2026-109619-vuln-1:80 in .env
docker compose up -d sentinel   # recreate to pick up change

# Clear the block log and proof file
docker exec php-canarywall python3 -c "open('/var/log/sentinel/blocked.jsonl','w').close()"
docker compose -f /path/to/cozybear/compose.yaml exec vuln rm -f /out/p

# Run the exploit against Sentinel's public port
python3 attacker/exploit.py \
    -u http://localhost:8080/index.php \
    --proof /dev/null \
    --cmd 'id>/out/p'

# Expected: exploit fails — all requests return 403 or connection reset
# Check the block log:
docker exec php-canarywall cat /var/log/sentinel/blocked.jsonl
# Every entry should show "upload_progress_blocked"

# Verify no RCE proof
docker compose -f /path/to/cozybear/compose.yaml exec vuln cat /out/p
# Should fail: file does not exist
```

**Test 2 — upload-progress filter OFF (canary-only detection):**

```bash
# Disable the filter to test canary detection alone
# Set SENTINEL_BLOCK_UPLOAD_PROGRESS=false in .env
docker compose up -d sentinel   # recreate to pick up change

# Clear the block log and proof file
docker exec php-canarywall python3 -c "open('/var/log/sentinel/blocked.jsonl','w').close()"
docker compose -f /path/to/cozybear/compose.yaml exec vuln rm -f /out/p

# Run the exploit again
python3 attacker/exploit.py \
    -u http://localhost:8080/index.php \
    --proof /dev/null \
    --cmd 'id>/out/p'

# Expected: exploit fails — canaries crash (502), Sentinel returns 403
# The block log entries will show killed canaries instead of
# "upload_progress_blocked"

# Verify no RCE proof
docker compose -f /path/to/cozybear/compose.yaml exec vuln cat /out/p
# Should fail: file does not exist

# Re-enable the filter when done
# Set SENTINEL_BLOCK_UPLOAD_PROGRESS=true in .env
docker compose up -d sentinel
```

**Current status:** Test 0 CONFIRMED on native Linux Docker (stock
exploit, all 3 stages succeeded on attempt 1) and Docker Desktop
(WSL2, x86_64). The exploit achieves full RCE on PHP 8.4.26 (code
execution as www-data) and correctly fails on patched PHP 8.4.27.
Tests 1–2 confirmed that Sentinel blocks every cozybear request via
both detection layers, preventing RCE that is proven to work without
Sentinel.
