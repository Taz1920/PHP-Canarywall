# PHP Sentinel — Test Results

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

**CVE-2026-109619 finding:** The cozybear exploit (the only public working RCE for CVE-2026-109619) sends `PHP_SESSION_UPLOAD_PROGRESS` in every request — the shared attack surface for both CVEs. With the filter ON, all requests are blocked before reaching canaries. With the filter OFF, the exploit's 12MB OOM payload crashes all 11 canary FPM workers (502), and Sentinel blocks the request. The exploit also requires `display_errors=On`, single Apache prefork worker, and mod_php — all conditions Sentinel's FPM-based canary architecture defeats. No code execution was achieved under either configuration.

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

- **Upload-progress filter:** Deterministic blocking of `PHP_SESSION_UPLOAD_PROGRESS` multipart payloads (CVE-2026-109618/109619 shared attack surface)
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
```
