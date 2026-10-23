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

Tested against four independent public PoC exploit tools:

| PoC | Attack Type | Result |
|-----|-------------|--------|
| eness/php2shell-PoC | Full 3-stage heap exploit chain | Blocked (HEAP_LEAK_FAILED — stage 1 reconnaissance killed) |
| murrez/php2shell | CVE-2026-109618 UAF trigger | Neutered (could not arm exploit) |
| ikow/php2shell-poc | 4-tier scanner + active OOM probe | Blocked |
| ikow/php2shell-poc | OOM header bomb (5000 headers) | Blocked (403) |
| ikow/php2shell-poc | Session filename injection | Blocked (upload-progress filter) |

## What These Tests Cover

- **Upload-progress filter:** Deterministic blocking of `PHP_SESSION_UPLOAD_PROGRESS` multipart payloads (CVE-2026-109618 attack surface)
- **Canary crash detection:** Worker SIGKILL, OOM, and timeout detection across all 11 PHP versions
- **Memory pressure:** Bodies exceeding canary `memory_limit=16M` trigger OOM and block
- **Concurrency:** Multiple simultaneous attacks don't bypass the canary array
- **False positives:** Clean GET/POST requests, edge-case multipart bodies, and malformed-but-benign payloads all pass through

## What These Tests Do NOT Cover

- Exploits that succeed without crashing the PHP worker (silent RCE)
- Multi-request heap grooming (CVE-2026-109619 cross-request state corruption)
- False positive rate under production traffic patterns
- Latency under sustained production load
- Custom `session.upload_progress.name` bypass of the filter

## Running the Tests

```bash
# Kill test (requires SENTINEL_TEST_MODE=1 in canary environment)
SENTINEL_ADMIN_KEY=<your-key> python tests/kill_test.py

# Stress test
python tests/stress_test.py

# Stress test with longer flood
python tests/stress_test.py --flood-duration 30
```
