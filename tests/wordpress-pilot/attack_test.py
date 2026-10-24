"""Attack simulation — verify Sentinel blocks exploit payloads in enforce mode.

Tests CVE-2026-109618 (upload progress OOM injection) via the upload-progress
filter, and generic canary-kill payloads via the canary OOM tripwire.

Note: CVE-2026-109619 (stale global UAF) requires a multi-stage RCE chain
that is tested separately by the stress_test.py cozybear harness.  The canary
OOM tests here confirm the fail-closed mechanism works but are not specific
109619 reproductions.

Usage:
    python attack_test.py [base_url]

Default base_url is http://localhost:8080.
"""
import requests
import json
import sys

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8080"
results = {"blocked": 0, "passed": 0, "errors": 0}

def attack(desc, method, path, expect_block=True, **kwargs):
    url = f"{BASE}{path}"
    try:
        r = requests.request(method, url, timeout=30, allow_redirects=False, **kwargs)
        if r.status_code == 403:
            tag = "BLOCKED" if expect_block else "FALSE POS"
            results["blocked"] += 1
        elif r.status_code < 400:
            tag = "PASSED" if not expect_block else "!! MISSED"
            results["passed"] += 1
        else:
            tag = f"HTTP {r.status_code}"
            results["passed"] += 1
        print(f"  [{tag:>10s}]  {desc}  ->  {r.status_code}")
    except Exception as e:
        results["errors"] += 1
        print(f"  [   ERROR ]  {desc}  ->  {e}")

print("=" * 70)
print(f"ATTACK SIMULATION — Enforce Mode — {BASE}")
print("=" * 70)

# ── CVE-2026-109618: Upload progress session injection ──
# The attack uses PHP_SESSION_UPLOAD_PROGRESS in a multipart POST
# to trigger OOM corruption in the session upload progress parser.
# Sentinel's upload-progress filter blocks these before they reach the backend.
print("\n--- CVE-2026-109618: Upload Progress OOM Injection ---")

attack(
    "Upload progress cookie + matching field name",
    "POST", "/",
    headers={"Cookie": "PHPSESSID=attacker_session_1"},
    files={"PHP_SESSION_UPLOAD_PROGRESS": (None, "exploit_payload_1")},
)

attack(
    "Upload progress with 1MB payload",
    "POST", "/",
    headers={"Cookie": "PHPSESSID=attacker_session_2"},
    files={"PHP_SESSION_UPLOAD_PROGRESS": (None, "A" * 1_000_000)},
)

attack(
    "Upload progress + file upload combo",
    "POST", "/wp-admin/async-upload.php",
    headers={"Cookie": "PHPSESSID=attacker_session_3"},
    files={
        "PHP_SESSION_UPLOAD_PROGRESS": (None, "trigger_oom"),
        "file": ("evil.php", b"<?php system($_GET['cmd']); ?>", "application/octet-stream"),
    },
)

attack(
    "Upload progress on wp-login.php",
    "POST", "/wp-login.php",
    headers={"Cookie": "PHPSESSID=attacker_session_4"},
    files={"PHP_SESSION_UPLOAD_PROGRESS": (None, "login_exploit")},
)

attack(
    "Upload progress via xmlrpc.php",
    "POST", "/xmlrpc.php",
    headers={"Cookie": "PHPSESSID=attacker_session_5"},
    files={"PHP_SESSION_UPLOAD_PROGRESS": (None, "xmlrpc_exploit")},
)

attack(
    "Multiple upload progress fields",
    "POST", "/",
    headers={"Cookie": "PHPSESSID=attacker_session_6"},
    files=[
        ("PHP_SESSION_UPLOAD_PROGRESS", (None, "payload_a")),
        ("PHP_SESSION_UPLOAD_PROGRESS", (None, "payload_b")),
        ("file", ("test.txt", b"normal file", "text/plain")),
    ],
)

# ── Canary OOM tripwire ──
# These test the fail-closed mechanism: a large body that OOMs a canary
# triggers a block even though it isn't a specific CVE-2026-109619 chain.
# The real 109619 RCE sequence is tested by stress_test.py (cozybear harness).
print("\n--- Canary OOM tripwire (fail-closed) ---")

attack(
    "10MB body triggers canary OOM -> fail-closed block",
    "POST", "/",
    headers={"Cookie": "PHPSESSID=kill_canary_1", "Content-Type": "application/octet-stream"},
    data=b"X" * 10_000_000,
)

attack(
    "Upload progress + 5MB body (combined vector)",
    "POST", "/",
    headers={"Cookie": "PHPSESSID=combined_attack_1"},
    files={
        "PHP_SESSION_UPLOAD_PROGRESS": (None, "combined_exploit"),
        "bigfile": ("payload.bin", b"Y" * 5_000_000, "application/octet-stream"),
    },
)

# ── Control: Legitimate traffic should NOT be blocked ──
print("\n--- Control: Legitimate traffic (should pass) ---")

attack(
    "Normal GET homepage",
    "GET", "/",
    expect_block=False,
)

attack(
    "Normal POST login",
    "POST", "/wp-login.php",
    expect_block=False,
    data={"log": "admin", "pwd": "admin", "wp-submit": "Log In"},
)

attack(
    "Normal file upload (no upload progress field)",
    "POST", "/wp-admin/async-upload.php",
    expect_block=False,
    files={"async-upload": ("photo.jpg", b"\xff\xd8\xff\xe0" + b"\x00" * 1000, "image/jpeg")},
    data={"action": "upload-attachment"},
)

attack(
    "Normal multipart form (no upload progress field)",
    "POST", "/",
    expect_block=False,
    files={"name": (None, "John"), "email": (None, "john@example.com")},
)

attack(
    "Normal large POST body (no session cookie)",
    "POST", "/",
    expect_block=False,
    headers={"Content-Type": "application/octet-stream"},
    data=b"Z" * 1_000_000,
)

# ── Summary ──
print("\n" + "=" * 70)
print(f"RESULTS:  {results['blocked']} BLOCKED  |  {results['passed']} PASSED  |  {results['errors']} ERRORS")
print("=" * 70)

expected_blocks = 8
expected_passes = 5
ok = True
if results["blocked"] != expected_blocks:
    print(f"\n!! Expected {expected_blocks} blocks, got {results['blocked']}")
    ok = False
if results["passed"] < expected_passes:
    print(f"\n!! Expected at least {expected_passes} passes, got {results['passed']}")
    ok = False
if ok:
    print(f"\nAll {expected_blocks} attack payloads blocked, "
          f"all {results['passed']} legitimate requests passed.")

sys.exit(0 if ok else 1)
