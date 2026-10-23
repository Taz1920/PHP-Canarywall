#!/usr/bin/env python3
"""
PHP Sentinel — Stress Test Suite

Sends crafted payloads that target the PHP SAPI parsing code paths
CVE-2026-109619 (session upload progress use-after-free) and related
multipart/header parsing bugs live in. Run against your local Sentinel
stack to verify it catches what it should and forwards what it shouldn't.

Usage:
    python stress_test.py [--target http://localhost:8080] [--workers 4]
"""

import argparse
import asyncio
import io
import os
import random
import string
import struct
import sys
import time
from dataclasses import dataclass
from typing import Optional

import aiohttp

# ── Payload generators ──────────────────────────────────────────────


def random_bytes(n: int) -> bytes:
    return os.urandom(n)


def random_string(n: int) -> str:
    return "".join(random.choices(string.ascii_letters + string.digits, k=n))


# ── 1. Multipart boundary attacks ──────────────────────────────────
# The multipart parser walks boundary strings byte-by-byte.  Malformed
# boundaries can confuse the state machine and trigger OOB reads/writes.

def payload_oversized_boundary() -> dict:
    """Boundary string far exceeding the RFC 2046 70-char limit."""
    boundary = "B" * 8000
    body = (
        f"--{boundary}\r\n"
        f"Content-Disposition: form-data; name=\"file\"; filename=\"test.txt\"\r\n"
        f"Content-Type: text/plain\r\n\r\n"
        f"AAAA\r\n"
        f"--{boundary}--\r\n"
    ).encode()
    return {
        "name": "oversized_boundary",
        "headers": {"Content-Type": f"multipart/form-data; boundary={boundary}"},
        "body": body,
    }


def payload_null_in_boundary() -> dict:
    """NULL bytes embedded in multipart body — parser confusion vector.
    (NULLs can't go in HTTP headers via aiohttp, so we put them in the body
    where the multipart parser will encounter them.)"""
    boundary = "NULLTEST"
    body = (
        f"--{boundary}\r\n"
        f"Content-Disposition: form-data; name=\"x\"\r\n\r\n"
    ).encode()
    body += b"before\x00after\x00more\x00nulls\x00everywhere"
    body += f"\r\n--{boundary}--\r\n".encode()
    return {
        "name": "null_in_body",
        "headers": {"Content-Type": f"multipart/form-data; boundary={boundary}"},
        "body": body,
    }


def payload_nested_multipart() -> dict:
    """Deeply nested multipart parts — stack exhaustion."""
    depth = 200
    inner_boundary = "inner"
    body = b""
    boundaries = []
    for i in range(depth):
        b = f"boundary-level-{i}"
        boundaries.append(b)
        body += f"--{b}\r\nContent-Type: multipart/mixed; boundary=boundary-level-{i+1}\r\n\r\n".encode()
    body += b"innermost data\r\n"
    for b in reversed(boundaries):
        body += f"--{b}--\r\n".encode()
    return {
        "name": "nested_multipart_200_deep",
        "headers": {"Content-Type": f"multipart/form-data; boundary={boundaries[0]}"},
        "body": body,
    }


def payload_boundary_in_content() -> dict:
    """Boundary string appears inside field content — parser off-by-one."""
    boundary = "TESTBOUNDARY"
    body = (
        f"--{boundary}\r\n"
        f"Content-Disposition: form-data; name=\"trap\"\r\n\r\n"
        f"--{boundary}\r\n"
        f"Content-Disposition: form-data; name=\"injected\"\r\n\r\n"
        f"INJECTED_VALUE\r\n"
        f"--{boundary}--\r\n"
    ).encode()
    return {
        "name": "boundary_in_content",
        "headers": {"Content-Type": f"multipart/form-data; boundary={boundary}"},
        "body": body,
    }


def payload_incomplete_multipart() -> dict:
    """Multipart body that never closes — parser reads past buffer."""
    boundary = "OPEN_ENDED"
    body = (
        f"--{boundary}\r\n"
        f"Content-Disposition: form-data; name=\"file\"; filename=\"big.bin\"\r\n"
        f"Content-Type: application/octet-stream\r\n\r\n"
    ).encode()
    body += random_bytes(1024 * 512)  # 512KB of random data, no closing boundary
    return {
        "name": "incomplete_multipart_no_close",
        "headers": {"Content-Type": f"multipart/form-data; boundary={boundary}"},
        "body": body,
    }


def payload_many_tiny_parts() -> dict:
    """Thousands of tiny multipart parts — resource exhaustion."""
    boundary = "MANYPARTS"
    parts = []
    for i in range(5000):
        parts.append(
            f"--{boundary}\r\n"
            f"Content-Disposition: form-data; name=\"f{i}\"\r\n\r\n"
            f"v{i}\r\n"
        )
    body = ("".join(parts) + f"--{boundary}--\r\n").encode()
    return {
        "name": "5000_tiny_multipart_parts",
        "headers": {"Content-Type": f"multipart/form-data; boundary={boundary}"},
        "body": body,
    }


# ── 2. Session upload progress attacks ─────────────────────────────
# CVE-2026-109619 lives in the session upload progress handler.  It fires
# when a multipart POST includes both a session cookie and a field whose
# name matches session.upload_progress.name.  The UAF triggers during
# the cleanup/finalization of the upload progress data structure.

def payload_session_upload_progress_basic() -> dict:
    """Standard session upload progress trigger — the exact CVE vector."""
    boundary = "SESSUPLOAD"
    session_id = random_string(32)
    body = (
        f"--{boundary}\r\n"
        f"Content-Disposition: form-data; name=\"PHP_SESSION_UPLOAD_PROGRESS\"\r\n\r\n"
        f"trigger_upload_tracking\r\n"
        f"--{boundary}\r\n"
        f"Content-Disposition: form-data; name=\"file\"; filename=\"payload.bin\"\r\n"
        f"Content-Type: application/octet-stream\r\n\r\n"
    ).encode()
    body += random_bytes(1024 * 64)  # 64KB file body
    body += f"\r\n--{boundary}--\r\n".encode()
    return {
        "name": "session_upload_progress_basic",
        "headers": {
            "Content-Type": f"multipart/form-data; boundary={boundary}",
            "Cookie": f"PHPSESSID={session_id}; PHP_SESSION_UPLOAD_PROGRESS=1",
        },
        "body": body,
    }


def payload_session_upload_progress_malformed() -> dict:
    """Session upload progress with corrupted multipart after the trigger field."""
    boundary = "SESSCORRUPT"
    session_id = random_string(32)
    body = (
        f"--{boundary}\r\n"
        f"Content-Disposition: form-data; name=\"PHP_SESSION_UPLOAD_PROGRESS\"\r\n\r\n"
        f"tracking\r\n"
        f"--{boundary}\r\n"
        f"Content-Disposition: form-data; name=\"file\"; filename=\"x.bin\"\r\n"
        f"Content-Type: application/octet-stream\r\n\r\n"
    ).encode()
    # Corrupted data after the upload trigger — truncated mid-part
    body += random_bytes(2048)
    # No closing boundary — force cleanup with dangling state
    return {
        "name": "session_upload_progress_malformed",
        "headers": {
            "Content-Type": f"multipart/form-data; boundary={boundary}",
            "Cookie": f"PHPSESSID={session_id}; PHP_SESSION_UPLOAD_PROGRESS=1",
        },
        "body": body,
    }


def payload_session_upload_concurrent_sessions() -> dict:
    """Multiple session IDs in one request — confused session state."""
    boundary = "MULTISESS"
    body = (
        f"--{boundary}\r\n"
        f"Content-Disposition: form-data; name=\"PHP_SESSION_UPLOAD_PROGRESS\"\r\n\r\n"
        f"x\r\n"
        f"--{boundary}\r\n"
        f"Content-Disposition: form-data; name=\"file\"; filename=\"f.bin\"\r\n"
        f"Content-Type: application/octet-stream\r\n\r\n"
        f"data\r\n"
        f"--{boundary}--\r\n"
    ).encode()
    cookies = "; ".join(
        f"PHPSESSID={random_string(32)}" for _ in range(10)
    )
    return {
        "name": "session_upload_many_session_ids",
        "headers": {
            "Content-Type": f"multipart/form-data; boundary={boundary}",
            "Cookie": f"{cookies}; PHP_SESSION_UPLOAD_PROGRESS=1",
        },
        "body": body,
    }


# ── 3. Header injection / overflow ─────────────────────────────────

def payload_header_overflow() -> dict:
    """Extremely long header values — buffer overflow vector."""
    return {
        "name": "header_overflow_64KB",
        "headers": {
            "Content-Type": "application/x-www-form-urlencoded",
            "X-Overflow": "A" * 65536,
            "Cookie": "session=" + "B" * 32768,
        },
        "body": b"x=1",
    }


def payload_header_crlf_injection() -> dict:
    """CRLF sequences in field names — header injection via multipart."""
    boundary = "CRLFTEST"
    body = (
        f"--{boundary}\r\n"
        f"Content-Disposition: form-data; name=\"legit\r\nX-Injected: evil\"\r\n\r\n"
        f"payload\r\n"
        f"--{boundary}--\r\n"
    ).encode("latin-1")
    return {
        "name": "crlf_injection_in_multipart",
        "headers": {"Content-Type": f"multipart/form-data; boundary={boundary}"},
        "body": body,
    }


def payload_many_headers() -> dict:
    """Thousands of headers — resource exhaustion in header parsing."""
    headers = {"Content-Type": "text/plain"}
    for i in range(500):
        headers[f"X-Fuzz-{i}"] = random_string(64)
    return {
        "name": "500_headers",
        "headers": headers,
        "body": b"test",
    }


# ── 4. POST body attacks ───────────────────────────────────────────

def payload_urlencoded_deep_nesting() -> dict:
    """Deeply nested array keys in urlencoded body — parser stack exhaustion."""
    key = "a" + "[b]" * 200
    body = f"{key}=pwned".encode()
    return {
        "name": "urlencoded_200_deep_nesting",
        "headers": {"Content-Type": "application/x-www-form-urlencoded"},
        "body": body,
    }


def payload_urlencoded_many_vars() -> dict:
    """More vars than max_input_vars — parser boundary behavior."""
    pairs = [f"v{i}={i}" for i in range(5000)]
    body = "&".join(pairs).encode()
    return {
        "name": "urlencoded_5000_vars",
        "headers": {"Content-Type": "application/x-www-form-urlencoded"},
        "body": body,
    }


def payload_raw_binary_as_form() -> dict:
    """Random binary data with a form Content-Type — confused parser."""
    return {
        "name": "raw_binary_as_urlencoded",
        "headers": {"Content-Type": "application/x-www-form-urlencoded"},
        "body": random_bytes(4096),
    }


def payload_empty_multipart_parts() -> dict:
    """Multipart with empty Content-Disposition and zero-length parts."""
    boundary = "EMPTYPARTS"
    body = (
        f"--{boundary}\r\n"
        f"Content-Disposition: \r\n\r\n"
        f"\r\n"
        f"--{boundary}\r\n"
        f"\r\n"
        f"\r\n"
        f"--{boundary}\r\n"
        f"Content-Disposition: form-data; name=\"\"; filename=\"\"\r\n"
        f"Content-Type: \r\n\r\n"
        f"\r\n"
        f"--{boundary}--\r\n"
    ).encode()
    return {
        "name": "empty_multipart_parts",
        "headers": {"Content-Type": f"multipart/form-data; boundary={boundary}"},
        "body": body,
    }


# ── 5. Rapid-fire / concurrency ────────────────────────────────────

def payload_clean_request() -> dict:
    """Normal GET — should always pass. Baseline for comparison."""
    return {
        "name": "clean_GET_baseline",
        "method": "GET",
        "headers": {},
        "body": b"",
    }


# ── Test runner ─────────────────────────────────────────────────────

ALL_PAYLOADS = [
    # Multipart
    payload_oversized_boundary,
    payload_null_in_boundary,
    payload_nested_multipart,
    payload_boundary_in_content,
    payload_incomplete_multipart,
    payload_many_tiny_parts,
    # Session upload progress (CVE vector)
    payload_session_upload_progress_basic,
    payload_session_upload_progress_malformed,
    payload_session_upload_concurrent_sessions,
    # Headers
    payload_header_overflow,
    payload_header_crlf_injection,
    payload_many_headers,
    # POST body
    payload_urlencoded_deep_nesting,
    payload_urlencoded_many_vars,
    payload_raw_binary_as_form,
    payload_empty_multipart_parts,
    # Baseline
    payload_clean_request,
]


@dataclass
class TestResult:
    name: str
    status: int
    blocked: bool
    response_time_ms: float
    error: Optional[str] = None


async def send_payload(
    session: aiohttp.ClientSession,
    target: str,
    payload_fn,
) -> TestResult:
    payload = payload_fn()
    name = payload["name"]
    method = payload.get("method", "POST")
    headers = payload.get("headers", {})
    body = payload.get("body", b"")
    path = f"/test-{name}"

    start = time.monotonic()
    try:
        async with session.request(
            method=method,
            url=target + path,
            headers=headers,
            data=body,
            allow_redirects=False,
            ssl=False,
            timeout=aiohttp.ClientTimeout(total=15),
        ) as resp:
            await resp.read()
            elapsed = (time.monotonic() - start) * 1000
            blocked = resp.status == 403
            return TestResult(
                name=name,
                status=resp.status,
                blocked=blocked,
                response_time_ms=round(elapsed, 1),
            )
    except Exception as exc:
        elapsed = (time.monotonic() - start) * 1000
        return TestResult(
            name=name,
            status=0,
            blocked=False,
            response_time_ms=round(elapsed, 1),
            error=f"{type(exc).__name__}: {exc}",
        )


async def run_flood(
    target: str,
    rps: int,
    duration: int,
    workers: int,
) -> list[TestResult]:
    """Rapid-fire random payloads for sustained load testing."""
    results = []
    stop_time = time.monotonic() + duration
    sem = asyncio.Semaphore(workers)

    async with aiohttp.ClientSession() as session:
        async def fire():
            async with sem:
                fn = random.choice(ALL_PAYLOADS)
                r = await send_payload(session, target, fn)
                results.append(r)

        tasks = []
        while time.monotonic() < stop_time:
            tasks.append(asyncio.create_task(fire()))
            await asyncio.sleep(1.0 / rps)

        await asyncio.gather(*tasks, return_exceptions=True)
    return results


async def run_suite(target: str, workers: int, flood_rps: int, flood_duration: int):
    print(f"\n{'='*70}")
    print(f"  PHP Sentinel Stress Test")
    print(f"  Target: {target}")
    print(f"{'='*70}\n")

    # Phase 1: Individual payload tests
    print("Phase 1: Individual payload tests\n")
    print(f"  {'Payload':<45} {'Status':>6} {'Blocked':>8} {'Time':>8}")
    print(f"  {'-'*45} {'-'*6} {'-'*8} {'-'*8}")

    async with aiohttp.ClientSession() as session:
        for payload_fn in ALL_PAYLOADS:
            result = await send_payload(session, target, payload_fn)
            status_str = str(result.status) if result.status else "ERR"
            blocked_str = "BLOCKED" if result.blocked else ("ERROR" if result.error else "PASS")
            time_str = f"{result.response_time_ms:.0f}ms"

            if result.blocked:
                marker = "[!]"
            elif result.error:
                marker = "[E]"
            else:
                marker = "[+]"

            print(f"  {marker} {result.name:<42} {status_str:>6} {blocked_str:>8} {time_str:>8}")
            if result.error:
                print(f"      Error: {result.error}")

    # Phase 2: Flood test
    if flood_duration > 0:
        print(f"\nPhase 2: Flood test ({flood_rps} req/s for {flood_duration}s, {workers} workers)\n")
        results = await run_flood(target, flood_rps, flood_duration, workers)

        total = len(results)
        blocked = sum(1 for r in results if r.blocked)
        errors = sum(1 for r in results if r.error)
        passed = total - blocked - errors
        avg_time = sum(r.response_time_ms for r in results) / total if total else 0

        print(f"  Total requests:  {total}")
        print(f"  Passed (2xx):    {passed}")
        print(f"  Blocked (403):   {blocked}")
        print(f"  Errors:          {errors}")
        print(f"  Avg latency:     {avg_time:.0f}ms")

        if errors > 0:
            error_types = {}
            for r in results:
                if r.error:
                    key = r.error.split(":")[0]
                    error_types[key] = error_types.get(key, 0) + 1
            print(f"  Error breakdown: {error_types}")

    # Final metrics from Sentinel
    admin_key = os.getenv("SENTINEL_ADMIN_KEY", "")
    print(f"\nSentinel metrics after test:")
    try:
        headers = {"X-Sentinel-Key": admin_key} if admin_key else {}
        async with aiohttp.ClientSession() as session:
            async with session.get(f"{target}/__sentinel/metrics", headers=headers, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                metrics = await resp.json()
                for k, v in metrics.items():
                    print(f"  {k}: {v}")
    except Exception as e:
        print(f"  Could not fetch metrics: {e}")

    print(f"\n{'='*70}")
    print(f"  Done")
    print(f"{'='*70}\n")


def main():
    parser = argparse.ArgumentParser(description="PHP Sentinel Stress Test")
    parser.add_argument("--target", default="http://localhost:8080", help="Sentinel URL")
    parser.add_argument("--workers", type=int, default=8, help="Concurrent workers for flood test")
    parser.add_argument("--flood-rps", type=int, default=50, help="Requests per second during flood")
    parser.add_argument("--flood-duration", type=int, default=10, help="Flood duration in seconds (0 to skip)")
    args = parser.parse_args()

    asyncio.run(run_suite(args.target, args.workers, args.flood_rps, args.flood_duration))


if __name__ == "__main__":
    main()
