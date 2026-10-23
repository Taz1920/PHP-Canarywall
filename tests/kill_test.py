#!/usr/bin/env python3
"""
PHP Sentinel — Kill Test

Actually tries to crash canary workers through multiple attack vectors,
then verifies the proxy blocked every one. Run against your local stack.

Usage:
    python kill_test.py [--target http://localhost:8080]
"""

import asyncio
import os
import random
import string
import sys
import time

import aiohttp


TARGET = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8080"
ADMIN_KEY = os.getenv("SENTINEL_ADMIN_KEY", "")

PASS = "PASS"
FAIL = "FAIL"
BLOCKED = "BLOCKED"


def rand(n):
    return "".join(random.choices(string.ascii_letters, k=n))


async def send(session, name, method="POST", path="/", headers=None, body=b"", expect_block=True):
    headers = headers or {}
    start = time.monotonic()
    try:
        async with session.request(
            method=method,
            url=TARGET + path,
            headers=headers,
            data=body,
            allow_redirects=False,
            ssl=False,
            timeout=aiohttp.ClientTimeout(total=15),
        ) as resp:
            status = resp.status
            try:
                await resp.read()
            except aiohttp.ClientPayloadError:
                pass  # Streaming response didn't close cleanly — status is still valid
            elapsed = (time.monotonic() - start) * 1000
            blocked = status == 403

            if expect_block and blocked:
                result = BLOCKED
            elif not expect_block and not blocked:
                result = PASS
            else:
                result = FAIL

            print(f"  {result}  {name:<50} HTTP {status:>3}  {elapsed:>7.0f}ms")
            return blocked
    except Exception as exc:
        elapsed = (time.monotonic() - start) * 1000
        print(f"  {FAIL}  {name:<50} ERR: {type(exc).__name__}  {elapsed:>7.0f}ms")
        return False


async def main():
    print(f"\n{'='*75}")
    print(f"  PHP Sentinel Kill Test — {TARGET}")
    print(f"{'='*75}\n")

    async with aiohttp.ClientSession() as s:

        # ── Baseline ──
        print("  --- Baseline (should pass through) ---\n")
        await send(s, "Clean GET", method="GET", path="/", expect_block=False)
        await send(s, "Clean POST", path="/", headers={"Content-Type": "text/plain"}, body=b"hello", expect_block=False)
        print()

        # ── Simulated kills (X-Sentinel-Test header) ──
        print("  --- Simulated kills (test header) ---\n")
        await send(s, "SIGKILL worker", path="/kill", headers={"X-Sentinel-Test": "crash"})
        await send(s, "Timeout (hung worker)", path="/hang", headers={"X-Sentinel-Test": "timeout"})
        await send(s, "OOM (memory bomb)", path="/oom", headers={"X-Sentinel-Test": "oom"})
        print()

        # ── Real attack payloads ──
        print("  --- Real attack payloads (no test header) ---\n")

        # 1. Session upload progress with malformed multipart — the CVE vector
        boundary = "EXPLOIT"
        sid = rand(32)
        body = (
            f"--{boundary}\r\n"
            f"Content-Disposition: form-data; name=\"PHP_SESSION_UPLOAD_PROGRESS\"\r\n\r\n"
            f"pwn\r\n"
            f"--{boundary}\r\n"
            f"Content-Disposition: form-data; name=\"file\"; filename=\"x.bin\"\r\n"
            f"Content-Type: application/octet-stream\r\n\r\n"
        ).encode()
        body += os.urandom(1024 * 512)  # 512KB random — no closing boundary
        await send(s, "CVE vector: session upload + truncated multipart",
                   path="/upload",
                   headers={
                       "Content-Type": f"multipart/form-data; boundary={boundary}",
                       "Cookie": f"PHPSESSID={sid}; PHP_SESSION_UPLOAD_PROGRESS=1",
                   },
                   body=body,
                   expect_block=True)  # Blocked by upload_progress filter before canaries

        # 2. Massive body — try to OOM canary workers via php://input read
        #    Canary reads file_get_contents('php://input'). memory_limit=16M.
        #    Send 20MB body → PHP fatal error E_ERROR → 500 → blocked
        print()
        print("  --- Memory pressure attacks ---\n")
        fat_body = os.urandom(20 * 1024 * 1024)  # 20MB
        await send(s, "20MB body -> php://input OOM (500->block)",
                   path="/fat",
                   headers={"Content-Type": "application/octet-stream"},
                   body=fat_body,
                   expect_block=True)

        # 3. Concurrent fat bodies — overwhelm multiple workers
        print()
        print("  --- Concurrent worker kills (4x 15MB simultaneous) ---\n")
        tasks = []
        for i in range(4):
            body = os.urandom(15 * 1024 * 1024)
            tasks.append(send(s, f"  Worker kill #{i+1} (15MB body)",
                             path=f"/concurrent-{i}",
                             headers={"Content-Type": "application/octet-stream"},
                             body=body,
                             expect_block=True))
        results = await asyncio.gather(*tasks)
        killed = sum(1 for r in results if r)
        print(f"\n  Concurrent kills: {killed}/4 blocked")

        # 4. Many small requests with session upload progress — exhaust workers
        print()
        print("  --- Rapid session upload progress spam (20 requests) ---\n")
        tasks = []
        for i in range(20):
            boundary = f"RAPID{i}"
            sid = rand(32)
            file_data = os.urandom(17 * 1024 * 1024)  # 17MB > 16MB memory_limit
            body = (
                f"--{boundary}\r\n"
                f"Content-Disposition: form-data; name=\"PHP_SESSION_UPLOAD_PROGRESS\"\r\n\r\n"
                f"spam{i}\r\n"
                f"--{boundary}\r\n"
                f"Content-Disposition: form-data; name=\"f\"; filename=\"f{i}.bin\"\r\n"
                f"Content-Type: application/octet-stream\r\n\r\n"
            ).encode()
            body += file_data
            body += f"\r\n--{boundary}--\r\n".encode()
            tasks.append(send(s, f"  Session upload spam #{i+1:02d}",
                             path=f"/spam-{i}",
                             headers={
                                 "Content-Type": f"multipart/form-data; boundary={boundary}",
                                 "Cookie": f"PHPSESSID={sid}; PHP_SESSION_UPLOAD_PROGRESS=1",
                             },
                             body=body,
                             expect_block=True))
        results = await asyncio.gather(*tasks)
        killed = sum(1 for r in results if r)
        print(f"\n  Session spam kills: {killed}/20 blocked")

    # Final metrics
    print(f"\n  --- Final Sentinel Metrics ---\n")
    headers = {"X-Sentinel-Key": ADMIN_KEY} if ADMIN_KEY else {}
    async with aiohttp.ClientSession() as s:
        async with s.get(f"{TARGET}/__sentinel/metrics", headers=headers, timeout=aiohttp.ClientTimeout(total=5)) as resp:
            import json
            metrics = await resp.json()
            print(f"  Total requests:   {metrics['total_requests']}")
            print(f"  Forwarded:        {metrics['forwarded']}")
            print(f"  Blocked:          {metrics['blocked']}")
            print(f"  Canary errors:    {metrics['canary_errors']}")
            print(f"  Canary timeouts:  {metrics['canary_timeouts']}")
            print(f"  Block rate:       {metrics['block_rate_pct']}%")
            print(f"\n  Per-canary breakdown:")
            for name, stats in metrics['canaries'].items():
                print(f"    {name}: errors={stats['errors']} timeouts={stats['timeouts']} crashes={stats['crashes']}")

    print(f"\n{'='*75}")
    print(f"  Done")
    print(f"{'='*75}\n")


if __name__ == "__main__":
    asyncio.run(main())
