#!/usr/bin/env python3
"""
PHP Sentinel — Request Sanitization Proxy (Multi-Canary)

Replays every inbound HTTP request against MULTIPLE canary PHP instances
running different PHP versions in parallel.  If ANY canary's worker
segfaults, OOMs, or returns an error, the request is dropped before
production ever sees it.

Multi-version canary array means broader coverage: an exploit that
targets PHP 8.2's parser but not 8.4's still gets caught, and vice versa.
"""

import asyncio
import logging
import time
import os
import sys
import signal
import json
import secrets
import hmac
from dataclasses import dataclass, field
from typing import Optional

import aiohttp
from aiohttp import web

# ── Configuration ────────────────────────────────────────────────────

@dataclass
class SentinelConfig:
    canary_urls: list = field(default_factory=lambda: ["http://canary:9080"])
    backend_url: str = "http://backend:80"
    listen_port: int = 8080
    listen_host: str = "0.0.0.0"
    canary_timeout: float = 5.0
    max_replay_body: int = 32 * 1024 * 1024
    max_body_size: int = 100 * 1024 * 1024
    replay_methods: list = field(default_factory=lambda: [
        "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS",
    ])
    canary_fail_codes: list = field(default_factory=lambda: [500, 502, 503, 504])
    log_file: str = ""
    block_log: str = "/var/log/sentinel/blocked.jsonl"
    verbose: bool = False
    admin_key: str = ""
    block_upload_progress: bool = True
    upload_progress_name: str = "PHP_SESSION_UPLOAD_PROGRESS"
    webhook_url: str = ""
    admin_port: int = 0
    skip_canary_paths: list = field(default_factory=list)
    block_log_max_bytes: int = 50 * 1024 * 1024

    @classmethod
    def from_env(cls) -> "SentinelConfig":
        cfg = cls()
        urls_str = os.getenv("SENTINEL_CANARY_URLS", "")
        if urls_str:
            cfg.canary_urls = [u.strip().rstrip("/") for u in urls_str.split(",") if u.strip()]
        else:
            single = os.getenv("SENTINEL_CANARY_URL", "http://canary:9080").rstrip("/")
            cfg.canary_urls = [single]
        cfg.backend_url = os.getenv("SENTINEL_BACKEND_URL", cfg.backend_url).rstrip("/")
        cfg.listen_port = int(os.getenv("SENTINEL_PORT", cfg.listen_port))
        cfg.listen_host = os.getenv("SENTINEL_HOST", cfg.listen_host)
        cfg.canary_timeout = float(os.getenv("SENTINEL_CANARY_TIMEOUT", cfg.canary_timeout))
        cfg.max_replay_body = int(os.getenv("SENTINEL_MAX_REPLAY_BODY", cfg.max_replay_body))
        cfg.max_body_size = int(os.getenv("SENTINEL_MAX_BODY_SIZE", cfg.max_body_size))
        cfg.log_file = os.getenv("SENTINEL_LOG_FILE", cfg.log_file)
        cfg.block_log = os.getenv("SENTINEL_BLOCK_LOG", cfg.block_log)
        cfg.verbose = os.getenv("SENTINEL_VERBOSE", "").lower() in ("1", "true", "yes")
        cfg.block_upload_progress = os.getenv(
            "SENTINEL_BLOCK_UPLOAD_PROGRESS", "true"
        ).lower() not in ("0", "false", "no", "off")
        cfg.upload_progress_name = os.getenv(
            "SENTINEL_UPLOAD_PROGRESS_NAME", cfg.upload_progress_name
        )
        cfg.webhook_url = os.getenv("SENTINEL_WEBHOOK_URL", "")
        cfg.admin_port = int(os.getenv("SENTINEL_ADMIN_PORT", "0"))
        cfg.block_log_max_bytes = int(os.getenv("SENTINEL_BLOCK_LOG_MAX_BYTES", cfg.block_log_max_bytes))
        skip_paths = os.getenv("SENTINEL_SKIP_CANARY_PATHS", "")
        cfg.skip_canary_paths = [p.strip() for p in skip_paths.split(",") if p.strip()]
        cfg.admin_key = os.getenv("SENTINEL_ADMIN_KEY", "")
        if not cfg.admin_key:
            cfg.admin_key = secrets.token_urlsafe(32)
            cfg._admin_key_generated = True
        else:
            cfg._admin_key_generated = False
        return cfg


# ── Logging ──────────────────────────────────────────────────────────

def setup_logging(cfg: SentinelConfig) -> logging.Logger:
    logger = logging.getLogger("sentinel")
    logger.setLevel(logging.DEBUG if cfg.verbose else logging.INFO)
    fmt = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S%z",
    )
    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(fmt)
    logger.addHandler(sh)
    if cfg.log_file:
        fh = logging.FileHandler(cfg.log_file)
        fh.setFormatter(fmt)
        logger.addHandler(fh)
    return logger


# ── Metrics ──────────────────────────────────────────────────────────

class Metrics:
    def __init__(self, canary_names: list[str]):
        self.total_requests = 0
        self.forwarded = 0
        self.blocked = 0
        self.canary_errors = 0
        self.canary_timeouts = 0
        self.bypassed = 0
        self.start_time = time.time()
        self.per_canary = {name: {"errors": 0, "timeouts": 0, "crashes": 0} for name in canary_names}

    def to_dict(self) -> dict:
        uptime = time.time() - self.start_time
        return {
            "uptime_seconds": round(uptime, 1),
            "total_requests": self.total_requests,
            "forwarded": self.forwarded,
            "blocked": self.blocked,
            "canary_errors": self.canary_errors,
            "canary_timeouts": self.canary_timeouts,
            "bypassed": self.bypassed,
            "block_rate_pct": round(
                (self.blocked / self.total_requests * 100)
                if self.total_requests else 0, 2
            ),
            "canaries": self.per_canary,
        }


PHP_VERSION_MAP = {
    "canary-84": "8.4", "canary-83": "8.3", "canary-82": "8.2",
    "canary-81": "8.1", "canary-80": "8.0", "canary-74": "7.4",
    "canary-73": "7.3", "canary-72": "7.2", "canary-71": "7.1",
    "canary-70": "7.0", "canary-56": "5.6",
}

EOL_VERSIONS = {"8.1", "8.0", "7.4", "7.3", "7.2", "7.1", "7.0", "5.6"}


# ── Proxy Core ───────────────────────────────────────────────────────

class SentinelProxy:
    def __init__(self, cfg: SentinelConfig, logger: logging.Logger):
        self.cfg = cfg
        self.log = logger
        self.canary_names = [self._canary_label(u) for u in cfg.canary_urls]
        self.canary_url_map = dict(zip(self.canary_names, cfg.canary_urls))
        self.disabled_canaries: set[str] = set()
        self.metrics = Metrics(self.canary_names)
        self._canary_session: Optional[aiohttp.ClientSession] = None
        self._backend_session: Optional[aiohttp.ClientSession] = None

    @staticmethod
    def _canary_label(url: str) -> str:
        host = url.split("://")[-1].split("/")[0].split(":")[0]
        return host

    async def start(self):
        timeout = aiohttp.ClientTimeout(total=self.cfg.canary_timeout)
        self._canary_session = aiohttp.ClientSession(timeout=timeout)
        self._backend_session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=300)
        )
        block_dir = os.path.dirname(self.cfg.block_log)
        if block_dir:
            os.makedirs(block_dir, exist_ok=True)

    async def stop(self):
        if self._canary_session:
            await self._canary_session.close()
        if self._backend_session:
            await self._backend_session.close()

    async def _check_canary_health(self, name: str) -> str:
        url = self.canary_url_map.get(name)
        if not url:
            return "unknown"
        try:
            timeout = aiohttp.ClientTimeout(total=3)
            async with self._canary_session.request(
                "GET", url + "/__canary/health", timeout=timeout, ssl=False,
            ) as resp:
                return "healthy" if resp.status == 200 else "unhealthy"
        except Exception:
            return "unreachable"

    def _check_auth(self, request: web.Request) -> bool:
        key = request.headers.get("X-Sentinel-Key", "")
        if not key:
            return False
        return hmac.compare_digest(key, self.cfg.admin_key)

    @staticmethod
    def _unauthorized() -> web.Response:
        return web.json_response(
            {"error": "Unauthorized. Provide SENTINEL_ADMIN_KEY via X-Sentinel-Key header."},
            status=401,
        )

    async def _handle_admin(self, request: web.Request, path: str) -> web.Response:
        if not self._check_auth(request):
            return self._unauthorized()
        if path == "/__sentinel/admin/canaries" and request.method == "GET":
            canaries = []
            health_tasks = {name: self._check_canary_health(name) for name in self.canary_names}
            health_results = {}
            for name, coro in health_tasks.items():
                health_results[name] = await coro
            for name in self.canary_names:
                php_ver = PHP_VERSION_MAP.get(name, "?")
                canaries.append({
                    "name": name,
                    "php_version": php_ver,
                    "eol": php_ver in EOL_VERSIONS,
                    "enabled": name not in self.disabled_canaries,
                    "health": health_results.get(name, "unknown"),
                    "url": self.canary_url_map[name],
                    "metrics": self.metrics.per_canary.get(name, {}),
                })
            return web.json_response({"canaries": canaries})

        if path.startswith("/__sentinel/admin/canaries/") and request.method == "POST":
            parts = path.split("/")
            if len(parts) == 6:
                name = parts[4]
                action = parts[5]
                if name not in self.canary_url_map:
                    return web.json_response({"error": f"Unknown canary: {name}"}, status=404)
                if action == "enable":
                    self.disabled_canaries.discard(name)
                    self.log.info(f"ADMIN: Enabled canary [{name}]")
                    return web.json_response({"ok": True, "name": name, "enabled": True})
                elif action == "disable":
                    self.disabled_canaries.add(name)
                    self.log.info(f"ADMIN: Disabled canary [{name}]")
                    return web.json_response({"ok": True, "name": name, "enabled": False})

        if path == "/__sentinel/admin/canaries/bulk" and request.method == "POST":
            try:
                data = await request.json()
            except Exception:
                return web.json_response({"error": "Invalid JSON"}, status=400)
            enabled_list = data.get("enabled", [])
            self.disabled_canaries = {n for n in self.canary_names if n not in enabled_list}
            self.log.info(f"ADMIN: Bulk update — enabled={enabled_list}, disabled={list(self.disabled_canaries)}")
            return web.json_response({"ok": True, "enabled": enabled_list, "disabled": list(self.disabled_canaries)})

        if path == "/__sentinel/admin/config" and request.method == "GET":
            return web.json_response({
                "config": {
                    "canary_timeout": self.cfg.canary_timeout,
                    "max_replay_body": self.cfg.max_replay_body,
                    "max_replay_body_mb": round(self.cfg.max_replay_body / (1024 * 1024), 1) if self.cfg.max_replay_body else 0,
                    "max_body_size": self.cfg.max_body_size,
                    "max_body_size_mb": round(self.cfg.max_body_size / (1024 * 1024), 1) if self.cfg.max_body_size else 0,
                    "canary_fail_codes": self.cfg.canary_fail_codes,
                    "backend_url": self.cfg.backend_url,
                    "verbose": self.cfg.verbose,
                    "block_log": self.cfg.block_log,
                }
            })

        if path == "/__sentinel/admin/config" and request.method == "POST":
            try:
                data = await request.json()
            except Exception:
                return web.json_response({"error": "Invalid JSON"}, status=400)
            changed = []
            if "canary_timeout" in data:
                val = float(data["canary_timeout"])
                if val > 0:
                    self.cfg.canary_timeout = val
                    if self._canary_session:
                        await self._canary_session.close()
                    self._canary_session = aiohttp.ClientSession(
                        timeout=aiohttp.ClientTimeout(total=val)
                    )
                    changed.append(f"canary_timeout={val}")
            if "max_replay_body" in data:
                val = int(data["max_replay_body"])
                self.cfg.max_replay_body = max(0, val)
                changed.append(f"max_replay_body={val}")
            if "max_replay_body_mb" in data:
                mb = float(data["max_replay_body_mb"])
                self.cfg.max_replay_body = int(mb * 1024 * 1024)
                changed.append(f"max_replay_body={self.cfg.max_replay_body}")
            if "verbose" in data:
                self.cfg.verbose = bool(data["verbose"])
                self.log.setLevel(logging.DEBUG if self.cfg.verbose else logging.INFO)
                changed.append(f"verbose={self.cfg.verbose}")
            if "canary_fail_codes" in data:
                codes = [int(c) for c in data["canary_fail_codes"]]
                self.cfg.canary_fail_codes = codes
                changed.append(f"canary_fail_codes={codes}")
            self.log.info(f"ADMIN: Config updated — {', '.join(changed)}")
            return web.json_response({"ok": True, "changed": changed})

        return web.json_response({"error": "Not found"}, status=404)

    async def _serve_dashboard(self, request: web.Request) -> web.Response:
        dashboard_paths = [
            os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "dashboard", "index.html"),
            os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "dashboard", "index.html"),
            "/app/dashboard/index.html",
        ]
        for p in dashboard_paths:
            if os.path.isfile(p):
                with open(p, "r", encoding="utf-8") as f:
                    html = f.read()
                return web.Response(text=html, content_type="text/html")
        return web.Response(text="Dashboard not found. Place dashboard/index.html in the project root.", status=404)

    def _is_admin_path(self, path: str) -> bool:
        return (
            path.startswith("/__sentinel/admin/")
            or path in ("/__sentinel/dashboard", "/__sentinel/dashboard/")
            or path == "/__sentinel/metrics"
        )

    async def handle_admin(self, request: web.Request) -> web.StreamResponse:
        path = request.path_qs
        if path.startswith("/__sentinel/admin/"):
            return await self._handle_admin(request, path)
        if path in ("/__sentinel/dashboard", "/__sentinel/dashboard/"):
            return await self._serve_dashboard(request)
        if path == "/__sentinel/metrics":
            if not self._check_auth(request):
                return self._unauthorized()
            return web.json_response(self.metrics.to_dict())
        return web.json_response({"error": "Not found"}, status=404)

    async def handle(self, request: web.Request) -> web.StreamResponse:
        path = request.path_qs

        if self._is_admin_path(path):
            if self.cfg.admin_port:
                return web.json_response({"error": "Not found"}, status=404)
            return await self.handle_admin(request)

        if path == "/__sentinel/health":
            return web.json_response({"status": "ok"})

        self.metrics.total_requests += 1
        client_ip = request.remote or "unknown"

        if self.cfg.verbose:
            self.log.debug(f"REQ {client_ip} {request.method} {path}")

        body = await request.read()

        if self.cfg.block_upload_progress and self.cfg.upload_progress_name.encode() in body:
            ct = (request.content_type or "").lower()
            if "multipart" in ct:
                self.metrics.blocked += 1
                self.log.warning(
                    f"BLOCKED {client_ip} {request.method} {path} — "
                    f"{self.cfg.upload_progress_name} in multipart body (CVE-2026-109618/109619 vector)"
                )
                await self._log_blocked(request, body, client_ip, ["upload_progress_blocked"])
                return web.Response(
                    status=403,
                    text="Request blocked by PHP Sentinel. session.upload_progress exploit vector detected.\n",
                    content_type="text/plain",
                )

        req_path = path.split("?", 1)[0]
        if any(req_path.startswith(p) for p in self.cfg.skip_canary_paths):
            if self.cfg.verbose:
                self.log.debug(f"SKIP-CANARY {client_ip} {request.method} {path} (path allowlist)")
            self.metrics.bypassed += 1
            return await self._forward_to_backend(request, body)

        if self.cfg.max_replay_body and len(body) > self.cfg.max_replay_body:
            self.log.info(
                f"BYPASS {client_ip} {request.method} {path} "
                f"body={len(body)} exceeds max_replay_body"
            )
            self.metrics.bypassed += 1
            return await self._forward_to_backend(request, body)

        # ── Fan out to ALL canaries in parallel ──────────────────────
        failed_canaries = await self._replay_to_all_canaries(request, body, client_ip)

        if not failed_canaries:
            self.metrics.forwarded += 1
            return await self._forward_to_backend(request, body)
        else:
            self.metrics.blocked += 1
            names = ", ".join(failed_canaries)
            self.log.warning(f"BLOCKED {client_ip} {request.method} {path} — killed: [{names}]")
            await self._log_blocked(request, body, client_ip, failed_canaries)
            return web.Response(
                status=403,
                text=f"Request blocked by PHP Sentinel. Canary kill: [{names}]\n",
                content_type="text/plain",
            )

    # ── Multi-canary parallel replay ─────────────────────────────────

    async def _replay_to_all_canaries(
        self,
        request: web.Request,
        body: bytes,
        client_ip: str,
    ) -> list[str]:
        """
        Replay to every canary in parallel.  Returns a list of canary
        names that FAILED (empty = all survived = request is clean).
        """
        skip_headers = {
            "host", "connection", "keep-alive", "transfer-encoding",
            "te", "trailer", "upgrade",
        }
        headers = {
            k: v for k, v in request.headers.items()
            if k.lower() not in skip_headers
        }
        headers["X-Sentinel-Client-IP"] = client_ip

        tasks = []
        for canary_url, canary_name in zip(self.cfg.canary_urls, self.canary_names):
            if canary_name in self.disabled_canaries:
                continue
            h = dict(headers)
            h["Host"] = canary_name
            tasks.append(self._replay_one(
                canary_url, canary_name, request.method, request.path_qs, h, body, client_ip
            ))

        if not tasks:
            self.log.warning(f"ALL canaries disabled — blocking {client_ip} {request.method} {request.path_qs}")
            return ["all_canaries_disabled"]

        results = await asyncio.gather(*tasks)
        return [name for name, ok in results if not ok]

    async def _replay_one(
        self,
        canary_url: str,
        canary_name: str,
        method: str,
        path_qs: str,
        headers: dict,
        body: bytes,
        client_ip: str,
    ) -> tuple[str, bool]:
        target = canary_url + path_qs
        try:
            async with self._canary_session.request(
                method=method,
                url=target,
                headers=headers,
                data=body,
                allow_redirects=False,
                ssl=False,
            ) as resp:
                if resp.status in self.cfg.canary_fail_codes:
                    self.log.warning(
                        f"CANARY FAIL [{canary_name}] status={resp.status} "
                        f"{client_ip} {method} {path_qs}"
                    )
                    self.metrics.canary_errors += 1
                    self.metrics.per_canary[canary_name]["errors"] += 1
                    return (canary_name, False)
                return (canary_name, True)

        except asyncio.TimeoutError:
            self.log.warning(
                f"CANARY TIMEOUT [{canary_name}] {client_ip} {method} {path_qs}"
            )
            self.metrics.canary_timeouts += 1
            self.metrics.per_canary[canary_name]["timeouts"] += 1
            return (canary_name, False)

        except (aiohttp.ClientError, ConnectionError, OSError) as exc:
            self.log.warning(
                f"CANARY CRASH [{canary_name}] {type(exc).__name__}: {exc} "
                f"{client_ip} {method} {path_qs}"
            )
            self.metrics.canary_errors += 1
            self.metrics.per_canary[canary_name]["crashes"] += 1
            return (canary_name, False)

    # ── Backend forwarding ───────────────────────────────────────────

    async def _forward_to_backend(
        self,
        request: web.Request,
        body: bytes,
    ) -> web.StreamResponse:
        skip_headers = {
            "host", "connection", "keep-alive", "transfer-encoding",
            "te", "trailer", "upgrade",
        }
        headers = {
            k: v for k, v in request.headers.items()
            if k.lower() not in skip_headers
        }
        headers["Host"] = request.host
        headers["X-Forwarded-For"] = request.remote or ""
        headers["X-Forwarded-Proto"] = request.scheme

        backend_target = self.cfg.backend_url + request.path_qs

        try:
            async with self._backend_session.request(
                method=request.method,
                url=backend_target,
                headers=headers,
                data=body,
                allow_redirects=False,
                ssl=False,
            ) as resp:
                excluded = {"transfer-encoding", "connection", "keep-alive"}
                resp_headers = {
                    k: v for k, v in resp.headers.items()
                    if k.lower() not in excluded
                }
                response = web.StreamResponse(
                    status=resp.status,
                    headers=resp_headers,
                )
                await response.prepare(request)
                async for chunk in resp.content.iter_any():
                    await response.write(chunk)
                await response.write_eof()
                return response

        except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
            self.log.error(f"BACKEND ERROR {type(exc).__name__}: {exc}")
            return web.Response(
                status=502,
                text="Backend unavailable.\n",
                content_type="text/plain",
            )

    # ── Block logging ────────────────────────────────────────────────

    async def _log_blocked(
        self,
        request: web.Request,
        body: bytes,
        client_ip: str,
        failed_canaries: list[str],
    ):
        redact = {"cookie", "authorization", "proxy-authorization", "x-sentinel-key"}
        safe_headers = {
            k: ("[REDACTED]" if k.lower() in redact else v)
            for k, v in request.headers.items()
        }
        entry = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "client_ip": client_ip,
            "method": request.method,
            "path": request.path_qs,
            "content_type": request.content_type or "",
            "content_length": len(body),
            "killed_canaries": failed_canaries,
            "headers": safe_headers,
        }
        if self.cfg.block_log:
            try:
                if self.cfg.block_log_max_bytes:
                    try:
                        sz = os.path.getsize(self.cfg.block_log)
                    except OSError:
                        sz = 0
                    if sz >= self.cfg.block_log_max_bytes:
                        rotated = self.cfg.block_log + ".1"
                        try:
                            os.replace(self.cfg.block_log, rotated)
                        except OSError:
                            pass
                with open(self.cfg.block_log, "a") as f:
                    f.write(json.dumps(entry) + "\n")
            except Exception as exc:
                self.log.error(f"Failed to write block log: {exc}")
        if self.cfg.webhook_url:
            asyncio.ensure_future(self._send_webhook(entry))

    async def _send_webhook(self, entry: dict):
        try:
            async with self._backend_session.post(
                self.cfg.webhook_url,
                json={"event": "request_blocked", "source": "php-sentinel", **entry},
                timeout=aiohttp.ClientTimeout(total=5),
            ) as resp:
                if resp.status >= 400:
                    self.log.warning(f"Webhook returned HTTP {resp.status}")
        except Exception as exc:
            self.log.warning(f"Webhook failed: {type(exc).__name__}: {exc}")


async def _detect_upload_progress_name(proxy: "SentinelProxy", logger: logging.Logger) -> str:
    for url in proxy.cfg.canary_urls:
        try:
            async with proxy._canary_session.get(f"{url}/__canary/health") as resp:
                if resp.status == 200:
                    data = await resp.json()
                    name = data.get("upload_progress_name")
                    if name:
                        return name
        except Exception:
            continue
    return ""


# ── Application entry point ──────────────────────────────────────────

async def run():
    cfg = SentinelConfig.from_env()
    logger = setup_logging(cfg)

    proxy = SentinelProxy(cfg, logger)
    await proxy.start()

    if cfg.block_upload_progress and not os.getenv("SENTINEL_UPLOAD_PROGRESS_NAME"):
        detected = await _detect_upload_progress_name(proxy, logger)
        if detected and detected != cfg.upload_progress_name:
            cfg.upload_progress_name = detected
            logger.info(f"Auto-detected session.upload_progress.name from canary: {detected}")
        elif detected:
            logger.info(f"Upload-progress filter targeting: {detected}")
        logger.info(
            "Verify this matches production: "
            "php -r \"echo ini_get('session.upload_progress.name');\" on your prod server"
        )

    logger.info(
        f"PHP Sentinel listening on {cfg.listen_host}:{cfg.listen_port}  "
        f"canaries={cfg.canary_urls}  backend={cfg.backend_url}"
    )
    if getattr(cfg, '_admin_key_generated', False):
        logger.warning(
            f"No SENTINEL_ADMIN_KEY set — generated random key for this session:\n"
            f"  SENTINEL_ADMIN_KEY={cfg.admin_key}\n"
            f"  Set this in docker-compose.yml to keep the same key across restarts."
        )
    else:
        logger.info("Admin API authentication enabled (SENTINEL_ADMIN_KEY is set)")

    app = web.Application(client_max_size=cfg.max_body_size or 100 * 1024 * 1024)
    app.router.add_route("*", "/{path_info:.*}", proxy.handle)

    runner = web.AppRunner(app, access_log=None)
    await runner.setup()

    site = web.TCPSite(runner, cfg.listen_host, cfg.listen_port)
    await site.start()

    admin_runner = None
    if cfg.admin_port:
        admin_app = web.Application()
        admin_app.router.add_route("*", "/{path_info:.*}", proxy.handle_admin)
        admin_runner = web.AppRunner(admin_app, access_log=None)
        await admin_runner.setup()
        admin_site = web.TCPSite(admin_runner, "127.0.0.1", cfg.admin_port)
        await admin_site.start()
        logger.info(f"Admin API/dashboard on 127.0.0.1:{cfg.admin_port} (not exposed on public port)")
    else:
        logger.warning(
            "Admin API is on the public port (%d). Set SENTINEL_ADMIN_PORT to bind "
            "it to a separate internal port, or put /__sentinel/admin/* behind an IP allowlist.",
            cfg.listen_port,
        )

    stop_event = asyncio.Event()

    def _shutdown(sig, frame):
        logger.info(f"Received {signal.Signals(sig).name}, shutting down...")
        stop_event.set()

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    await stop_event.wait()

    logger.info(f"Final metrics: {json.dumps(proxy.metrics.to_dict())}")
    await proxy.stop()
    if admin_runner:
        await admin_runner.cleanup()
    await runner.cleanup()


def main():
    asyncio.run(run())


if __name__ == "__main__":
    main()
