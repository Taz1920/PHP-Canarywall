# Security Policy

## Reporting a Vulnerability

If you find a security vulnerability in PHP CanaryWall, please report it responsibly.

**Email:** ryan.tj.birdusnavy@gmail.com

Please include:
- Description of the vulnerability
- Steps to reproduce
- Impact assessment
- Suggested fix (if any)

I will acknowledge receipt within 48 hours and aim to provide a fix or mitigation within 7 days for critical issues.

## Scope

This policy covers vulnerabilities in PHP CanaryWall itself — the proxy, canary configuration, dashboard, and admin API. It does not cover the PHP vulnerabilities (CVE-2026-109618, CVE-2026-109619) that Sentinel is designed to mitigate.

## Supported Versions

| Version | Supported |
|---------|-----------|
| Latest release | Yes |
| Older releases | Best effort |

## Security Design

- Admin API requires authentication via `X-Sentinel-Key` header
- Canary instances run on an internal Docker network with no egress
- Block logs redact sensitive headers (Cookie, Authorization)
- Test mode (`X-Sentinel-Test` header) is disabled by default and requires `SENTINEL_TEST_MODE=1` environment variable
