# 02 — Web Hardening

Mirror of web proxies/web exploits: reduce what a web attacker can reach, and make successful exploitation loud.

## Baseline response headers
```
Content-Security-Policy: default-src 'self'
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
Referrer-Policy: no-referrer
Set-Cookie: ...; HttpOnly; Secure; SameSite=Lax
```
- CSP is the single biggest XSS mitigation; start in `Content-Security-Policy-Report-Only` and tighten using the violation reports.
- `HttpOnly` cookies blunt cookie theft via XSS. `SameSite` blunts CSRF.

## Input handling (defense-in-depth, server side)
- **Parameterized queries everywhere** — the only reliable SQLi defense. Never build SQL by string concatenation.
- Output-encode per context (HTML/attr/JS/URL) to neutralize XSS.
- Validate file uploads by content, not extension; store outside webroot; serve via a handler, never execute.

## WAF as detection + virtual patch
- Run the WAF in blocking mode for known signatures, but also ship its logs to the SIEM — WAF alerts are high-signal web-attack telemetry (see [Web Attack Detection](../3-detection/04-web-attack-detection.md)).

## Reduce surface
- Disable dangerous HTTP verbs (`PUT`, `DELETE`, `TRACE`) unless required. `TRACE` enabled is a finding.
- Remove default apps, server-status pages, verbose error pages, and version banners.
- Lock admin panels to an allowlisted management network / VPN.
