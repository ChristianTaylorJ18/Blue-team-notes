# 02 — Web Hardening

Mirror of web proxies/web exploits: reduce what a web attacker can reach, neutralize the common bug classes server-side, and make successful exploitation loud.

## Baseline response headers
```
Content-Security-Policy: default-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'
X-Content-Type-Options: nosniff
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
Referrer-Policy: no-referrer
Permissions-Policy: geolocation=(), microphone=(), camera=()
Set-Cookie: ...; HttpOnly; Secure; SameSite=Lax
```
- **CSP** is the single biggest XSS mitigation; roll out in `Content-Security-Policy-Report-Only` first, tighten using violation reports, then enforce. `frame-ancestors 'none'` replaces `X-Frame-Options` for clickjacking.
- `HttpOnly` blunts cookie theft via XSS; `Secure` + `SameSite` blunt interception and CSRF.

## Neutralize the bug classes server-side (defense in depth)
- **SQLi** → parameterized queries / prepared statements everywhere. The only reliable fix; never build SQL by string concatenation, and give the app's DB user least privilege (no DDL, no `xp_cmdshell`).
- **XSS** → context-aware output encoding (HTML / attribute / JS / URL each differ), plus CSP as the safety net.
- **File upload** → validate by content type and magic bytes not extension, randomize stored names, store **outside the webroot**, serve via a handler that never executes, and scan with AV. This directly kills the `.phtml`/webshell path.
- **Path traversal / LFI** → canonicalize and allowlist paths; never pass user input to file APIs or `include`.
- **SSRF** → allowlist outbound destinations from the app tier; block link-local/metadata IPs (169.254.169.254).
- **Deserialization / template injection** → avoid native deserialization of untrusted data; sandbox template engines.

## Reduce surface
- Disable dangerous HTTP verbs (`PUT`, `DELETE`, `TRACE`, `TRACK`) unless required — `TRACE` enabled is a finding (verb-tampering + XST).
- Remove default apps, `server-status`/`info` pages, directory listing, verbose errors, and version banners.
- Lock admin panels and management endpoints to an allowlisted network / VPN + MFA.
- Keep the stack patched ([vuln mgmt](./01-vulnerability-management.md)) and run app components as least-privileged, non-root service accounts.

## WAF as detection + virtual patch
Run the WAF in blocking mode for known signatures, **and** ship its logs to the SIEM — WAF events are high-signal web-attack telemetry and let you virtual-patch a specific CVE fast while the code fix is scheduled ([web attack detection](../3-detection/04-web-attack-detection.md)). Don't treat the WAF as the fix; treat it as the tripwire and the stopgap.
