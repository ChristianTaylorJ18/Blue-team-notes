# 04 — Web Attack Detection

Mirror of web exploits: the log patterns that reveal SQLi, XSS, LFI, upload abuse, and verb tampering — so you catch the attempt, and more importantly the *success*.

## Where to look (correlate all three)
- **Web/access logs** (what was requested, status, size, timing), **app logs** (errors, stack traces, slow queries), and **WAF logs** (what matched a signature). The WAF shows the attempt; the app log + access log show whether it worked (500s, anomalous response size/time, a new file served).

## Patterns worth alerting on
| Attack | Log signal | ATT&CK |
|--------|-----------|--------|
| SQLi | `union select`, `' or 1=1`, `sleep(`/`waitfor delay`, `information_schema`, sqlmap UA | T1190 |
| XSS | `<script`, `onerror=`, `javascript:`, `document.cookie` in params | T1059.007 |
| LFI / traversal | `../`, `..%2f`, `%2e%2e`, `/etc/passwd`, `php://filter`, `data://` | T1083/T1212 |
| RFI / SSRF | `=http://`, `=https://`, `169.254.169.254`, internal IPs in params | T1190 |
| Upload abuse | POST to upload endpoint, then GET of a new `.php`/`.phtml`/`.aspx`/`.jsp` under uploads | T1505.003 |
| Verb tampering | non-GET/POST (`PUT`,`TRACE`,`DELETE`), odd `X-*-IP`/`X-Forwarded` headers | T1190 |
| Auth attacks | burst of 401/403 then a 200 on a protected path; many users one IP (spray) | T1110 |

```bash
grep -Ei "union(\s|%20)+select|/etc/passwd|\.\./|<script|sleep\(|waitfor delay|information_schema|php://|169\.254\.169\.254" access.log | tail -80
```

## From attempt to success (the real detection)
A single probe is noise; the *pipeline* is the incident. Alert when one source walks the chain:
`many 404/403 (fuzzing)` → `200 on a sensitive/parameterized path` → `POST` → `a new file is served from an upload/writable dir`. That sequence is a webshell drop in progress.

```splunk
index=web method=POST status=200 uri_path="*/uploads/*"
| stats count values(uri_path) earliest(_time) as first by src_ip
| where count > 0
```

## Webshell detection
- New **executable web files** created by the web-server user after the deployment freeze (`find /var/www -name '*.php' -newermt '-7 days'`), and short, obfuscated requests (`?cmd=`, `?x=`) to files in upload/writable dirs.
- Web-server process (`w3wp`/`httpd`/`nginx`/`php-fpm`) spawning `cmd`/`sh`/`powershell` (Sysmon EID 1) = the shell reached OS command exec. Pivot there immediately.

## Baseline the app
Legit apps have a finite set of URLs and parameters. Requests to parameters the app never defined, or to paths outside its route map, are recon or exploitation. A learned app profile turns "weird request" into a precise, low-FP detection.
