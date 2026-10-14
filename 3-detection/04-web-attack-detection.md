# 04 — Web Attack Detection

Mirror of web exploits: the log patterns that reveal SQLi, XSS, LFI, upload abuse, and verb tampering — so you catch the attempt, and the success.

## Where to look
- Web server access logs, app logs, and WAF logs. Correlate all three: WAF shows the attempt, app log shows whether it worked (500s, unusual query times, new files).

## Patterns worth alerting on
| Attack | Log signal | ATT&CK |
|--------|-----------|--------|
| SQLi | `union select`, `' or 1=1`, `sleep(`, `information_schema`, sqlmap UA | T1190 |
| XSS | `<script`, `onerror=`, `javascript:` in params | T1059.007 |
| LFI/traversal | `../`, `..%2f`, `/etc/passwd`, `php://filter` | T1083 |
| Upload abuse | POST to upload endpoint then GET of a new `.php`/`.aspx` under uploads | T1505.003 |
| Verb tampering | non-GET/POST (`PUT`,`TRACE`,`DELETE`) to app paths, odd `X-*-IP` headers | T1190 |

```bash
# Quick grep sweep of access log for common injection/traversal markers
grep -Ei "union(\s|%20)+select|/etc/passwd|\.\./|<script|sleep\(|information_schema" access.log
```

## From attempt to success
- A single probe is noise; the pipeline is the incident. Alert when the same source IP goes: many 404/403 (fuzzing) → a 200 on a sensitive path → a POST → a new file served. That sequence is a webshell drop.
- **Webshell detection**: alert on new executable web files created by the web-server user after deployment freeze, and on short, obfuscated requests to files in upload dirs.
```splunk
index=web status=200 method=POST uri_path="*/uploads/*"
| stats count values(uri_path) by src_ip
```

## Baseline the app
Legit apps have a finite URL/parameter set. Requests to parameters the app never defined are either recon or exploitation.
