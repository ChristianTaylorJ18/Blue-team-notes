# 02 — Web Incident

**Trigger:** suspected web compromise — WAF burst, webshell alert, defacement, odd outbound from a web server. Counterpart to the web-exploit kill chain.

- [ ] Identify the app, host, tier, and whether it reaches internal networks (a web box that can see an internal subnet is the pivot — prioritize).
- [ ] Preserve: capture the web server's memory/process state if it may matter; **copy** logs off before they rotate.
- [ ] Reconstruct the attack from access logs:
  - [ ] Find the source IP(s): fuzzing bursts (many 404/403) → a 200 on a sensitive path → POST → new file served.
  - [ ] Grep for injection/traversal/upload markers ([web attack detection](../3-detection/04-web-attack-detection.md)).
```bash
grep -Ei "union(\s|%20)+select|/etc/passwd|\.\./|<script|sleep\(|cmd=|/uploads/.*\.(php|aspx|jsp)" access.log | tail -80
```
- [ ] Hunt the webshell:
  - [ ] New/modified executable web files since the last clean deploy:
```bash
find /var/www -type f \( -name '*.php' -o -name '*.aspx' -o -name '*.jsp' \) -newermt '-7 days' -ls
```
  - [ ] Files owned by the web-server user in upload dirs; short obfuscated files; files with `eval`/`system`/`base64_decode`/`FromBase64String`.
- [ ] Check what the shell did: web-server process spawning `sh`/`cmd`/`powershell` (Sysmon EID 1, parent `w3wp`/`httpd`/`nginx`) → it reached OS command exec.
- [ ] Scope outward: did the web box auth to anything internal afterward? Any new local account, cron/service, SSH key? → [04](./04-linux-compromise.md)/[05](./05-windows-compromise.md).
- [ ] Add IOCs (source IPs, shell hashes/paths, user-agents) and sweep all web hosts for the same shell.
- [ ] Contain: block source at WAF/edge, remove the shell **after** preserving a copy, then eradicate persistence and rotate any secrets the app held (DB creds, API keys, tokens in config).
- [ ] Virtual-patch the entry vuln at the WAF immediately; schedule the real code fix ([web hardening](../2-hardening/02-web-hardening.md)).
