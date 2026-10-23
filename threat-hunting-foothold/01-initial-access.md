# 01 — Initial Access (TA0001)

Getting the first foothold — via valid credentials or remote code execution. Three scenarios.

## SSH brute force (filebeat)
Brute force = many failed auths, then a success. Build a **Lens** table: index `filebeat`, Rows `source.ip` + `user.name`, Metric `count`.
```kql
host.name: jumphost AND event.category: authentication AND system.auth.ssh.event: Failed
```
Two IPs generated 500+ failed events. Check whether it worked by flipping to `Accepted` and filtering to the top source IPs:
```kql
host.name: jumphost AND event.category: authentication AND system.auth.ssh.event: Accepted AND source.ip: (167.71.198.43 OR 218.92.0.115)
```
Confirmed: `167.71.198.43` got in on the `dev` account. Next thread → what commands they ran (Execution tactic).

## Web RCE (packetbeat)
Web attacks: enumeration first, then exploitation. **Lens** table: index `packetbeat`, Rows `source.ip` + `http.response.status_code`, Metric `count`.
```kql
host.name: web01 AND network.protocol: http AND destination.port: 80
```
A flood of **404s** from one IP = directory enumeration. Drill into it in **Discover** (columns: `query`, `user_agent.original`, `url.query`):
```kql
host.name: web01 AND network.protocol: http AND destination.port: 80 AND source.ip: 167.71.198.43 AND http.response.status_code: 404
```
User-Agent showed **Gobuster**; the attacker fixated on the `/gila` endpoint. Then look at success codes to see what landed, sorted ascending by time:
```kql
host.name: web01 AND network.protocol: http AND destination.port: 80 AND source.ip: 167.71.198.43 AND http.response.status_code: (200 OR 301 OR 302)
```
After finding `/gila`, the attacker put **PHP in the User-Agent** and used an `x` parameter to run commands via `system()` — confirmed RCE (Gila CMS vuln). Lesson: status-code patterns (404 vs 200/301/302) tell the enumeration→exploitation story; check odd fields like User-Agent for payloads.

## Phishing (winlogbeat, Sysmon EID 11 = file creation)
Two indicators: files downloaded via browser, and files opened from the email client.

**Downloaded via Chrome** (ignore Chrome's `.tmp` files):
```kql
host.name: WKSTN-* AND process.name: chrome.exe AND winlog.event_id: 11
```
Columns: `winlog.computer_name`, `winlog.event_data.User`, `file.path`. Turned up `chrome.exe` + `microsoft.hta` (WKSTN-1) and `update.exe` (WKSTN-2) in Downloads.

**Opened via Outlook**:
```kql
host.name: WKSTN-* AND process.name: OUTLOOK.EXE AND winlog.event_id: 11
```
An attachment `Update.zip` landed in `\AppData\Local\Microsoft\Windows\INetCache\Content.Outlook\`. Confirm its contents:
```kql
host.name: WKSTN-* AND *Update.zip*
```
Inside was a `.lnk` (shortcut) — a classic malware attachment. Add `process.executable` as a column and **View surrounding documents** on the `update.lnk` event to see what it spawned (powershell.exe on WKSTN-2).
