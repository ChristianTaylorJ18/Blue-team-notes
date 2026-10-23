# 05 — Command & Control (TA0011)

The attacker's comms channel, blended into normal traffic. Hunt network in `packetbeat-*`, then correlate the owning process in `winlogbeat-*`.

Reading network traffic:
- **Egress** → file uploads / C2 callbacks. **Ingress** → inbound intrusion.
- Cleartext host commands in traffic → active C2. High connection count / encrypted bandwidth → unusual activity.

## C2 over DNS
**Lens**: index `packetbeat`, Rows `dns.question.registered_domain` + `host.name`, Metric **Unique count** of `dns.question.subdomain`.
```kql
network.protocol: dns AND NOT dns.question.name: *arpa
```
`golge[.]xyz` had **2191 unique subdomains** from WKSTN-1 = tunnelling. Drill in:
```kql
network.protocol: dns AND NOT dns.question.name: *arpa AND dns.question.registered_domain: golge.xyz AND host.name: WKSTN-1
```
Continuous queries with CNAME/TXT/MX record types and **hex subdomains**, sent straight to an unknown nameserver (bypassing configured DNS). Correlate the process:
```kql
host.name: WKSTN-1* AND destination.ip: 167.71.198.43 AND destination.port: 53
```
All `:53` traffic came from **nslookup.exe**; surrounding docs showed it was `dnscat2.ps1` (downloaded from the dnscat2-powershell GitHub repo). Note: DNS queries are normally short — long hex subdomains / large `network.bytes` are the anomaly.

## C2 over cloud apps
**Lens** top-50 domains by count (Rows `dns.question.registered_domain` [50 values, rank by count desc] + `host.name`), same base query. `discord.gg` stood out on WKSTN-1:
```kql
host.name: WKSTN-1* AND *discord.gg*
```
Columns: `process.executable`, `dns.question.name`. Initiated by `C:\Windows\Temp\installer.exe`. Pull its children:
```kql
host.name: WKSTN-1* AND winlog.event_id: 1 AND process.parent.executable: "C:\\Windows\\Temp\\installer.exe"
```
Multiple `cmd.exe` commands = C2 over Discord.

## C2 over encrypted HTTP
**Lens**: Rows `host.name` + `destination.domain` + `http.request.method`, Metric `count`.
```kql
network.protocol: http AND network.direction: egress
```
Heavy traffic to `cdn[.]golge[.]xyz` from both workstations = long-running C2. Focus it:
```kql
host.name: WKSTN-* AND network.protocol: http AND network.direction: egress AND destination.domain: cdn.golge.xyz
```
GET requests to 3 `.php` endpoints, same on both hosts → identical malware. Correlate:
```kql
host.name: WKSTN-* AND *cdn.golge.xyz*
```
Established by a malicious PowerShell command; the associated process on WKSTN-2 was `update.exe`. Lesson: same C2 endpoints across hosts imply a shared implant.
