# 05 — Log Sources & Retention

A detection is worthless if the underlying log was never collected or already rotated away. Define the source-of-truth list and retention up front.

## Minimum viable log sources
| Source | Gives you | Priority |
|--------|-----------|----------|
| Windows Security (4624/4625/4648/4672/4688) | Auth, logon type, privilege use, process creation | Critical |
| Sysmon (1,3,7,8,10,11,13,22) | Process, network, image load, injection, file, registry, DNS | Critical |
| PowerShell (4103/4104) | Script-block + module logging | Critical |
| EDR telemetry | Rich endpoint behavior | Critical |
| Firewall / proxy | Egress, C2, exfil | High |
| DNS resolver logs | C2 domains, DGA, tunneling | High |
| AD / LDAP | Object changes, replication, Kerberos | High |
| Linux auditd / journald | execve, auth, file access | High |

## Retention
- **Hot (searchable):** 90 days minimum — most hunts live here.
- **Cold (recoverable):** 1 year+ — dwell time routinely exceeds a quarter; you need history to scope a breach.
- Authentication and AD change logs: keep longest. They anchor every "when did this start?" question.

## Collection hygiene
- Monitor *log-source health*: a source going silent is an alert (attacker cleared logs, or collection broke).
- Forward logs off-host in real time. Local-only logs are deletable by whoever owns the box.

```powershell
# Confirm Sysmon is running and config hash matches your golden config
Get-Service Sysmon* ; (Get-FileHash C:\Windows\sysmon.exe).Hash
```
