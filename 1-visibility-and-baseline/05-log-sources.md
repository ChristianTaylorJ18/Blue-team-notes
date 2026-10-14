# 05 — Log Sources & Retention

A detection is worthless if the underlying log was never collected, was collected without the needed fields, or already rotated away. Define the source-of-truth list, the required fields, and retention up front.

## Minimum viable log sources
| Source | Gives you | Priority |
|--------|-----------|----------|
| Windows Security (4624/4625/4648/4672/4688/4720/4728/4732/4768/4769/4662/5140/5145/7045) | Auth, privilege, process, account/group change, Kerberos, shares, service install | Critical |
| Sysmon (1,3,7,8,10,11,12/13,22,23) | Process+cmdline, network, image load, injection, lsass access, file, registry, DNS, file delete | Critical |
| PowerShell (4103/4104) | Module + deobfuscated script-block logging | Critical |
| EDR telemetry | Rich endpoint behavior, process tree, memory | Critical |
| Firewall / proxy / web | Egress, C2, exfil, web-attack attempts | High |
| DNS resolver logs | C2 domains, DGA, tunneling | High |
| AD / LDAP / DS changes (5136/5137) | Object + ACL changes, replication | High |
| Linux auditd / journald | execve, auth, file access, module load | High |
| Cloud audit (CloudTrail/Activity/Audit) | IAM, control-plane, data-plane | High |

## Get the fields, not just the events
- Turn on **command-line logging** (4688 `ProcessCommandLine`, Sysmon EID 1) — a process event without its command line is half-blind.
- Ensure audit policy actually logs the above (many are off by default): Kerberos service-ticket ops, directory-service changes, detailed file share, process creation.
- Normalize to a schema (ECS/CIM) at ingest so `user`/`host`/`src_ip` mean the same thing everywhere; detections survive source swaps.

```powershell
# Confirm the audit subcategories you depend on are actually on
auditpol /get /category:* | findstr /i "Logon Process Kerberos Directory"
# Confirm Sysmon running and matches the golden config
Get-Service Sysmon* ; (Get-FileHash C:\Windows\Sysmon64.exe).Hash
```

## Retention
- **Hot (searchable):** 90 days minimum — most hunts and triage live here.
- **Cold (recoverable):** 12 months+ — dwell time routinely exceeds a quarter; you need history to scope a breach and answer "when did this start?".
- Auth and AD/ACL change logs: keep longest; they anchor every timeline.
- Match retention to legal/regulatory holds where applicable.

## Collection hygiene
- **Forward logs off-host in real time.** Local-only logs are deletable by whoever owns the box (ATT&CK T1070). The DC and the crown-jewel server are exactly where logs get cleared.
- **Monitor log-source health**: a source going silent is itself an alert — attacker cleared logs, disabled the agent, or collection broke. Alert on expected-but-absent sources, not just on events.
- Protect the log pipeline: restricted access, integrity on the collector, and ideally a write-once/immutable tier for the highest-value sources.
