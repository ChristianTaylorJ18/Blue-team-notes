# 05 — Windows Compromise

**Trigger:** suspect Windows host (EDR alert, encoded PowerShell, LSASS access, new service/task). Counterpart to Windows privesc/credential dumping/persistence.

- [ ] **Preserve first** if it may matter: capture RAM (WinPmem) before isolating/rebooting ([forensics](../4-incident-response/06-forensic-preservation.md)).
- [ ] Pull the EDR process tree + timeline for the host — start there if EDR is present; the commands below are the manual floor.
- [ ] Volatile state ([windows triage](../4-incident-response/02-windows-triage.md)):
```powershell
Get-CimInstance Win32_Process | Select ProcessId,ParentProcessId,Name,CommandLine
Get-NetTCPConnection -State Established,Listen | Select LocalPort,RemoteAddress,RemotePort,OwningProcess
Get-LocalGroupMember Administrators
```
- [ ] Credential-theft check (high priority — stops spread): LSASS access (Sysmon EID 10 → lsass), encoded PowerShell (4104), 4648/4672 on this host.
- [ ] Persistence sweep ([persistence hunting](../4-incident-response/04-persistence-hunting.md)):
```powershell
Get-CimInstance Win32_Service | Where {$_.PathName -match 'Users|Temp|AppData'} | Select Name,State,PathName
Get-ScheduledTask | Where {$_.Actions.Execute -match 'Temp|Users|AppData|powershell|cmd'}
Get-CimInstance -Namespace root\subscription -Class __FilterToConsumerBinding   # WMI persistence
Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run, HKCU:\...\Run
```
  (Run **Autoruns** `-a * -c` for the complete ASEP set.)
- [ ] Lateral traces: 7045 (service install), 4697, 4698 (task), WinRM/WMI exec, outbound SMB/WinRM to other hosts → each target host enters scope.
- [ ] Map where the involved account authenticated (4624 type 3/10 estate-wide) → that's the spread.
- [ ] Add IOCs (hashes, C2, service/task names, accounts); sweep all hosts.
- [ ] Deep compromise or tier-0 → plan rebuild, not clean. Hand to [07-containment](./07-containment.md).
