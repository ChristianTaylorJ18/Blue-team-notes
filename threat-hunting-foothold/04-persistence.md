# 04 — Persistence (TA0003)

Keeping access across reboots/logouts. All `winlogbeat-*`.

## Scheduled tasks
Use EID **4698** if audit policy is configured; otherwise hunt the command keywords.
```kql
host.name: WKSTN-* AND (winlog.event_id: 4698 OR (*schtasks* OR *Register-ScheduledTask*))
```
Columns: `process.command_line`, `winlog.event_id`, `winlog.event_data.TaskName`. Among benign tasks (OneDrive) was a fake **"Windows Update"** task running a PowerShell command **every minute** — and tied to the known-malicious domain `oneedirve[.]xyz`.

## Registry autoruns (Sysmon EID 13 = registry value set)
Broad query is overwhelming (1481 hits), so focus on known autorun keys:
```kql
host.name: WKSTN-* AND winlog.event_id: 13 AND winlog.channel: Microsoft-Windows-Sysmon/Operational AND registry.path: (*CurrentVersion\\Run* OR *CurrentVersion\\Explorer\\User* OR *CurrentVersion\\Explorer\\Shell*)
```
Columns: `registry.path`, `winlog.event_data.Details`. Stand-out:
- Path `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx\0001\Depend\1`
- Data `C:\Windows\Temp\installer.exe` → runs the known payload at startup.

Alternative: hunt by the modifying process instead of the key:
```kql
host.name: WKSTN-* AND winlog.event_id: 13 AND winlog.channel: Microsoft-Windows-Sysmon/Operational AND process.name: (reg.exe OR powershell.exe)
```
(Catches `reg.exe`/`powershell.exe` edits; to find odd binaries touching the registry, exclude known-good processes instead.)
