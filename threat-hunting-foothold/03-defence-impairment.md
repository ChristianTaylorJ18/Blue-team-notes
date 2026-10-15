# 03 — Defence Impairment (TA0112)

Disabling defences and destroying evidence. All `winlogbeat-*`.

## Disabling Windows Defender
```kql
host.name: WKSTN-* AND (*DisableRealtimeMonitoring* OR *RemoveDefinitions*)
```
Two indicators:
- `DisableRealtimeMonitoring` — PowerShell `Set-MpPreference -DisableRealtimeMonitoring $true` (run by `installer.exe`).
- `RemoveDefinitions` — `MpCmdRun.exe -RemoveDefinitions` wipes AV signatures (run by the `cmd.exe` PID 1832 spawned from Python).
Columns: `process.parent.command_line`, `process.name`, `process.command_line`. Both on WKSTN-1, correlating to earlier execution findings.

## Log deletion (EID 1102)
Windows always logs **1102** when the event log is cleared — there's no legitimate reason, so it's a strong signal.
```kql
host.name: WKSTN-* AND winlog.event_id: 1102
```
Logs cleared on WKSTN-1. **View surrounding documents** to find the command (`Clear-EventLog -LogName Security`) and the process behind it.

## Process injection (Sysmon EID 8 = CreateRemoteThread)
```kql
host.name: WKSTN-* AND winlog.event_id: 8
```
Fields: `process.executable`, `winlog.event_data.SourceUser`, `winlog.event_data.TargetImage`. `C:\Users\clifford.miller\Downloads\chrome.exe` created a remote thread in **explorer.exe** (classic injection target). The tell: every other EID 8 was SYSTEM, but this one ran as a user account — the anomaly.
