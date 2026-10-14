# 02 — Windows Triage

Mirror of Windows privesc / credential dumping / persistence. Capture volatile state, then sweep the autostart surface.

## Volatile state
```powershell
Get-CimInstance Win32_Process | Select ProcessId,ParentProcessId,Name,CommandLine | Sort ParentProcessId
Get-NetTCPConnection -State Established,Listen |
  Select LocalPort,RemoteAddress,RemotePort,OwningProcess,State
Get-CimInstance Win32_LogonSession | Select LogonId,LogonType,StartTime
query user ; qwinsta         # interactive / RDP sessions
```

## Autostart & persistence surface
```powershell
# Services pointing at odd paths / user dirs
Get-CimInstance Win32_Service | Where {$_.PathName -match 'Users|Temp|AppData|\\\\'} |
  Select Name,StartMode,State,PathName
# Scheduled tasks (full export)
Get-ScheduledTask | Get-ScheduledTaskInfo |
  ForEach-Object { Get-ScheduledTask -TaskName $_.TaskName } |
  Select TaskName,TaskPath,@{n='Action';e={$_.Actions.Execute+' '+$_.Actions.Arguments}}
# Run keys + common ASEPs (use Autoruns -accepteula -a * -c for the full set)
Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run,
  HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
# WMI event-subscription persistence (stealthy)
Get-CimInstance -Namespace root\subscription -Class __FilterToConsumerBinding
```

## Credential-theft and lateral-movement artifacts
```powershell
# Recent 4624 type 3/10 (network/RDP) + 4648 (explicit creds) — who touched this box
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4624,4648,4672} -MaxEvents 100 |
  Select TimeCreated,Id,@{n='Msg';e={$_.Message.Split("`n")[0]}}
# PowerShell script blocks recorded on this host
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational';Id=4104} -MaxEvents 50 |
  Where {$_.Message -match 'DownloadString|IEX|FromBase64|Mimikatz|lsass'}
```

## Local accounts & groups
```powershell
Get-LocalUser | Select Name,Enabled,LastLogon
Get-LocalGroupMember Administrators     # any unexpected member = finding
```

## Prefer Autoruns + a proper EDR timeline
The commands above are the manual floor. If EDR is present, pull the process tree and timeline there first — it already recorded what live-response can only partly reconstruct.
