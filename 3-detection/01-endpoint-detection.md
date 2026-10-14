# 01 — Endpoint Detection

The endpoint is where exploitation becomes execution. Sysmon plus a capable EDR is where most real detections live — the attacker's code has to run somewhere, and this is where you see it run.

## Highest-value Sysmon-based detections
| Technique | Signal | ATT&CK |
|-----------|--------|--------|
| LSASS credential access | EID 10, TargetImage `lsass.exe`, GrantedAccess `0x1010`/`0x1410`, non-allowlisted source | T1003.001 |
| Process injection | EID 8 (CreateRemoteThread), EID 10 cross-process into a legit host | T1055 |
| Office → shell | parent `winword/excel/outlook`, child `powershell/cmd/wscript/mshta` | T1059 |
| Encoded/obfuscated PowerShell | EID 1 cmdline `-enc`/`-e`/`FromBase64String`/`-w hidden` | T1059.001 |
| LOLBins | `certutil -urlcache`, `mshta http`, `regsvr32 /i:http`, `rundll32 javascript:`, `bitsadmin /transfer` | T1218/T1197 |
| Masquerading | `svchost.exe` outside `System32`, wrong parent, lookalike names | T1036 |
| Service/task persistence | EID 1 `sc create`/`schtasks /create`, 7045 service install | T1543/T1053 |
| Suspicious DNS | EID 22 query to known-bad / high-entropy / newly-registered domain | T1071.004 |
| Defense evasion | EID 1 `wevtutil cl`, `vssadmin delete shadows`, AMSI/ETW tamper | T1070/T1562 |

## Process ancestry is king
Single events lie; chains don't. An Office app spawning a shell that spawns `certutil` downloading an executable that then beacons is four benign-ish events and one unambiguous intrusion. Build detections and triage around the **parent→child→grandchild** tree, not the leaf event.

```splunk
index=sysmon EventCode=1 ParentImage IN ("*\\winword.exe","*\\excel.exe","*\\outlook.exe","*\\w3wp.exe")
  Image IN ("*\\powershell.exe","*\\cmd.exe","*\\wscript.exe","*\\cscript.exe","*\\mshta.exe")
| table _time host User ParentImage Image CommandLine
```

## PowerShell script-block logging (4104)
Captures deobfuscated script content even when the command line was encoded. Alert on `DownloadString`/`DownloadData`, `IEX`/`Invoke-Expression`, `Reflection.Assembly`/`[Reflection.Assembly]::Load`, `AmsiUtils`/`amsiInitFailed` (AMSI bypass), `Invoke-Mimikatz`, `Net.WebClient`, `FromBase64String`, and known offensive module names.

## Credential-access & evasion specifics
- **LSASS access** (above) is the flagship; also watch comsvcs.dll `MiniDump`, `procdump lsass`, and `rundll32` dumping lsass.
- **Shadow-copy deletion** (`vssadmin`/`wmic shadowcopy delete`) and **log clearing** (`wevtutil cl`, EID 1102) are ransomware/anti-forensics tells — high severity.
- **AMSI/ETW tampering** and `Set-MpPreference -Disable*` indicate defense evasion in progress.

## Tune with allowlists, not by deleting the rule
Admin tools, backup agents, and management software will trip these. Maintain per-rule allowlists keyed on **process path + signer + host/role** (not just name — attackers name their binary `svchost.exe`). Review the allowlist like code, and prefer *narrowing* (add a correlating condition, raise aggregation) over silencing. Feed every triage verdict back into the rule's FP notes.
