# 01 — Endpoint Detection

The endpoint is where exploitation becomes execution. Sysmon + a good EDR is where most real detections live.

## Highest-value Sysmon-based detections
| Technique | Signal | ATT&CK |
|-----------|--------|--------|
| LSASS access | EID 10, TargetImage `lsass.exe`, non-allowlisted source | T1003.001 |
| Process injection | EID 8 (CreateRemoteThread), EID 10 cross-process | T1055 |
| Suspicious parent/child | `winword.exe`→`powershell.exe`, `w3wp.exe`→`cmd.exe` | T1059 |
| Encoded PowerShell | EID 1 cmdline `-enc`/`-e`/`FromBase64String` | T1059.001 |
| LOLBins | `certutil -urlcache`, `mshta`, `regsvr32 /i:http`, `rundll32` js | T1218 |
| Masquerading | `svchost.exe` outside `System32`, wrong parent | T1036 |

## Process ancestry is king
Single events lie; chains don't. An Office app spawning a shell that spawns `certutil` downloading an executable is three benign events and one obvious intrusion.

```splunk
index=sysmon EventCode=1 ParentImage IN ("*\\winword.exe","*\\excel.exe","*\\outlook.exe")
  Image IN ("*\\powershell.exe","*\\cmd.exe","*\\wscript.exe","*\\mshta.exe")
| table _time host User ParentImage Image CommandLine
```

## Script-block logging
PowerShell 4104 captures deobfuscated script content. Alert on `DownloadString`, `IEX`, `Invoke-Mimikatz`, `Reflection.Assembly`, `AmsiUtils`.

## Tune with allowlists, not by deleting the rule
Admin tools and backup agents will trip these. Maintain per-rule allowlists of known-good (process + signer + host), and review the allowlist like code.
