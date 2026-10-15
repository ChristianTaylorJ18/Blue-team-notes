# 05 — Malicious Binaries & Masquerading

What LOKI's binary alerts flagged on the host, and the masquerading trick to watch for.

## Binary alerts (matched by header bytes / content / YARA)
| File | Why flagged |
|------|-------------|
| `nbtscan.exe` | FIRST_BYTES `4d5a90000300000004000000ffff0000b8000000` (`MZ` PE header); reason "Known Bad / Dual use classics" |
| `p.exe` | **APT Cloaked**; matched PsExec strings `psexesvc.exe`, `Sysinternals PsExec` |
| `xCmd.exe` | Encrypted, trojan-like (remote command execution tool) |
| `schtasks-backdoor.ps1` | Associated with `somethingwindows.dmp` in `C:\TMP` |
| `en-US.js` | Hacktool; YARA rule match **`CACTUSTORCH`** |

`4d 5a` = `MZ` = the DOS/PE header every Windows executable starts with — useful to recognise.

## Masquerading as a core process
A binary at **`C:\Users\Public\svchost.exe`** posed as the Windows `svchost`. The **legitimate** `svchost.exe` only lives in **`C:\Windows\System32`**. LOKI's reason: "Stuff running where it normally shouldn't."

Lesson: core Windows process names (`svchost`, `lsass`, `services`, `csrss`) in the *wrong path* = masquerading (ATT&CK T1036.005). Know the legitimate paths cold so a wrong one jumps out — covered in Core Windows Processes.
