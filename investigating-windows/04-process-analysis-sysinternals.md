# 04 — Process Analysis with Sysinternals

Using **Process Monitor** (Procmon) and **Process Explorer** to catch short-lived malicious processes and their parentage.

## Catching the recurring processes
Two processes opened and closed every few minutes: **`mim.exe`** and **`powershell.exe`** (`powershell.exe` starts first). In **Process Monitor**, filter on each and inspect:
- **Parent process**: both spawned from **`svchost.exe`** (check the Parent PID).
- **First operation** for the first process: **Process Start**.
- In the event's **Event tab**, the four fields shown: **Parent PID, Command line, Current directory, Environment** — use the command line + current directory to see what it actually ran and from where.

## Notes from doing it
- These processes may not appear on a clean baseline machine — their presence is itself the anomaly (baseline first).
- **Process Explorer** was being killed by the WMI backdoor (see [WMI Backdoor](./03-wmi-backdoor.md)), so Procmon/Autoruns carried the analysis. If one Sysinternals tool won't stay open, suspect an anti-analysis mechanism rather than a broken tool.

Lesson: Procmon's per-process filter + parent PID + the Event tab's command line/working dir is the fast way to confirm what a short-lived process is doing and who launched it.
