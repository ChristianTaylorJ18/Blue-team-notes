# 04 — Process Injection

A second process reaching the same attacker host led to a CreateRemoteThread injection chain.

## The second process calling home
- **`Explorer.exe`**, **PID 2684**, also connected to the attacker FQDN — suspicious, because Explorer has no reason to make external connections. That's the sign code was injected into it.
- First image loaded by that process: **`C:\Windows\System32\mscoree.dll`** — the .NET runtime loader, i.e. .NET/PowerShell code was loaded into Explorer.

## The injection event (Sysmon)
Between the two processes, Sysmon logged:
- **CreateRemoteThread** — **Event ID 8** (one process created a thread in another — classic injection).
- First event UTC time: `2021-01-22 01:07:06.182` (local on the box: `1/21/2021 5:07:06 PM`).
- In **Process Monitor**, filtering the 2nd process from that time, the first operation was **Thread Create**.

## Recon the attacker ran
Registry path queried to fingerprint the victim's Windows version:
```
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ReleaseID
```
(The last module in that event's stack with a successful result showed as `<unknown>`.)

## Attribution
- Empire module most likely used between the two processes: **`Invoke-PSInject`**.
- MITRE technique: **T1055** (Process Injection).

Lesson: a core process (Explorer) making network connections + loading `mscoree.dll` + a Sysmon **EID 8 CreateRemoteThread** into it = process injection. Sysmon EID 8 is the key injection signal; correlate the source/target PIDs to see who injected into what.
