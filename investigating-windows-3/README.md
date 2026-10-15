# Investigating Windows 3.x

Notes from the TryHackMe **Investigating Windows 3.x** room — working the endpoint's logs and artefacts to reconstruct the attack. Heavy use of **Windows Event Logs / Event Viewer** and **Sysmon**, decoding an encoded payload, and identifying the C2 framework and a process-injection chain. RDP in as Administrator.

> Note: I couldn't load the linked walkthrough (the Medium URL redirect-loops). These notes are from the room itself plus standard tooling; a couple of added-context lines are flagged inline.

## Sections
1. [Registry Run-Key Persistence](./01-registry-runkey-persistence.md) — Sysmon EID 13, T1547.001, decoding the payload.
2. [PrintDemon Spooler Abuse](./02-printdemon-spooler.md) — spoolsv.exe, Event ID 823, malicious printer.
3. [Empire C2 Profile](./03-empire-c2.md) — default comms profile, URIs, attacker FQDN.
4. [Process Injection](./04-process-injection.md) — CreateRemoteThread, Explorer.exe, Invoke-PSInject.

Prereq rooms: Core Windows Processes, Windows Event Logs, Sysinternals, Sysmon, Yara, MITRE.
