# 01 — Registry Run-Key Persistence

Finding an encoded payload planted in the registry for persistence, via its Sysmon log.

## The artefact
Encoded payload stored in the registry key (full path):
```
HKCU\Software\Microsoft\Windows\CurrentVersion\Debug
```

## The Sysmon event that caught it
In **Event Viewer** → `Applications and Services Logs` → `Microsoft-Windows-Sysmon/Operational`:
- **Event ID 13** — **SetValue** (registry value set). Sysmon tags registry-persistence writes with a rule name.
- Rule name: **`T1547.001`** (Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder).
- Tactics for that ATT&CK ID: **Persistence, Privilege Escalation**.
- Event UTC time: `2021-01-22 01:08:13.468`.

Lesson: Sysmon EID 13 is the registry-write signal; a good Sysmon config labels the event with the ATT&CK technique (T1547.001 here), so the log tells you both *what* and *which technique*.

## Decoding the payload
Copy the encoded value out and decode it (e.g. **CyberChef** — "From Base64", and un-wrap any gzip/PowerShell `-enc` UTF-16LE layers). Decoded, this payload:
- Starts the **Fax** service.
- Opens local port **9299**.
- Terminates the process **`FXSSVC`** (the Fax service executable).
- Removes the DLL **`C:\Windows\System32\ualapi.dll`**.

Those steps line up with the PrintDemon spooler abuse → see [PrintDemon](./02-printdemon-spooler.md).
