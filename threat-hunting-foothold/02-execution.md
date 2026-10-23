# 02 — Execution (TA0002)

Running malicious code through tools already on the host. All queries use `winlogbeat-*`.

## Command-line tools (EID 1 = process creation)
```kql
host.name: WKSTN-* AND winlog.event_id: 1 AND process.name: (cmd.exe OR powershell.exe)
```
Columns: `winlog.computer_name`, `user.name`, `process.parent.command_line`, `process.command_line`. Red flag: `cmd.exe` spawned by `C:\Windows\Temp\installer.exe` — a payload running from a temp folder.

## PowerShell script-block logging (EID 4104)
```kql
host.name: WKSTN-* AND winlog.event_id: 4104
```
Column: `powershell.file.script_block_text`. Noisy — minus-filter benign repeats (e.g. `Set-StrictMode`) to clear the view. Found **Invoke-Empire** (Empire C2 agent signature) on WKSTN-1.

**PowerShell malicious-string indicators** (validate, some are legit admin use):
`invoke` / `invoke-expression` / `iex`, `-enc` / `-encoded`, `-noprofile` / `-nop`, `bypass`, `-c` / `-command`, `-executionpolicy` / `-ep`, `WebRequest`, `Download`.

## LOLBAS / built-in binaries (EID 1 or 3)
```kql
host.name: WKSTN-* AND winlog.event_id: (1 OR 3) AND (process.name: (mshta.exe OR certutil.exe OR regsvr32.exe) OR process.parent.name: (mshta.exe OR certutil.exe OR regsvr32.exe))
```
Including `process.parent.name` catches child processes these tools spawn. Columns add `destination.ip`. Findings:
- **certutil** downloaded `installer.exe` into `C:\Windows\Temp`.
- **regsvr32** pulled a remote `teams.sct` and spawned encoded PowerShell.
- **mshta** spawned encoded PowerShell.

## Scripting / programming tools (EID 1 or 3)
```kql
host.name: WKSTN-* AND winlog.event_id: (1 OR 3) AND (process.name: (*python* OR *php* OR *nodejs*) OR process.parent.name: (*python* OR *php* OR *nodejs*))
```
Columns add `destination.ip`, `destination.port`. Python spawned `cmd.exe` and connected to `167.71.198.43:8080`. Grab that Python-spawned cmd's PID, then pull its children:
```kql
host.name: WKSTN-* AND winlog.event_id: (1 OR 3) AND process.parent.pid: 1832
```
`dev.py` was a Python reverse shell. Lesson: scripting interpreters making network connections + spawning `cmd` = reverse shell; pivot on PID to follow the chain.
