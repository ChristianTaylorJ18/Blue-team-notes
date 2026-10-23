# 02 — PrintDemon Spooler Abuse

The decoded payload's Fax/spooler actions point at a print-spooler persistence/privesc abuse (PrintDemon).

## Why Fax + ualapi.dll
> Added context (not stated verbatim in the room): this maps to **PrintDemon (CVE-2020-1048)**, print-spooler abuse. Dropping/removing a DLL the spooler loads (like `ualapi.dll`, a known spooler-loaded DLL) is how the technique gets code executed as SYSTEM and persists.

The payload (from [section 01](./01-registry-runkey-persistence.md)) started **Fax**, killed **FXSSVC**, and removed **`C:\Windows\System32\ualapi.dll`** — spooler-adjacent actions to set up the malicious printer.

## The spooler event
In **Event Viewer**, the print service log shows:
- **Windows Event ID 823** (print-service configuration change).
- **New Default Printer**: **`PrintDemon`**.
- Associated process: **`spoolsv.exe`** (the Print Spooler service).
- Parent PID of `spoolsv.exe`: **620**.

Lesson: a new/odd default printer in the print-service event log, tied to `spoolsv.exe`, is the fingerprint of spooler abuse. Check the PrintService operational/admin logs when the spooler is involved.
