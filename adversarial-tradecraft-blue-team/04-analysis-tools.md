# 04 — Analysis Tools

Workflow: **get local telemetry → investigate a suspicious process → analyze an artifact.**

## Windows Sysinternals
A collection of ~70 free Microsoft utilities to monitor, diagnose, and troubleshoot Windows; each is a standalone exe (no install). Key ones by category:
- **File & Disk**: `DiskMon` (capture hard-disk activity), `DiskUsage` (disk usage by directory).
- **Networking**: `TCPView` (TCP/UDP endpoints), `PsTools` (list/run processes on local + remote systems).
- **Processes**: `Process Explorer` (files, registry keys, objects a process has open), `Process Monitor` (real-time file-system/registry/process activity).
- **Security**: `LogonSessions` (active logon sessions), `Autoruns` (apps that start automatically at boot).
- **System Info**: `Coreinfo` (logical↔physical processor mapping), `Handle` (which files are open by which processes).

## YARA — identify & classify malware (pattern matching)
Rule anatomy:
```yara
rule PlayForESXi : ransomware esxi play {
    meta:
        description = "Detects PLAY ransomware targeting ESXi Hypervisors"
        date = "2025-01"
        filetype = "elf"
        maltype = "ransomware"
    strings:
        $encrypt_str = "encrypt:"
        $vmfs_path_str = "/vmfs/volumes"
        $PLAY_ext_str = ".PLAY" fullword
        // ... observable artifacts of the malware
    condition:
        all of them
}
```
- **Rule name** — unique primary identifier; should be descriptive.
- **Tags** (after the `:`) — categorize rules for operational use. Run a tag with: `yara -t ransomware rules.yar /path/to/files`
- **Meta** — descriptive context for analysts (description, date, filetype, author, reference, md5…).
- **Strings** — the core detection elements / observable artifacts; text, hex byte patterns, or regex. `fullword` matches whole words.
- **Condition** — mandatory logical expression that decides when the rule matches (a file/process/memory/stream). Shorthands: `all of them`, `one of them`, `$a or $b or $c`, and combos like `pe.*` checks with `import pe`.
- **Rule repositories** exist, e.g. `https://github.com/pedramamini/awesome-yara#rules`.

## Binwalk — what if YARA finds something (firmware/binary)
- Searches a binary for embedded files and executable code; designed for finding files/code inside firmware images (a firmware image = snapshot of the software/config/filesystem to run a hardware device).
```bash
binwalk -B ddwrt-linksys-wrt1200ac-webflash.bin
# lists DECIMAL / HEX offset / DESCRIPTION (TRX header, uImage, kernel, xz data, dtb, UBI...)
```

## Malware sandbox — what if YARA finds something (executable)
- Put the suspicious file/URL in an **isolated virtual environment** to safely execute and analyze it.
- Online sandboxes: **ANY.RUN**, **Joe Sandbox**.
