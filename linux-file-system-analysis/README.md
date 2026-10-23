# Linux File System Analysis

Notes from the TryHackMe **Linux File System Analysis** room — performing live forensic file-system analysis on a Linux host to find an attacker's artefacts. Scenario: Penguin Corp's web server had a file-upload vuln that led to root.

Live analysis changes the system (reading a file updates its `atime`; your commands leave history). It's unsafe to remediate a live compromised host for reuse — take forensic backups first, then restore from clean backups for recovery.

## Sections
1. [Investigation Setup](./01-investigation-setup.md) — isolate, back up, work from known-good binaries.
2. [Files, Permissions & Timestamps](./02-files-permissions-timestamps.md) — foothold, ownership, `find`, metadata, checksums, mtime/ctime/atime.
3. [Users & Groups](./03-users-and-groups.md) — UID-0 backdoors, groups, sudoers, login history.
4. [User Directories & Files](./04-user-directories-and-files.md) — `.bash_history`, `.ssh/authorized_keys` abuse.
5. [Binaries & Executables](./05-binaries-and-executables.md) — `find`, `strings`, `debsums`, SUID, checksums.
6. [Rootkits](./06-rootkits.md) — `chkrootkit`, `rkhunter`.
