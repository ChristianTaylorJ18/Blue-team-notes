# 05 — Binaries & Executables

## Find suspicious binaries
Executables owned by root (unauthorized ones are a concern):
```bash
find / -type f -executable -user root 2>/dev/null
```
Refine further by modification time, size, or directory as needed.

## Inspect a binary
```bash
strings example.elf    # human-readable strings: function names, messages, embedded data
```

## Package integrity (debsums)
Verify installed package files against their known-good checksums:
```bash
sudo debsums -e -s     # config files only, silence errors
sudo debsums -c -e     # check only *changed* config files
```
Reported changes indicate files that differ from what the package shipped — possible malicious modification.

## SUID binaries
SetUID executables run with the owner's privileges; unexpected ones (especially in writable dirs like `/tmp`, `/var/tmp`) are suspicious.
```bash
find / -perm -u=s -type f 2>/dev/null
```
Correlate SUID abuse with the user's command history:
```bash
sudo cat /home/jane/.bash_history | grep -B 2 -A 2 "python"
```

## Integrity-check a suspect binary
```bash
md5sum /var/tmp/bash   # e.g. a SUID-root copy of bash dropped for privesc
```
