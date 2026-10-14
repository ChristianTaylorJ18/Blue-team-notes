# 06 — Rootkits

Two tools from the room for detecting rootkits.

## chkrootkit
```bash
sudo chkrootkit
```
Quick check for known rootkit-related files/patterns. Good for an initial pass; can be evaded by modern rootkits. In this room it detected a suspicious `.sh` file.

## rkhunter (Rootkit Hunter)
```bash
sudo rkhunter --update    # refresh the signature database first (important)
sudo rkhunter -c -sk      # run the check
```
More comprehensive than chkrootkit: compares SHA-1 hashes of core system files against known-good, checks for wrong permissions, hidden files, and suspicious strings in kernel modules. Includes a `(UID 0) accounts` check. Produces a system-check summary.

Use both together — chkrootkit for a fast first look, rkhunter for the thorough assessment.
