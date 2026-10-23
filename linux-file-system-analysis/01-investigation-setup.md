# 01 — Investigation Setup

Securing the environment before doing live forensic analysis.

- Acquire backups first, then isolate the system from the network.
- Use **known-good binaries and libraries** — a compromised host may have trojaned tools. Mount a USB with clean Debian-based binaries and copy `/bin`, `/sbin`, `/lib`, and `/lib64` from a clean install to `/mnt/usb` on the affected system.
- Point the shell at the trusted binaries/libraries before investigating:

```bash
export PATH=/mnt/usb/bin:/mnt/usb/sbin
export LD_LIBRARY_PATH=/mnt/usb/lib:/mnt/usb/lib64
check-env
```

Key point from the room: at this stage we're only analysing and identifying artefacts of compromise. It's generally unsafe to remediate the live compromised system for further use — recovery means restoring from backups and doing vulnerability remediation separately.
