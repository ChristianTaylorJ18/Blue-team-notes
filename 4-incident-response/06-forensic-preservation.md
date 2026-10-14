# 06 — Forensic Preservation

If the incident might go to legal, insurance, or just needs an accurate timeline, evidence handling matters. Collect in order of volatility; prove nothing changed after collection.

## Order of volatility (collect most-volatile first)
1. CPU/registers, RAM (live memory capture).
2. Network state (connections, ARP, routing).
3. Running processes, open files, logged-on users.
4. Disk (forensic image).
5. Remote/archived logs, physical config.

## Memory first, if the box is still live
```bash
# Linux (AVML is simple and reliable)
./avml mem.lime
# Windows: WinPmem / Magnet RAM Capture → image.raw
```
Memory holds injected code, decrypted payloads, keys, and C2 config that never touch disk. Capture it before isolating/powering down.

## Disk imaging
- Write-blocker for physical; `dd`/`ewfacquire` for raw/E01. Image, don't work on the original.
- Hash before and after: the acquisition hash proves integrity.
```bash
dd if=/dev/sdX of=/evidence/host.img bs=4M conv=sync,noerror status=progress
sha256sum /evidence/host.img | tee /evidence/host.img.sha256
```

## Chain of custody
- Record: what, who collected it, when (UTC), from where, and every handoff. One tamper-evident log per item.
- Store evidence read-only, access-controlled, with the hashes. If a hash can't be reproduced later, the evidence is contestable.

## Cloud / ephemeral
- Snapshot volumes before terminating instances; export the relevant audit logs immediately (they age out). For containers, capture the image + runtime state before the pod is rescheduled.

## Timeline
- Normalize everything to UTC and build a super-timeline (e.g. Plaso/`log2timeline`) merging filesystem, registry/journal, and log events. The timeline is what turns artifacts into a story.
