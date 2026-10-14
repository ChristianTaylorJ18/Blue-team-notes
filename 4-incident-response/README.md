# 4. Incident Response

The mirror of post-exploitation: once an attacker has a foothold, this is how you find them, understand what they did, and remove them. Work calmly and in order — rushed eradication tips off the attacker and destroys evidence.

## Sections
1. [Linux Triage](./01-linux-triage.md) — live-response collection and what to check first on a Linux host.
2. [Windows Triage](./02-windows-triage.md) — the same for Windows: processes, autoruns, artifacts.
3. [Credential Compromise Response](./03-credential-compromise-response.md) — what to rotate, in what order, after creds are stolen.
4. [Persistence Hunting](./04-persistence-hunting.md) — finding the mechanisms that survive a reboot.
5. [Containment & Eradication](./05-containment-eradication.md) — isolate, scope, remove, verify.
6. [Forensic Preservation](./06-forensic-preservation.md) — order of volatility, imaging, chain of custody.

> **Scope before you swing.** Isolating one box while missing the other five hands the attacker a warning and keeps them in. Understand the blast radius first.
