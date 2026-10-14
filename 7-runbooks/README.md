# Runbooks

Practical "when the alert fires, run this" playbooks by phase. Each file is a topical checklist — not a curriculum. Every item is something to actually **do**, in order of highest expected value.

The main notes (`1-` through `5-`) explain *how* each defensive technique works. **This section is the reflex layer** — when an alert fires at 2am, open the matching runbook, work top-to-bottom, tick items as you go.

## General Reminders

- **Scope before you contain.** Isolating one box while five others are compromised warns the attacker. See [Containment](../4-incident-response/05-containment-eradication.md).
- **Preserve before you poke.** Memory and volatile state die on reboot/isolation — capture them first if the incident may matter later.
- **Never rabbit-hole.** If a lead isn't producing after 45 minutes, note it and move to the next item.
- **Everything goes in the case log** with UTC timestamps — every command you run, every finding, every decision and who made it.
- **One source of truth for IOCs**: keep `iocs.txt` (hashes, IPs, domains, accounts) and sweep every new IOC across the whole estate.

## Index

| # | File | Trigger |
|---|------|---------|
| 00 | [Methodology & Setup](./00-methodology.md) | Before the incident / standing readiness |
| 01 | [Triage](./01-triage.md) | An alert fired — is it real? |
| 02 | [Web Incident](./02-web-incident.md) | Suspected web compromise / webshell |
| 03 | [Active Directory Incident](./03-active-directory-incident.md) | AD attack signal (roast, DCSync, spray) |
| 04 | [Linux Compromise](./04-linux-compromise.md) | Suspicious Linux host |
| 05 | [Windows Compromise](./05-windows-compromise.md) | Suspicious Windows host |
| 06 | [Credential Incident](./06-credential-incident.md) | Creds suspected stolen |
| 07 | [Containment](./07-containment.md) | Confirmed intrusion — remove the attacker |

## Quick decision tree

```
Alert fired?                 → 01-triage.md
Web app / webshell?          → 02-web-incident.md
Kerberos / DCSync / spray?   → 03-active-directory-incident.md
Suspect host (Linux)?        → 04-linux-compromise.md
Suspect host (Windows)?      → 05-windows-compromise.md
Creds stolen?                → 06-credential-incident.md
Confirmed intrusion?         → 07-containment.md
```
