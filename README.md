# Blue Team Notes

My blue-team notes, as I actually work through the material. Defensive counterpart to my red-team notes — same idea, same format, but only things I've genuinely learned go in here.

## Contents

| Topic | Source | What it covers |
|-------|--------|----------------|
| [Linux File System Analysis](./linux-file-system-analysis/) | TryHackMe room | Live Linux forensics: find an attacker's artefacts, read timestamps, hunt backdoor accounts/persistence, check binary integrity, sweep for rootkits |
| [Linux Process Analysis](./linux-process-analysis/) | TryHackMe room | Process & persistence analysis on Linux: ps/lsof/pstree/top, cronjobs, services, autostart scripts, application artefacts |
| [Investigating Windows 2.0](./investigating-windows/) | TryHackMe room | Windows IR: scheduled-task + registry persistence, LOKI IOC scans, WMI event-subscription backdoors, Sysinternals process analysis, YARA rules |
| [Investigating Windows 3.x](./investigating-windows-3/) | TryHackMe room | Windows IR via event logs: Sysmon run-key persistence, decoding payloads, PrintDemon spooler abuse, Empire C2 profile, process injection |
| [Threat Hunting: Foothold (Elastic)](./threat-hunting-foothold/) | TryHackMe room | Hunting initial compromise in the Elastic Stack (Kibana / KQL) across the ATT&CK tactics: initial access, execution, defence impairment, persistence, C2 |
| [Adversarial Tradecraft — Blue Team](./adversarial-tradecraft-blue-team/) | CIS4930 class | Defensive content from my Cyber Adversarial Tradecraft course: preparing for battle / runbooks, logging & SIEM, detection tools (EDR/IDS), analysis tools |

*More topics get added here as I complete them.*

## Conventions
- Standard Markdown (`.md`) so it renders on GitHub.
- Each file: short summary, then the commands/queries/lessons, copy-paste-ready.
- Placeholders in `<angle-brackets>`.
