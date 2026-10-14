# Blue Team Notes

A clean, sectioned defensive reference — the mirror image of an offensive playbook. Where a red-team note asks *"how do I get in?"*, each note here asks *"how would I see it, stop it, and respond?"* Distilled from HTB/CPTS coursework, CCDC-style blue-team practice, and lab notes.

Each stage folder holds a set of `.md` files covering one focused topic; sections mirror the defender's lifecycle from visibility through hardening, detection, and incident response.

---

## Master Directory

| # | Stage | What lives here |
|---|-------|-----------------|
| 1 | [Visibility & Asset Baseline](./1-visibility-and-baseline/) | Asset inventory, network visibility, logging baseline, log sources, AD visibility |
| 2 | [Hardening & Prevention](./2-hardening/) | Vulnerability management, web hardening, credential defense, account & password policy |
| 3 | [Detection Engineering](./3-detection/) | Endpoint detection, SIEM & alerting, network detection, web & AD attack detection |
| 4 | [Incident Response](./4-incident-response/) | Linux & Windows triage, credential-compromise response, persistence hunting, containment |
| 5 | [Threat Hunting & Lateral-Movement Defense](./5-threat-hunting/) | AD monitoring, Kerberos abuse detection, ACL-change auditing, pivot detection |
| 7 | [Runbooks](./7-runbooks/) | Actionable "when the alert fires, run this" playbooks by phase |

---

## Full Section Index

### 1. Visibility & Asset Baseline
- [01 - Asset Inventory](./1-visibility-and-baseline/01-asset-inventory.md)
- [02 - Network Visibility](./1-visibility-and-baseline/02-network-visibility.md)
- [03 - Logging Baseline](./1-visibility-and-baseline/03-logging-baseline.md)
- [04 - Service Inventory & Attack Surface](./1-visibility-and-baseline/04-service-inventory.md)
- [05 - Log Sources & Retention](./1-visibility-and-baseline/05-log-sources.md)
- [06 - Active Directory Visibility](./1-visibility-and-baseline/06-active-directory-visibility.md)

### 2. Hardening & Prevention
- [01 - Vulnerability Management](./2-hardening/01-vulnerability-management.md)
- [02 - Web Hardening](./2-hardening/02-web-hardening.md)
- [03 - Credential Defense](./2-hardening/03-credential-defense.md)
- [04 - Account & Password Policy](./2-hardening/04-account-password-policy.md)

### 3. Detection Engineering
- [01 - Endpoint Detection](./3-detection/01-endpoint-detection.md)
- [02 - SIEM & Alerting](./3-detection/02-siem-and-alerting.md)
- [03 - Network Detection](./3-detection/03-network-detection.md)
- [04 - Web Attack Detection](./3-detection/04-web-attack-detection.md)
- [05 - AD Attack Detection](./3-detection/05-ad-attack-detection.md)
- [06 - Container & Cloud Defense](./3-detection/06-container-defense.md)
- [07 - Common Application Monitoring](./3-detection/07-common-app-monitoring.md)

### 4. Incident Response
- [01 - Linux Triage](./4-incident-response/01-linux-triage.md)
- [02 - Windows Triage](./4-incident-response/02-windows-triage.md)
- [03 - Credential Compromise Response](./4-incident-response/03-credential-compromise-response.md)
- [04 - Persistence Hunting](./4-incident-response/04-persistence-hunting.md)
- [05 - Containment & Eradication](./4-incident-response/05-containment-eradication.md)
- [06 - Forensic Preservation](./4-incident-response/06-forensic-preservation.md)
- [07 - Linux Live Forensics & Artefact Hunting](./4-incident-response/07-linux-live-forensics.md)

### 5. Threat Hunting & Lateral-Movement Defense
- [01 - AD Monitoring Overview](./5-threat-hunting/01-ad-monitoring-overview.md)
- [02 - AD Protocol Monitoring](./5-threat-hunting/02-ad-protocol-monitoring.md)
- [03 - Kerberos Attack Detection](./5-threat-hunting/03-kerberos-attack-detection.md)
- [04 - ACL & Object Change Auditing](./5-threat-hunting/04-acl-change-auditing.md)
- [05 - Lateral Movement Detection](./5-threat-hunting/05-lateral-movement-detection.md)

### 7. Runbooks
- [00 - Methodology & Setup](./7-runbooks/00-methodology.md)
- [01 - Triage](./7-runbooks/01-triage.md)
- [02 - Web Incident](./7-runbooks/02-web-incident.md)
- [03 - Active Directory Incident](./7-runbooks/03-active-directory-incident.md)
- [04 - Linux Compromise](./7-runbooks/04-linux-compromise.md)
- [05 - Windows Compromise](./7-runbooks/05-windows-compromise.md)
- [06 - Credential Incident](./7-runbooks/06-credential-incident.md)
- [07 - Containment](./7-runbooks/07-containment.md)

---

## Conventions

- All files are standard Markdown (`.md`) for direct rendering on GitHub.
- Each file opens with a short summary, then practical content organized by tool, log source, or technique.
- Code blocks are fenced with `bash`, `powershell`, `splunk`, `sql`, etc. so syntax highlighting works on GitHub.
- Placeholders use `<angle-brackets>` (e.g. `<dc-ip>`, `<domain>`, `<user>`) — replace with environment values.
- Detections reference **MITRE ATT&CK** technique IDs (e.g. `T1558.003`) and, where relevant, Windows Event IDs and Sysmon Event IDs.

## Layout

```
blue_team_notes/
├── README.md                       ← this file (master directory)
├── 1-visibility-and-baseline/
│   ├── README.md                   ← stage index
│   ├── 01-asset-inventory.md
│   ├── 02-network-visibility.md
│   └── ...
├── 2-hardening/
├── 3-detection/
├── 4-incident-response/
├── 5-threat-hunting/
├── 7-runbooks/                     ← actionable playbooks by phase
└── _archive/                       ← original source material
```

## Acknowledgements

Structured as the defensive counterpart to a red-team notes repo. Content distilled from personal coursework, HTB blue-team labs, CCDC-style defensive practice, and the MITRE ATT&CK framework.
