# 02 — Logging & SIEM

Log collection and analysis is critical to detect malicious activity quickly — sometimes audit records are the only evidence of a successful attack. Attackers know this and try to hide their location, malware, and activity in/around the logs.

## Two kinds of logs
- **System logs** — system-level events (process start/end, crashes). Native to systems, less config to turn on.
- **Audit logs** — user-level events (user logged in, accessed a file). More planning/effort to set up.

## Event types worth logging/alerting on
Password changes · unauthorized logins · login failures · new login events · malware detection · malware attacks · firewall port scans · DoS · filename changes · file-integrity changes · data exported · new processes started / running processes stopped · shared-access events · disconnected events · new service installation · new user accounts · modified registry values.

## Syslog
- Universal protocol for collecting/transmitting system and network event info — a common language for routers, switches, firewalls, Linux/Unix servers, and apps to generate, relay, and store logs in a consistent, analyzable format.
- Linux: **rsyslog**; config in **`/etc/rsyslog.conf`** (logs by facility, e.g. `auth,authpriv.* -> /var/log/auth.log`).
- Network gear emits structured syslog (e.g. Cisco firewall messages with mnemonic + severity + description) — feed these into the SIEM.

## Sysmon (Windows System Monitor)
Sysinternals tool that massively enriches Windows logging:
- Logs process creation with **full command line** for both current and parent processes.
- Records process-image **hashes** (SHA1 default; MD5/SHA256/IMPHASH).
- **Process GUID** in create events → correlate even when Windows reuses PIDs; **session GUID** → correlate events on the same logon session.
- Logs **driver/DLL loads** with signatures and hashes.
- Detects **file-creation-time changes** (timestomping is a common anti-forensics trick).
- Generates events from early in boot to catch kernel-mode malware.

## Zeek
- Free, open-source network analysis framework / network security monitor (also usable as a NIDS).
- Produces an extensive set of logs: every connection on the wire, all HTTP sessions (URIs, key headers, MIME types, responses), DNS requests+replies, SSL certs, key SMTP content, and more.
- Writes tab-separated or JSON logs for post-processing; can feed external databases or a SIEM.

## SIEM — Wazuh
- **SIEM** (Security Information and Event Management): collects logs, converts records into usable info, provides real-time monitoring/analysis, and alerts on rule violations / attacks. Logs from firewalls, desktops, etc. land in a centralized DB and are summarized for visibility.
- **Wazuh** — free, open-source platform combining **SIEM** + **XDR**. Architecture:
  - **Wazuh agent** — lightweight, on endpoints (Windows/Linux/macOS/HP-UX/Solaris/AIX); modules include active response, command execution, config assessment, container/cloud security, **file integrity monitoring**, log collector, **malware detection**, system inventory. Provides prevention, detection, and response.
  - **Wazuh server** — analyzes agent data with decoders + rules and threat intel to hunt known IOCs; clusters to scale to thousands of agents.
  - **Wazuh indexer** — indexes/stores alerts; Kibana integration for visualization/analysis.
  - **Wazuh dashboard** — web UI for alerts, data, and config.
  - **Agent-less devices** (firewalls, switches, routers, network IDS) are monitored via **syslog**.
