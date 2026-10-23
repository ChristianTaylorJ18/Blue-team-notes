# Investigating Windows

Notes from the TryHackMe **Investigating Windows 2.0** room — a deeper IR dive on a compromised Windows host, hunting the attacker's persistence and tooling with Sysinternals, LOKI, and YARA. RDP in as Administrator; the box runs multiple persistence mechanisms and dropped hacktools.

## Sections
1. [Scheduled Task & Registry Persistence](./01-persistence-scheduled-task-registry.md)
2. [LOKI IOC Scan](./02-loki-ioc-scan.md)
3. [WMI Event-Subscription Backdoor](./03-wmi-backdoor.md)
4. [Process Analysis with Sysinternals](./04-process-analysis-sysinternals.md)
5. [Malicious Binaries & Masquerading](./05-malicious-binaries-masquerading.md)
6. [Writing a YARA Rule](./06-yara-rules.md)

Prereq rooms for context: Core Windows Processes, Sysinternals, Yara.
