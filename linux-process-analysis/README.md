# Linux Process Analysis

Notes from the TryHackMe **Linux Process Analysis** room — analysing running processes and application artefacts on a live Linux host to find an attacker's persistence. Scenario: user `janice` compromised, multiple persistence mechanisms planted.

Theme: persistence hides in processes, cronjobs, services, autostart scripts, and app artefacts. Baseline normal first so anomalies stand out, and restore from known-good backups rather than cleaning a live host.

## Sections
1. [Processes](./01-processes.md) — ps, lsof, pstree, top; spotting a bind shell and bad parent-child chains.
2. [Cronjobs](./02-cronjobs.md) — system & user crontabs, cron logs, pspy.
3. [Services](./03-services.md) — systemctl, unit files, journalctl.
4. [Autostart Scripts](./04-autostart-scripts.md) — init/systemd and user `.desktop` autostarts, MOTD.
5. [Application Artefacts](./05-application-artefacts.md) — dpkg, .viminfo, browser artefacts, Dumpzilla.
