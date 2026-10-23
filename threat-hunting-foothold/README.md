# Threat Hunting: Foothold (Elastic Stack)

Notes from the TryHackMe **Threat Hunting: Foothold** room — hunting indicators of initial user/host compromise in the Elastic Stack (Kibana), walking the ATT&CK tactics an attacker uses to get and keep a foothold. Scenario data is from July 3, 2023 across a jumphost, a web app (web01), and employee workstations (WKSTN-*).

## Sections
0. [Elastic Basics](./00-elastic-basics.md) — Kibana tools, beats indices, KQL, how I hunt.
1. [Initial Access (TA0001)](./01-initial-access.md) — SSH brute force, web RCE, phishing.
2. [Execution (TA0002)](./02-execution.md) — command-line tools, LOLBAS, scripting tools.
3. [Defence Impairment (TA0112)](./03-defence-impairment.md) — disabling AV, clearing logs, process injection.
4. [Persistence (TA0003)](./04-persistence.md) — scheduled tasks, registry autoruns.
5. [Command & Control (TA0011)](./05-command-and-control.md) — C2 over DNS, cloud apps, encrypted HTTP.
