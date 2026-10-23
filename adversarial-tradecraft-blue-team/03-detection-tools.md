# 03 — Detection Tools

Endpoint and network detection — EDR on the host, IDS/IPS on the wire.

## EDR (Endpoint Detection and Response)
- **Continuous monitoring** — records system-level behaviors across all endpoints, establishing a baseline of normal.
- **Threat detection** — behavioral analysis to spot anomalies, fileless malware, or unauthorized use of legitimate system tools (LOLBins).
- **Automated & manual response** — can auto-isolate compromised devices to stop lateral movement, terminate malicious processes, and guide remediation to a safe state.
- **Investigation & forensics** — root-cause tools (process trees, timelines) to dissect how an attack happened and what was impacted.
- Data EDR collects: user accounts that logged in; changes to service-provider keys/executables and admin-tool usage; process executions; file creation (incl. `.zip`/`.rar`); removable-media (USB) usage; all local/external addresses that connected to the host.
- Open-source option: **Wazuh** (SIEM + XDR) — see [Logging & SIEM](./02-logging-and-siem.md).

## IDS/IPS — Snort
Open-source network intrusion detection/prevention (by Cisco). Real-time traffic analysis, packet logging, content matching.

A Snort rule = **Rule Header** + **Rule Options**:
```
alert icmp 192.168.1.10 any -> any any (msg:"ICMP Attempt Attack"; sid:1000005)
<action><proto><srcIP><srcPort> <dir> <dstIP><dstPort> ( <options> )
```
Header fields: **action** (e.g. `alert`), **protocol** (tcp/udp/icmp/ip), **source address**, **source port**, **direction** (`->`), **destination address**, **destination port**. Options: `msg`, `sid`, `content`, `flow`, `reference`, `classtype`, `rev`, etc.

Example:
```
alert tcp any 21 -> 10.199.12.8 any (msg:"TCP Packet is detected"; sid:1000001)
```
Richer example (from Snortology):
```
alert tcp $EXTERNAL_NET $HTTP_PORTS -> $HOME_NET any (msg:"BROWSER-IE ... exploit attempt"; flow:to_client,established; content:"recordset"; reference:cve,2016-8077; classtype:attempted-user; sid:65535; rev:1;)
```
`$HOME_NET` / `$EXTERNAL_NET` / `$HTTP_PORTS` are variables. A matching alert shows the triggering rule + full packet payload (e.g. in a Sguil console).

## IDS/IPS — Suricata (alternative to Snort)
Far more than an IDS/IPS:
- **IDS** — passively monitors traffic for suspicious activity, known malware signatures, and policy violations; logs alerts.
- **IPS** — deployed inline, actively drops/blocks/resets malicious traffic before it breaches the perimeter.
- **Deep Packet Inspection (DPI)** — examines packet contents, not just headers.
- **File extraction** — identifies and extracts files (e.g. malicious executables) traversing the network for deeper analysis.
- Also produces IDS alerts, protocol transactions, network flows, and PCAP recordings.
