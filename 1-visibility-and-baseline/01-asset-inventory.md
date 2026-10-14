# 01 — Asset Inventory

An authoritative inventory is the foundation of every other control. An alert on an IP means nothing if you don't know what that IP *is*, who owns it, and whether it should exist.

## What to track per asset
- Hostname, all IPs/MACs, OS + version, physical/virtual/cloud.
- Owner (team + human), business function, data sensitivity.
- Is it internet-facing? What's the known-good open-port set?
- Last-seen, patch level, EDR/agent installed (yes/no).

## Discovery sources (correlate, don't trust one)
- **DHCP + DNS logs** — cheap, continuous, catches new hosts fast.
- **AD computer objects** — `Get-ADComputer -Filter * -Properties lastLogonTimestamp`.
- **Authenticated scans** (your own, scheduled) — Nmap/Nessus against known ranges.
- **EDR/agent console** — anything with a sensor is inventoried automatically; the gap is the risk.
- **Cloud provider API** — AWS `describe-instances`, Azure Resource Graph.

```bash
# Quick live-host sweep of a known range, dump to inventory delta
nmap -sn 10.0.0.0/24 -oG - | awk '/Up$/{print $2}' > seen.txt
# Compare against your authoritative list
comm -13 <(sort inventory.txt) <(sort seen.txt)   # hosts seen but NOT in inventory = investigate
```

## Drift detection
- Any host that appears on the wire but not in inventory is **rogue until proven otherwise**. Triage within the hour.
- Any inventoried host that stops reporting its EDR/agent is a blind spot — alert on agent silence, not just agent alerts.
- Schedule a weekly diff; the delta is your to-do list.

## Why this is the first file
Every downstream note assumes you can answer "what is `<ip>`?" in seconds. If you can't, fix that before building detections.
