# 01 — Asset Inventory

An authoritative inventory is the foundation of every other control. An alert on an IP means nothing if you don't know what that IP *is*, who owns it, and whether it should exist. CIS Control 1 puts this first for a reason: unknown assets are where incidents incubate.

## What to track per asset
- **Identity**: hostname, all IPs/MACs, FQDN, serial/asset tag.
- **Platform**: OS + build/patch level, physical / virtual / cloud / container.
- **Ownership**: owning team + a named human, business function, data classification.
- **Exposure**: internet-facing? known-good listening-port set? management network only?
- **Coverage**: EDR/agent installed, log-forwarding on, vuln-scan in scope, backup in scope. Each "no" is a measured blind spot.
- **Lifecycle**: build date, last-seen, decommission date. Stale-but-live is a classic forgotten-asset risk.

## Discovery sources (correlate — never trust one)
No single source is complete; the *gaps between* sources are where shadow IT and attacker infrastructure hide.
- **DHCP + DNS logs** — cheap, continuous, fastest signal of a new host joining.
- **AD / LDAP** — `Get-ADComputer -Filter * -Properties lastLogonTimestamp,operatingSystem,whenCreated`.
- **Authenticated scans** (scheduled) — Nmap/Nessus/OpenVAS against known ranges; authenticated beats unauthenticated for OS/patch truth.
- **EDR/agent console** — anything with a sensor is inventoried automatically; the delta vs the network is the risk.
- **Cloud provider API** — AWS `ec2 describe-instances`, Azure Resource Graph, GCP asset inventory. Cloud assets churn hourly; poll, don't snapshot once.
- **Switch/ARP/CAM tables & 802.1x** — ground truth of what is physically plugged in.

```bash
# Live-host sweep of a known range, compared to the authoritative list
nmap -sn 10.0.0.0/24 -oG - | awk '/Up$/{print $2}' | sort -u > seen.txt
comm -13 <(sort inventory.txt) seen.txt    # seen but NOT inventoried = rogue, triage now
comm -23 <(sort inventory.txt) seen.txt    # inventoried but silent = decommissioned? or agent killed?
```
```powershell
# AD computers not seen in 30 days (stale objects / possible rogue reuse)
$cut=(Get-Date).AddDays(-30)
Get-ADComputer -Filter * -Properties lastLogonTimestamp,operatingSystem |
  Select Name,operatingSystem,@{n='LastLogon';e={[datetime]::FromFileTime($_.lastLogonTimestamp)}} |
  Where {$_.LastLogon -lt $cut} | Sort LastLogon
```

## Classification drives everything downstream
Tag each asset with data sensitivity and a tier (0/1/2). Detection severity, containment urgency, and patch priority all key off these tags — an alert on a tier-0 box is a different night than the same alert on a lab VM.

## Drift detection (operationalize it)
- Any host on the wire but not in inventory is **rogue until proven otherwise** — triage within the hour.
- Any inventoried host whose **EDR/agent goes silent** is a blind spot; alert on agent silence, not just agent alerts (attackers kill sensors first).
- Schedule a weekly automated diff; the delta is your to-do list. Feed new legitimate assets back from change management so the diff stays signal, not noise.

## Why this is the first file
Every downstream note assumes you can answer "what is `<ip>`?" in seconds, with owner and tier. If you can't, fix that before building detections — a detection you can't attribute to an asset is an alert you can't action.
