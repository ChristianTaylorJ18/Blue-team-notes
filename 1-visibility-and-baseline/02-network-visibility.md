# 02 — Network Visibility

If traffic can move without being observed, an attacker's lateral movement is invisible. Map how you see packets and flows across every segment, and treat the blind spots as explicitly as the covered ones.

## Vantage points (you need all three)
- **North-south** (perimeter): firewall, proxy, egress IDS. Catches C2, exfil, inbound scanning. Most orgs have this.
- **East-west** (internal): SPAN/TAP at core/distribution switches, NetFlow/IPFIX from L3 devices. Catches lateral movement — the part most orgs are blind to and the part that matters most after initial access.
- **Host-level**: Sysmon Event ID 3 (network connection) and EDR flow telemetry fill gaps where you have no tap (cloud, remote, micro-segmented).

## Data types, cheapest to richest
| Type | Cost | Answers |
|------|------|---------|
| Flow (NetFlow/IPFIX/Zeek conn.log) | low | who↔who, how much, when, how often |
| Protocol metadata (Zeek logs, JA3/JA3S, SNI, DNS, HTTP, x509) | medium | what service, what TLS fingerprint, what domain/cert |
| Full PCAP | high | exact payload — keep targeted/rolling, not everywhere |

Flow is the workhorse: tiny to store, answers most hunting questions, and reveals beaconing periodicity even when payloads are encrypted.

```bash
# Top talkers to a suspect host in the last hour (nfdump)
nfdump -R /var/flows -t "$(date -d '1 hour ago' +%Y/%m/%d.%H:%M:%S)" \
  "dst ip <suspect-ip>" -s srcip/bytes -n 20
# Long-lived connections (possible tunnels/C2) — Zeek conn.log, duration desc
zeek-cut id.orig_h id.resp_h id.resp_p duration orig_bytes resp_bytes < conn.log \
  | sort -k4 -nr | head
```

## Segmentation map = detection content
Document which VLANs/subnets *should* reach which. The map becomes rules:
- Workstation→workstation SMB/RDP/WinRM is abnormal in most designs — alert on it.
- Server segment reaching the internet on new ports/destinations is suspect.
- Anything reaching tier-0 (DCs, PKI, backup) from outside the admin network is high-signal.
Known-good flows become allowlists; everything else is a hunting lead.

## Encryption reality
You won't decrypt most traffic, and shouldn't need to. Lean on metadata: JA3/JA3S TLS fingerprints (malware families reuse them), SNI/cert anomalies (self-signed, brand-new domains, mismatched CN), and flow shape. Beaconing shows up as periodicity + uniform size in flow data regardless of payload. Where you *do* break TLS (perimeter decrypt), feed it to the IDS and the proxy logs.

## Close the blind spots deliberately
- VPN/remote users, cloud VPCs, container overlays, and OT/IoT segments are common gaps — list each and state how (or whether) you see it.
- A documented blind spot is a risk decision; an undocumented one is a surprise during an incident.
