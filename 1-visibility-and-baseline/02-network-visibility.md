# 02 — Network Visibility

If traffic can move without being observed, an attacker's lateral movement is invisible. Map how you see packets and flows across every segment.

## Vantage points
- **North-south** (perimeter): firewall logs, proxy logs, IDS at the egress. Catches C2, exfil, inbound scans.
- **East-west** (internal): SPAN/TAP at core switches, NetFlow/IPFIX from routers. Catches lateral movement — the part most orgs are blind to.
- **Host-level**: Sysmon Event ID 3 (network connection) on endpoints fills gaps where you have no tap.

## NetFlow as a cheap baseline
Flow data (who talked to whom, how much, when) is tiny compared to full PCAP and answers most hunting questions.

```bash
# With nfdump: top talkers to a suspect host in the last hour
nfdump -R /var/flows -t "$(date -d '1 hour ago' +%Y/%m/%d.%H:%M:%S)" \
  "dst ip <suspect-ip>" -s srcip/bytes -n 20
```

## Segmentation map
- Document which VLANs/subnets *should* be able to reach which. The map is a detection rule: workstation subnet talking SMB to another workstation is abnormal in most designs.
- Known-good flows become allowlists; everything else is a hunting lead.

## Encryption reality
- You won't decrypt most traffic. Lean on metadata: JA3/JA3S TLS fingerprints, SNI, cert details, flow size/timing. Beaconing shows up in flow periodicity even when payload is opaque.
