# 03 — Network Detection

Mirror of C2, tunneling, and file transfer: what command-and-control and exfiltration look like on the wire, and how to catch them in metadata when you can't see payload.

## Beaconing (C2 callback) — T1071 / T1573
- Signature: regular connections to the same destination at a near-fixed interval (with jitter), often small and uniform in size, persisting over hours/days.
- Hunt with flow **periodicity**, not payload. Tools: Zeek `conn.log` + **RITA** (beacon scoring), Suricata flow records, or your own inter-arrival analysis.

```bash
# Candidate beacons: external dsts with many connections and low byte variance
nfdump -R /var/flows "not dst net 10.0.0.0/8 and (dst port 443 or dst port 80)" \
  -o "fmt:%sa %da %byt" | awk '{c[$1" "$2]++; b[$1" "$2]+=$3} END{for(k in c) if(c[k]>50) print c[k],k}' | sort -rn | head
```
- Low-and-slow beacons (hourly/daily) need **days** of history — another reason retention matters ([log sources](../1-visibility-and-baseline/05-log-sources.md)).

## DNS tunneling / DGA — T1071.004 / T1568
Signals: high volume of unique subdomains under one parent domain, long/high-entropy labels, TXT/NULL-record-heavy traffic, high NXDOMAIN ratio (DGA) or suspiciously low NXDOMAIN to a brand-new domain (tunnel).
```splunk
index=dns | eval len=len(query), labels=mvcount(split(query,"."))
| stats count dc(query) as uniq avg(len) as avglen by domain
| where uniq > 200 AND avglen > 40
```

## TLS/JA3 and cert anomalies
- Malware families reuse TLS stacks → **JA3/JA3S** fingerprints flag known tooling even over HTTPS.
- Self-signed certs, newly-registered domains (NRD feeds), SNI/CN mismatch, and certs with default/empty org fields are leads.

## Exfiltration — T1041 / T1567 / T1048
- Large outbound to a never-before-seen destination, especially off-hours.
- **Byte-ratio inversion**: a host that normally downloads suddenly uploading in volume.
- Uploads to cloud storage from server subnets with no business reason; DNS/ICMP volume anomalies (covert-channel exfil).

## IDS/NSM placement & tooling
- **Suricata** (signatures + flow) and/or **Zeek** (protocol logs) at egress (north-south) are table stakes; feed ET/Open rulesets and your own.
- Add **internal sensors** on the server/DC segment to see east-west — that's where lateral movement and internal recon hide ([lateral movement detection](../5-threat-hunting/05-lateral-movement-detection.md)).
- Correlate network detections with endpoint: a beacon flagged on the wire should pivot straight to the owning process via Sysmon EID 3 on that host.
