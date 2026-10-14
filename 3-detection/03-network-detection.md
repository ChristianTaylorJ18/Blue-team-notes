# 03 — Network Detection

Mirror of C2, tunneling, and file transfer: what command-and-control and exfil look like on the wire.

## Beaconing (C2 callback)
- Signature: regular connections to the same destination at a near-fixed interval, often small and uniform, with jitter.
- Hunt with flow periodicity, not payload:

```bash
# Group flows to each external dst, look at inter-arrival regularity
nfdump -R /var/flows "not dst net 10.0.0.0/8 and dst port 443" -o "fmt:%ts %sa %da %byt" \
 | awk '{print $3}' | sort | uniq -c | sort -rn | head
```
- Zeek `conn.log` + RITA, or Suricata flow records, do this well. Low-and-slow beacons need days of history — another reason retention matters.

## DNS tunneling / DGA
- Signals: high volume of unique subdomains under one domain, long/high-entropy labels, TXT-record-heavy traffic, low NXDOMAIN ratio to a new domain.
```splunk
index=dns | eval len=len(query), sub=mvcount(split(query,"."))
| stats count dc(query) as uniq avg(len) as avglen by domain
| where uniq > 200 AND avglen > 40
```

## Exfil
- Large outbound to a never-before-seen destination, especially off-hours.
- Cloud-storage uploads from server subnets that have no business reason.
- Watch byte-ratio inversion: a host that normally downloads suddenly uploading in volume.

## IDS placement
- Suricata/Zeek at egress (north-south) is table stakes. Add internal sensors on the server/DC segment to see east-west — that's where lateral movement hides.
