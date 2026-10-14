# 3. Detection Engineering

The mirror of exploitation: for each way in, the telemetry and logic that catches it. A detection is code — it has a hypothesis, a data source, a test, and a false-positive budget.

## Sections
1. [Endpoint Detection](./01-endpoint-detection.md) — Sysmon, process ancestry, LOLBins, injection.
2. [SIEM & Alerting](./02-siem-and-alerting.md) — pipeline, detection-as-code, tuning, the alert lifecycle.
3. [Network Detection](./03-network-detection.md) — IDS, beaconing, DNS tunneling, exfil.
4. [Web Attack Detection](./04-web-attack-detection.md) — finding SQLi/XSS/LFI/upload attempts in logs.
5. [AD Attack Detection](./05-ad-attack-detection.md) — Kerberoast, DCSync, spray, golden/silver ticket signals.
6. [Container & Cloud Defense](./06-container-defense.md) — escape signals, runtime policy, cloud audit logs.
7. [Common Application Monitoring](./07-common-app-monitoring.md) — detecting abuse of the services attackers love.

> Every detection names its [ATT&CK] technique and its expected false-positive source. If you can't state the FP source, you haven't finished writing it.
