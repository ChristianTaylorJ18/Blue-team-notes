# 03 — Logging Baseline

An alert is only meaningful against a baseline of normal. Spend time learning "normal" *before* writing thresholds, or you'll drown in false positives.

## Baseline these first
- **Authentication**: normal logon hours per user/group, normal source hosts, normal volume. (Feeds impossible-travel and spray detection.)
- **Process execution**: what binaries run where. A workstation that has never run `powershell.exe -enc` baselines that as high-signal.
- **Scheduled tasks / services / autoruns**: snapshot the known-good set per image.
- **Outbound destinations**: normal domains/IPs per host role.

## Method
1. Collect 2–4 weeks of raw telemetry with **no alerting**.
2. Compute per-entity norms (user, host, service account).
3. Alert on deviation, not on absolute events.

```splunk
index=win EventCode=4624
| bin _time span=1h
| stats count by user, date_hour
| eventstats avg(count) as avg stdev(count) as sd by user
| where count > avg + 3*sd
```

## Service accounts are the highest-value baseline
They behave predictably (same host, same hours, same targets) until an attacker steals them. A tight baseline on a service account turns theft into an obvious anomaly. Document each one's expected source host and logon type.
