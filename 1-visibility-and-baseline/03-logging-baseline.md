# 03 — Logging Baseline

An alert is only meaningful against a baseline of normal. Spend time learning "normal" *before* writing thresholds, or you'll drown in false positives and tune the real signal away with them.

## Baseline these first (highest detection payoff)
- **Authentication**: per user/group — normal logon hours, source hosts, logon types, and volume. Feeds impossible-travel, off-hours, and spray detection.
- **Process execution**: what binaries run where, and their normal parents. A workstation that has never run `powershell.exe -enc` makes that event high-signal.
- **Autostart surface**: scheduled tasks, services, Run keys, cron, systemd units — snapshot the known-good set per image/role.
- **Outbound destinations**: normal domains/IPs per host role; normal data volume and direction.
- **Admin actions**: who normally performs privileged operations, from where, when.

## Method
1. Collect 2–4 weeks of raw telemetry with **no alerting**.
2. Compute per-entity norms (user, host, service account, role) — mean, stdev, and the long tail.
3. Alert on *deviation from the entity's own norm*, not on absolute events. "This user, 3σ above their own hourly auth volume" beats "more than N logons".

```splunk
index=win EventCode=4624
| bin _time span=1h | stats count by user, date_hour
| eventstats avg(count) as avg stdev(count) as sd by user
| where count > avg + 3*sd
```

## Peer grouping beats individual baselines for new entities
A brand-new user has no history. Baseline them against their *role peer group* (same team/OU) until they accrue their own history — an account doing something no peer in its group ever does is a lead on day one.

## Service accounts are the highest-value baseline
They behave predictably — same host, same hours, same targets, same logon type — right up until an attacker steals them. A tight per-service-account baseline turns theft into an obvious anomaly. For each, document: expected source host(s), logon type, target services, and schedule. Any deviation is near-zero-FP.

## Keep baselines fresh
Normal drifts (new apps, reorgs, seasonal load). Recompute on a schedule (e.g. monthly) and after major environment changes, or yesterday's baseline becomes today's false-positive engine.
