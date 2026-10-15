# 00 — Elastic Basics

How the hunting works in Kibana, and the pieces I reused across every tactic.

## Beats indices (where the data lives)
| Index | Source data |
|-------|-------------|
| `filebeat-*` | Linux logs (e.g. SSH auth on the jumphost) |
| `packetbeat-*` | Network traffic (HTTP, DNS) |
| `winlogbeat-*` | Windows Event Logs + Sysmon from workstations |

## The two tools
- **Discover** — raw event hunting. Set the index pattern + time range, type a KQL query, and add fields as columns to focus the table. Sort by `@timestamp` to see attack sequence.
- **Visualize Library → Lens** — build a table to aggregate/count. Pick an index, set **Rows** (the fields to group by, via *Top values*) and **Metrics** (usually *Count of records*, or *Unique count* of a field). Good for "which source IP / domain / user stands out".

## KQL patterns I used
```kql
field: value
field: (A OR B)                 # multiple values
field: *substring*              # wildcard contains
NOT field: value                # exclude
a AND b AND c                   # combine
```

## Techniques
- **Add fields as columns** in Discover to make a noisy result readable (e.g. `process.parent.command_line`, `process.command_line`, `user.name`).
- **Filter out noise** with the minus button on a benign recurring value (e.g. `Set-StrictMode` in script-block logs).
- **View surrounding documents** — from a single event's dropdown, see events immediately before/after it on that host. Add a key column (e.g. `process.executable`) first, and filter to the host, to trace what a process did.
- **Pivot by PID** — grab a suspicious process's PID, then query `process.parent.pid: <pid>` to pull everything it spawned.
- **Correlate across indices** — spot the behaviour in `packetbeat` (network), then find the owning process in `winlogbeat` by matching `destination.ip`/domain.

## Useful Sysmon event IDs (seen in this room)
| ID | Meaning |
|----|---------|
| 1 | Process creation |
| 3 | Network connection |
| 8 | CreateRemoteThread (process injection) |
| 11 | File creation |
| 13 | Registry value set |
Plus Windows: `4104` PowerShell script-block, `4698` scheduled-task creation, `1102` event-log cleared.
