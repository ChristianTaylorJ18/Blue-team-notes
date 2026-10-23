# 01 — Preparing for Battle

The defender's prep work before an engagement/competition. "By failing to prepare, you are preparing to fail" — planning is preeminent.

## Planning & team
- **Document your plans** — write them down, don't throw them away. Planning is a team effort.
- Use code/document-sharing tools for access + persistence of your plans; keep competition-sensitive material confidential (OpSec).
- **Long-term planning**: shared, achievable goals across horizons (5-year / 1-year / single event). Set goals → identify milestones. Use down-time (non-competition) to build tools and automations — automatic is faster, but only if it works. Build contingency plans; plans go awry.
- **Team structure**: too much for one person. CCDC needs Windows, Unix, web apps, incident response, red-teaming, reverse-engineering. Contingency demands **skill redundancy** (more than one person per area). Practice makes (more) permanent.

## Operational planning & runbooks
- *Operational planning* = anything that helps operators prepare and navigate an upcoming engagement; can be generic or engagement-specific. Both matter.
- **Runbook** = a compilation of routine procedures and operations: how to begin, stop, supervise, and debug the system, plus specific actions to take in response to specific alerts/events/incidents. Good runbooks instruct the newcomer; annotate workflows from practical experience to cut needless redundancy.
- Runbook types especially relevant to competitions:
  - **System restoration** — recover hardware/software/data from backups.
  - **Network reconfiguration** — restore connectivity and security settings.
  - **Application recovery** — bring critical apps back online.
  - **Data recovery** — restore lost/corrupted data.
- Example runbook repo (CCDC competitor): `https://github.com/alexanderchmiel/ccdc-ops-runbooks/tree/main/runbooks`

## Defensive perspective
- **Defense in Depth** is critical — if you can't prevent breach of a single system, build a network of such systems.
- Prioritize infrastructure by your needs; prepare alternatives for failed components. Verify each primary tool's results with an alternate tool/method.
- **Best early investment: security log generation, aggregation, and alerting.**
- Three categories of digital-security telemetry (collect in this priority order):
  1. **Network-based telemetry** — can identify unknown devices on the network.
  2. **Host-based telemetry**.
  3. **Application-specific telemetry** — app logs can reveal protocol info showing fraud/abuse.
  Priority: network-based visibility first, then host-based, then application-specific.
