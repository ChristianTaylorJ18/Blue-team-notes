# 00 — Methodology & Setup

## Standing readiness (before anything happens)

- [ ] Asset inventory current and queryable — you can answer "what is `<ip>`?" in seconds ([inventory](../1-visibility-and-baseline/01-asset-inventory.md)).
- [ ] Log sources healthy and forwarded off-host; log-source-silence alerting is on ([log sources](../1-visibility-and-baseline/05-log-sources.md)).
- [ ] EDR deployed with coverage report — the gap list is known and shrinking.
- [ ] Golden Sysmon config deployed and hash-verified across the fleet.
- [ ] Tier-0 asset list written down and agreed.
- [ ] Out-of-band comms ready (if the network is owned, you can't trust in-band chat/email).
- [ ] Backups tested, offline/immutable copy exists, restore time known.
- [ ] Contact tree: who to call, who can authorize isolation/shutdown, legal/comms thresholds.

## Case setup (the moment an incident opens)

- [ ] Open a case log. Everything gets a UTC timestamp.
```bash
mkdir -p incident-$(date +%F)/{evidence,notes,iocs,timeline}
cd incident-$(date +%F)
: > iocs/iocs.txt            # hashes, IPs, domains, accounts
script -f notes/caselog-$(date +%F-%H%M).log   # record your own actions
```
- [ ] Assign roles: incident lead (decisions), scribe (case log), analysts (hands on keyboard). On a small team one person wears several hats — still write down who did what.
- [ ] Set the first objective explicitly: *confirm or deny*, then *scope*, then *contain*. Don't jump to containment before scope unless active harm is underway.

## First 30 minutes of a live incident

- [ ] Confirm the alert is real ([01-triage](./01-triage.md)) — don't mobilize on a false positive, don't dismiss a real one.
- [ ] Capture volatile state on the first suspect host **before** isolating it ([forensics](../4-incident-response/06-forensic-preservation.md)).
- [ ] Start an IOC list and sweep each IOC estate-wide as you find it.
- [ ] Decide isolate-now vs watch-to-scope — and write down the reasoning.

## The 45-minute rule

If a single lead has produced nothing for 45 minutes:
- [ ] Note what you tried in the case log, **move on** to the next highest-value item.
- [ ] Re-sweep fresh IOCs across the estate — the host you're stuck on may be explained by one you haven't looked at.
- [ ] Return to the timeline: what's the earliest attacker action you can see? Work outward from there.

## Hygiene (multi-day incidents)

- [ ] Hand off cleanly between shifts: case log current, IOC list current, open leads listed. Coming back cold to messy state kills momentum and causes missed footholds.
- [ ] Sleep. Critical errors compound on no sleep and cost more than they save. Rotate people.
- [ ] End each day with state flushed: timeline updated, evidence hashed and stored, next-day plan written.
