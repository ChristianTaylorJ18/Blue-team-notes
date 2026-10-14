# 01 — Triage

**Trigger:** an alert fired. Goal: decide *real or not*, and if real, *how bad*, within minutes — without destroying evidence.

- [ ] Read the alert: what rule, what entity (host/user), what ATT&CK technique, what time (UTC).
- [ ] Identify the asset — owner, role, tier, internet-facing? ([inventory](../1-visibility-and-baseline/01-asset-inventory.md)). A hit on a tier-0 box escalates immediately.
- [ ] Pull the surrounding context, don't judge the single event:
  - [ ] Process ancestry around the event (parent chain — the chain is the truth).
  - [ ] What else did this host/user do ±30 min? Auth events, network, new files.
  - [ ] Is the source a known admin tool / backup agent (allowlist check)?
- [ ] Reputation-check external IOCs (IPs/domains/hashes) in your TI — but absence of a hit ≠ benign.
- [ ] Verdict:
  - [ ] **False positive** → record why, feed the tuning backlog (allowlist, not delete). Done.
  - [ ] **Benign true positive** (real activity, authorized) → record, consider suppressing that context. Done.
  - [ ] **Suspicious / malicious** → open a case ([00-methodology](./00-methodology.md)) and continue.
- [ ] If malicious: **preserve volatile state now** on the suspect host before it reboots or you isolate it ([forensics](../4-incident-response/06-forensic-preservation.md)).
- [ ] Seed the IOC list with everything concrete from the alert; sweep each estate-wide.
- [ ] Route to the right runbook by what you're seeing: web → 02, AD → 03, host → 04/05, creds → 06.

> Triage bias: it's worse to dismiss a real intrusion than to spend 20 minutes disproving a false one. When genuinely unsure, treat as real until disproven — but don't mobilize the whole team on an unconfirmed single alert either. Confirm first.
