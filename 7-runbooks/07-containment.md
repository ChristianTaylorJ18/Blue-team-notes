# 07 — Containment

**Trigger:** confirmed intrusion. Goal: remove the attacker completely, in one coordinated action, without leaving a foothold. Counterpart to the attacker's persistence/stealth.

## 1. Decide timing
- [ ] Active harm now (ransomware, exfil, destruction)? → contain immediately.
- [ ] Otherwise, is scope fully mapped? If not, brief controlled watch to finish scoping — a lone isolated box warns the attacker and hides the rest. Document the decision.

## 2. Scope (must be done before eradication)
- [ ] List every in-scope host (from host runbooks + lateral-movement traces).
- [ ] List every implicated credential/secret.
- [ ] List every persistence mechanism found, per host.
- [ ] Sweep all IOCs estate-wide one more time — new hits expand scope.

## 3. Contain (preserve as you go)
- [ ] Capture volatile state on hosts you're about to isolate ([forensics](../4-incident-response/06-forensic-preservation.md)).
- [ ] EDR host-isolation or switch ACL (keeps box up for forensics; prefer over power-off).
- [ ] Disable (don't delete) compromised accounts; block C2 at egress; suspend cloud keys.

## 4. Eradicate — all scope in ONE window
- [ ] Remove every persistence mechanism on every in-scope host ([persistence hunting](../4-incident-response/04-persistence-hunting.md)).
- [ ] Rotate every implicated secret in order, including **krbtgt twice** if DC compromise ([cred response](../4-incident-response/03-credential-compromise-response.md)).
- [ ] Rebuild (don't clean) any host with kernel-level implant, rootkit, or tier-0 compromise.
- [ ] For each mechanism removed, confirm you also removed *what dropped it*.

## 5. Recover & verify
- [ ] Restore from backups verified clean (and verify backups weren't tampered/encrypted).
- [ ] Heightened detection on for the attacker's return — re-intrusion within days is common.
- [ ] Close only when: persistence gone across scope, all creds rotated, sessions invalidated, no attacker activity for the agreed watch window.

## 6. After
- [ ] Post-incident review: root cause, dwell time, what detected it (and what should have), gaps to close.
- [ ] Turn findings into new detections/hardening and feed the inventory/baseline back in ([stage 1](../1-visibility-and-baseline/)).

> The two failure modes: containing before scope (attacker warned, returns from the host you missed) and eradicating piecemeal (attacker re-establishes from the host you hadn't cleaned yet). One window, whole scope.
