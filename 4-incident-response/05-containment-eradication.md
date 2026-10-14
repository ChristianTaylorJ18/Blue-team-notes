# 05 — Containment & Eradication

Isolate, scope, remove, verify — in that order. The two most common failures are containing too early (tips off the attacker before you know the blast radius) and eradicating too shallow (missing a second foothold).

## 1. Decide: isolate now or watch?
- **Isolate now** if active harm is happening (ransomware encrypting, exfil in progress, destruction).
- **Watch briefly** if you can do so safely and need to scope — a lone contained box often hides the full footprint. This is a risk call; document it.

## 2. Contain
- Network-isolate via EDR host-isolation or switch ACL (keeps the box up for forensics, cuts attacker access). Prefer this over pulling the plug — power-off destroys memory evidence.
- Disable compromised accounts (don't delete), block attacker C2 IPs/domains at egress, suspend affected cloud keys.

## 3. Scope (the step people skip)
- From triage + logs, list every host the attacker touched, every credential used, every persistence mechanism. Lateral-movement logs ([5-threat-hunting](../5-threat-hunting/)) drive this.
- Eradication acts on the *whole* scope at once. Partial eradication = the attacker simply returns from the host you missed.

## 4. Eradicate
- Remove persistence on every in-scope host (see [Persistence Hunting](./04-persistence-hunting.md)).
- Rotate all implicated credentials in order (see [Credential Compromise Response](./03-credential-compromise-response.md)).
- For confirmed deep compromise (kernel implant, tier-0): **rebuild from known-good image**, don't clean. You can't trust a cleaned box that ran attacker kernel code.

## 5. Recover & verify
- Restore from backups verified clean (and verify the backups weren't encrypted/tampered).
- Watch the environment with heightened detection for the attacker's return — re-intrusion within days is common.
- Only declare closed when: persistence gone across scope, creds rotated, no attacker activity for a defined watch period.

## Coordinated action
Do eradication in one window. Rotating creds on Monday and removing persistence on Thursday gives the attacker three days to re-establish.
