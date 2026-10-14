# 04 — Account & Password Policy

Mirror of password attacks and wordlist generation: defeat sprays, roasting, and brute force structurally so the attacker's cheapest techniques stop paying off.

## Passwords
- **Length over complexity**: 14+ char minimum for users (NIST-style), with a **banned-password list** of common passwords plus org-specific terms (company name, product names, `Season+Year`, local sports teams). Complexity rules alone produce `Password1!`; length + banlist beats them.
- **Service accounts**: migrate to **gMSA** (machine-managed 240-char password, auto-rotated) — this removes the Kerberoasting payoff. Where gMSA isn't possible, 25+ char random and rotate on a schedule.
- **krbtgt**: rotate twice on a schedule and immediately after any suspected DC compromise (two resets, with replication between, to invalidate golden tickets).
- No reuse across accounts; screen new passwords against breach corpora (e.g. HaveIBeenPwned-style k-anonymity check) at set time.

## MFA
- Everywhere internet-facing and for **all** privileged logon. Highest-ROI control against credential theft, full stop.
- Prefer **phishing-resistant** factors (FIDO2 / WebAuthn / smartcard) over push/OTP. If push is used, enable **number matching** and limit prompts — push-fatigue bombing is a real bypass.
- Protect the enrollment/recovery path: attackers enroll their own MFA device after a password compromise. Alert on new MFA-device registration.

## Lockout & spray defense
- **Smart/observation-window lockout** that counts failures per account **across all DCs** (attackers spread attempts across DCs to dodge per-DC counters).
- Detect **horizontal spray**: many accounts each seeing a few failures from one source in a short window (one password → many users) — the opposite shape from brute force (one account, many tries). See [AD attack detection](../3-detection/05-ad-attack-detection.md).
- Rate-limit and alert on authentication from anomalous geographies / impossible travel for cloud identities.

```powershell
# Enabled accounts with non-expiring passwords (service-account & stale-cred risk)
Get-ADUser -Filter {Enabled -eq $true} -Properties PasswordNeverExpires,PasswordLastSet |
  Where {$_.PasswordNeverExpires} | Select SamAccountName,PasswordLastSet | Sort PasswordLastSet
```

## Kill the easy wins
- Disable/flag accounts with `DoesNotRequirePreAuth` (AS-REP roastable).
- **No privileged account should carry an SPN** — audit and remove; SPNs on DAs are a direct Kerberoast-to-domain path.
- Disable or tightly scope legacy/stale accounts; stale enabled accounts with old passwords are spray gold.
- Enforce AES for Kerberos and disable RC4 where feasible — removes the downgrade that makes roasting cheap.
