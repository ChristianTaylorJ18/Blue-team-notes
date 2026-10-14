# 06 — Credential Incident

**Trigger:** credentials suspected stolen — successful spray, LSASS dump, creds in a shell's loot, phishing hit, leaked key. Counterpart to credential dumping / password attacks.

- [ ] Identify exactly which secrets are in question: which accounts, which hosts, what type (password/NTLM/Kerberos/cloud key/SSH/cert).
- [ ] Assume reuse until disproven — one stolen cred is sprayed everywhere by default.
- [ ] Scope where the account has been:
```powershell
# Estate-wide: every host this account authenticated to recently
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4624,4768,4769} |
  Where {$_.Message -match '<account>'} | Select TimeCreated,Id
```
- [ ] Rotate in dependency order ([cred response](../4-incident-response/03-credential-compromise-response.md)):
  - [ ] Tier-0 / DC admins first.
  - [ ] **krbtgt twice** if DC compromise is on the table.
  - [ ] Service accounts (→ gMSA), then local admin (→ LAPS), then users and blast radius.
- [ ] Rotate the non-password secrets too: cloud keys, OAuth/refresh tokens, SAS tokens, SSH keys, certs, machine-account passwords on compromised hosts.
- [ ] **Invalidate live sessions** — rotation alone doesn't kill an already-issued ticket/token. Revoke sessions, force re-auth, revoke cloud refresh tokens.
- [ ] Close recovery backdoors: reset security questions, alt-email/phone, MFA devices the attacker may have enrolled.
- [ ] Verify the creds are dead: watch for failed logons from the attacker's source after rotation (also reveals their infra → add to IOCs).
- [ ] Prevent the repeat: MFA (phishing-resistant), banned-password list, gMSA, tiering ([account policy](../2-hardening/04-account-password-policy.md)).

> Rotation order matters: do it coordinated and in one window. Partial rotation lets the attacker re-harvest from what you haven't rotated yet.
