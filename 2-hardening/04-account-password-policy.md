# 04 — Account & Password Policy

Mirror of password attacks and wordlist generation: defeat sprays, roasting, and brute force structurally.

## Passwords
- **Length over complexity**: 14+ char minimum for users, banned-password list (common + org-specific terms like the company name, season+year).
- Service accounts: 25+ char random, managed via **gMSA** so the password is machine-managed and auto-rotated — this removes the Kerberoasting payoff.
- Krbtgt: rotate twice on a schedule and after any DC compromise.

## MFA
- Everywhere internet-facing and for all privileged logon. MFA is the single highest-ROI control against credential theft.
- Prefer phishing-resistant factors (FIDO2/WebAuthn) over push — push fatigue is a real bypass. Enable number-matching on push.

## Lockout & spray defense
- Smart lockout / observation window that counts failures per account across all DCs, not per DC.
- Alert on *horizontal* spray: many accounts each seeing a few failures from one source (classic spray signature — one password, many users). See [AD Attack Detection](../3-detection/05-ad-attack-detection.md).

```powershell
# Find enabled accounts with no MFA-equivalent / weak settings
Get-ADUser -Filter {Enabled -eq $true} -Properties PasswordNeverExpires,PasswordLastSet |
  Where-Object {$_.PasswordNeverExpires} | Select SamAccountName,PasswordLastSet
```

## Kill the easy wins
- Disable/flag accounts with `DoesNotRequirePreAuth` (AS-REP roastable).
- No privileged account should have an SPN. Audit and remove.
