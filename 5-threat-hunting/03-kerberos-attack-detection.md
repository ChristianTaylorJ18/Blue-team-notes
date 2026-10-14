# 03 — Kerberos Attack Detection

Mirror of Kerberos attacks, in operational depth. Kerberos abuse is the backbone of AD lateral movement and privilege escalation.

## Kerberoasting (T1558.003)
- **4769** RC4 (`0x17`) for many SPNs from one principal. Honeypot SPN = zero-FP detection (any request is malicious).
- Prevention that kills the technique: gMSA for service accounts, AES-only, and no SPNs on privileged accounts.

## AS-REP roasting (T1558.004)
- **4768** for accounts with pre-auth disabled. Baseline is normally zero; alert on any occurrence and audit `DONT_REQ_PREAUTH` quarterly.

## Delegation abuse
- **Unconstrained**: a server with this setting receiving a privileged TGT is the risk; inventory and retire it. Watch for machine accounts of delegation hosts suddenly used widely.
- **Constrained / RBCD**: changes to `msDS-AllowedToDelegateTo` or `msDS-AllowedToActOnBehalfOfOtherIdentity` (via **5136**) are high-signal — RBCD edits are a common privilege-escalation primitive. Alert on any write to those attributes.

## Ticket forgery
- **Golden** (forged TGT via krbtgt): anomalous TGT lifetime, tickets for nonexistent accounts, `krbtgt` activity after reset. Rotate krbtgt twice to invalidate.
- **Silver** (forged TGS for one service): service access with no preceding 4768/4769 on the DC — the hallmark is a TGS used that the DC never issued.
- **Overpass-the-hash**: 4768 requested with RC4 right after a suspicious logon, from a host that normally uses AES.

## Standing hygiene
- AES everywhere (disable RC4 where feasible), short ticket lifetimes, Protected Users for admins (no RC4, no delegation, no NTLM).
