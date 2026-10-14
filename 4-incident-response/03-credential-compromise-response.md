# 03 — Credential Compromise Response

Mirror of credential dumping / pass-the-hash. Once you believe credentials were stolen, assume reuse. Rotate in dependency order so you don't lock yourself out or miss a path.

## Rotation order (most → least privileged)
1. **Tier-0 first**: Domain Admins, Enterprise Admins, and any account that administers DCs/PKI/backup.
2. **krbtgt** — rotate **twice** (with replication time between) to invalidate golden tickets. This is mandatory if DC compromise is suspected.
3. Service accounts on affected systems (prefer moving them to **gMSA** during rotation).
4. Local admin passwords (deploy/rotate **LAPS**).
5. Affected user accounts, then broaden to the blast radius.

## Also rotate the non-password secrets
- Kerberos: krbtgt (above). NTLM: forcing password reset rotates the hash.
- Cloud/API: access keys, app secrets, OAuth refresh tokens, SAS tokens.
- Certificates/SSH keys on affected hosts; machine account passwords for compromised computers (`reset computer account`).

## Invalidate active sessions
- Revoke Kerberos tickets (reset forces re-auth), kill active sessions, revoke cloud refresh tokens — a rotated password doesn't end a session already issued.

## Scope the reuse
```powershell
# Where did this account authenticate recently? (run against collected DC logs)
# 4624/4768/4769 by the compromised account → every host it touched is in scope
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4624} |
  Where {$_.Message -match '<compromised-user>'} |
  Select TimeCreated,@{n='Src';e={($_.Message|Select-String 'Source Network Address:\s+(\S+)').Matches.Groups[1].Value}}
```

## Don't forget
- Password-reset the account's **helpdesk/recovery** paths too (security questions, alt email) — attackers plant recovery backdoors.
- After rotation, watch for failed logons from the attacker's known source — confirms the creds are dead and may reveal their infrastructure.
