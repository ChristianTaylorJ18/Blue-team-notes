# 07 — Common Application Monitoring

Mirror of attacking common applications: the services attackers target most, and the few high-value things to watch on each.

## SMB / file shares — T1021.002 / T1570
- Mass file access/reads in a short window (collection or ransomware staging): Event **5145** (detailed file share) + rename/encrypt bursts; many files touched by one account/host in minutes.
- Writes to `SYSVOL`/`NETLOGON` (logon scripts, GPO files) = GPO/script abuse.
- Admin-share (`ADMIN$`/`C$`) access from non-management hosts; a binary written to `ADMIN$` followed by a 7045 service install = PsExec-style exec.

## Databases — T1190 / T1059
- App-account logins from a host that isn't the app server; off-hours DBA activity.
- MSSQL `xp_cmdshell` enabled or called; `sp_OACreate`; bulk export / `SELECT ... INTO OUTFILE` / `bcp` to odd paths.
```sql
SELECT name, value_in_use FROM sys.configurations WHERE name IN ('xp_cmdshell','Ole Automation Procedures');
```

## Email / collaboration (M365 / Google) — T1114 / T1098.002
- New **inbox/forwarding rules**, especially forwarding externally or auto-deleting — classic BEC persistence.
- Mass mailbox access/download, impossible-travel sign-ins, **OAuth app-consent** grants to unknown apps (illicit-consent attacks).
- New delegate/mailbox permissions; mailbox export requests.

## Remote access (RDP / WinRM / SSH) — T1021
- **RDP** (logon type 10) to servers from workstations, or from accounts that never use it.
- **WinRM** (5985/5986) between workstations — almost always lateral movement; baseline legit WinRM to management hosts only.
- **SSH**: key added to `authorized_keys` outside change windows; new/odd source IPs; root login where disabled by policy.

## CMS / CI / app servers — T1505 / T1098
- New admin users, plugin/theme installs, or theme-file edits on WordPress; new Jenkins job running shell commands or a changed job config (RCE-as-a-feature); new Tomcat/JBoss WAR deploys; GitLab/GitHub runner or webhook changes.
- Service-account keys/tokens issued or scopes widened.

## Principle
For each business-critical app, write down its **three most dangerous legitimate features** — the ones that run code, move data, or grant access — and monitor those first. You don't need full app coverage; you need the features an attacker would reach for, watched well.
