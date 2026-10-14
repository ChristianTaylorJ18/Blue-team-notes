# 07 — Common Application Monitoring

Mirror of attacking common applications: the services attackers target most, and how to watch them.

## SMB / file shares
- Mass file access/reads in a short window (ransomware staging or collection). Event **5145** (detailed file share) + rename/encrypt bursts.
- Access to `SYSVOL`/`NETLOGON` scripts being modified = GPO/logon-script abuse.

## Databases
- Logins from app accounts off their known app host; `xp_cmdshell` enabled or called on MSSQL; bulk export / `SELECT INTO OUTFILE`.
```sql
-- MSSQL: alert if xp_cmdshell gets enabled
SELECT name, value_in_use FROM sys.configurations WHERE name = 'xp_cmdshell';
```

## Email / webmail / collaboration
- New inbox/forwarding rules (classic BEC persistence), especially rules that delete or forward externally.
- Mass mailbox access, impossible-travel logins, OAuth app consent grants to unknown apps.

## Remote access (RDP/WinRM/SSH)
- RDP (logon type 10) to servers from workstations, or from accounts that never use it.
- WinRM (5985/5986) activity between workstations — almost always lateral movement, rarely legitimate.
- SSH key added to `authorized_keys` outside change windows.

## CMS / app servers
- Admin-plugin installs, theme-file edits, new admin users on WordPress/Jenkins/Tomcat. New Jenkins job running shell commands = RCE-as-a-feature; watch job config changes.

## Principle
For each business-critical app, write down its three most dangerous legitimate features (the ones that run code, move data, or grant access) and monitor those first.
