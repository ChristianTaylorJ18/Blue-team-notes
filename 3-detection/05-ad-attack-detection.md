# 05 — AD Attack Detection

Mirror of Kerberos attacks and AD abuse: the event signatures for roasting, delegation abuse, DCSync, spray, and ticket forgery. Ensure the audit subcategories are on ([log sources](../1-visibility-and-baseline/05-log-sources.md)) or none of this logs.

## Kerberoasting — T1558.003
- Signal: Event **4769** (TGS request) with **encryption type 0x17 (RC4)** and ticket options `0x40810000`, many distinct SPNs requested by one account in a short window.
```splunk
index=win EventCode=4769 Ticket_Encryption_Type=0x17
| stats dc(Service_Name) as svc values(Service_Name) count by Account_Name, Client_Address
| where svc > 5
```
- **Honeypot SPN**: a fake service account with an SPN and a long password. Any 4769 for it is malicious — zero-FP. Best single roasting detection you can deploy.
- Enforcing AES removes RC4; residual RC4 requests then stand out further.

## AS-REP roasting — T1558.004
- Event **4768** (AS-REQ) for accounts with pre-auth disabled (`DONT_REQ_PREAUTH`). Baseline is normally zero — alert on any, and audit the flag quarterly.

## DCSync — T1003.006
- Directory replication (`DRSUAPI`/`GetNCChanges`) from a host that is **not a DC**. Event **4662** referencing the replication control-access rights:
  - `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2` (DS-Replication-Get-Changes)
  - `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2` (…-All)
```splunk
index=win EventCode=4662 Properties="*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2*"
| search NOT Account_Name IN (<dc-machine-accounts>)
```
- Treat any non-DC DCSync as **domain compromise** — the caller holds replication rights.

## Password spray — T1110.003
- Many **4625** (failed logon) across **many distinct accounts** from one source in a short window, status `0xC000006A`/sub `0x18`. Contrast with brute force (one account, many tries).
```splunk
index=win EventCode=4625 | bin _time span=10m
| stats dc(Account_Name) as users count by Source_Network_Address,_time
| where users > 10
```
- Watch for the **one success after the spray** (a 4624 from the same source) — that account is your first compromised identity.

## Delegation abuse — T1558 / T1484
- **5136** writing `msDS-AllowedToActOnBehalfOfOtherIdentity` (RBCD) or `msDS-AllowedToDelegateTo` (constrained) — common escalation primitive; alert on any write.
- Unconstrained-delegation host suddenly used to reach many services, or a privileged TGT appearing on such a host.

## Golden / silver ticket & overpass — T1558.001/.002
- **Golden** (forged TGT via krbtgt): anomalous TGT lifetime beyond domain policy, TGS (4769) for an account with no preceding AS (4768), tickets for nonexistent accounts, `krbtgt` misuse after reset.
- **Silver** (forged TGS for one service): service access with no DC-side 4768/4769 at all — the DC never issued the ticket it's honoring.
- **Overpass-the-hash**: 4768 requested with RC4 immediately after a suspicious logon, from a host that normally uses AES.

## Account/privilege & GPO changes
- **4720** (user created), **4728/4732/4756** (added to global/local/universal privileged group), **4672** (special privileges) on unexpected accounts.
- **DnsAdmins** membership change (DLL-load-to-SYSTEM-on-DC path) and **GPO edits** (5136 on GPC objects, or gPCFileSysPath changes) outside change windows.
- Honey admin group: any membership change = malicious.
