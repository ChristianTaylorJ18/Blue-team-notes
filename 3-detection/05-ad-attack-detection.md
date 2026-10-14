# 05 — AD Attack Detection

Mirror of Kerberos attacks and AD abuse: the event signatures for roasting, DCSync, spray, and ticket forgery.

## Kerberoasting (T1558.003)
- Signal: Event **4769** (TGS request) with encryption type **0x17 (RC4)** and `Ticket Options 0x40810000`, many distinct SPNs requested by one account in a short window.
```splunk
index=win EventCode=4769 Ticket_Encryption_Type=0x17
| stats dc(Service_Name) as svc count by Account_Name
| where svc > 5
```
- Honeypot SPN: a fake service account with an SPN and a long password; *any* 4769 for it is malicious. Zero-false-positive detection.

## AS-REP roasting (T1558.004)
- Event **4768** with pre-auth not required (accounts with `DONT_REQ_PREAUTH`). Baseline = none; alert on any.

## DCSync (T1003.006)
- Replication (`DRSUAPI` / `GetNCChanges`) from a host that is **not a domain controller**. Event **4662** with the replication GUIDs (`1131f6aa-...`, `1131f6ad-...`) where the caller isn't a DC.
```splunk
index=win EventCode=4662 Properties="*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2*"
| search NOT Account_Name IN (<dc-accounts>)
```

## Password spray (T1110.003)
- Many **4625** (failed logon) across *many distinct accounts* from one source in a short window, often `0xC000006A`/`0x18`. Contrast with brute force (one account, many tries).

## Golden / silver ticket signals
- TGT lifetimes that exceed domain policy; tickets for accounts that don't exist; **4769** with a username mismatch; RC4 where AES is standard. Alert on anomalous ticket lifetime and on `krbtgt` misuse after a reset.

## DnsAdmins / GPO abuse
- Alert on changes to `DnsAdmins` membership and on GPO edits (Event **5136** on GPC objects) outside change windows.
