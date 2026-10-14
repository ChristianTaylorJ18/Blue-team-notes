# 03 — Active Directory Incident

**Trigger:** AD attack signal — Kerberoast burst, AS-REP roast, DCSync from non-DC, password spray, suspicious ticket, privileged-group change. Counterpart to the AD attack chain.

- [ ] Classify the signal first — the response differs:
  - [ ] **Spray** (4625 across many accounts, one source) → [06-credential-incident](./06-credential-incident.md); block source, confirm no success (a 4624 after the spray = find that account).
  - [ ] **Kerberoast** (4769 RC4, many SPNs) → identify the requesting account (likely already compromised) and every targeted service account → rotate those service accounts (prefer gMSA).
  - [ ] **AS-REP roast** (4768, no-preauth accounts) → reset those accounts, remove `DONT_REQ_PREAUTH`.
  - [ ] **DCSync** (4662 replication GUID from non-DC) → **treat as domain compromise** (see below). This means they have replication rights.
  - [ ] **Ticket forgery** (anomalous lifetime, silver/golden signals) → domain compromise path.
- [ ] Scope the privileged surface right now:
```powershell
"Domain Admins","Enterprise Admins","Administrators","DnsAdmins","Account Operators","Backup Operators" |
  % { Get-ADGroupMember $_ -Recursive | Select @{n='Grp';e={$_}},SamAccountName }
# Recent privileged group changes
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4728,4732,4756} -MaxEvents 50
# ACL changes on tier-0 objects / AdminSDHolder
Get-WinEvent -FilterHashtable @{LogName='Security';Id=5136} -MaxEvents 100 |
  Where {$_.Message -match 'nTSecurityDescriptor|AdminSDHolder'}
```
- [ ] Identify patient zero: which account/host first showed the signal; pull its recent 4624/4648/4769 to map where it's been.
- [ ] If **domain compromise** is confirmed or suspected (DCSync, golden ticket, DA added):
  - [ ] Escalate — this is the top-severity path.
  - [ ] Plan **krbtgt double-reset** (two resets with replication between) to kill golden tickets ([cred response](../4-incident-response/03-credential-compromise-response.md)).
  - [ ] Assume all domain creds potentially exposed; plan staged rotation, tier-0 first.
  - [ ] Verify DC integrity: unexpected services (7045), new admins, replication from rogue hosts.
- [ ] Add IOCs (accounts, source hosts, ticket anomalies) and sweep.
- [ ] Hand confirmed intrusions to [07-containment](./07-containment.md) — eradicate across the whole scope in one window.

> DCSync, golden ticket, or an unexplained Domain Admin = you no longer trust the directory. Scope the whole domain, not one host.
