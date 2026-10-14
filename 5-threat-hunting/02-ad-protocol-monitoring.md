# 02 — AD Protocol Monitoring

Mirror of AD protocols. Each protocol an attacker uses to move has a defensive signature.

## SMB (445)
- Workstation→workstation SMB is abnormal in most designs — flag it.
- Admin-share access (`ADMIN$`, `C$`) from non-admin-management hosts → Event 5140/5145.
- Service binary written to a remote `ADMIN$` then a 7045 service-install = PsExec-style exec.

## LDAP (389/636)
- High-volume, broad LDAP queries from a non-admin host = BloodHound/SharpHound collection. Signature: enumerating users, groups, ACLs, trusts, and sessions in one burst.
```splunk
index=win EventCode=1644 OR source="ldap"
| stats count dc(search_filter) as filters by src_host
| where filters > 100
```
- Deploy a honey-object (a decoy privileged-looking user) — collection tools will read it; legitimate admins won't.

## RPC / DCE-RPC
- Remote service control (`svcctl`), task scheduler (`atsvc`/`tsch`), and `winreg` over RPC from unexpected sources = remote exec / recon.
- Coercion signatures (forced auth via printer/EFS RPC, e.g. `MS-RPRN`/`MS-EFSR`) → a DC or server authenticating *to* an attacker host. Watch for machine-account 4624 type 3 to non-infrastructure IPs.

## WMI (135 + dynamic) & WinRM (5985/5986)
- `wmic`/WMI process creation remotely, or WinRM between endpoints, is classic fileless lateral movement. Sysmon EID 1 with parent `WmiPrvSE.exe` spawning shells is high-signal.
- Baseline legitimate WinRM (usually management servers only); alert on any other source.
