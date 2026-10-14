# 03 — Credential Defense

Mirror of credential dumping and pass-the-hash: make the credentials not be there to steal, make reuse impossible across hosts, and make any theft attempt loud.

## Stop LSASS theft at the source
- **Credential Guard** (VBS-isolated LSASS secrets) on supported Windows — defeats classic LSASS scraping of NTLM/TGT secrets.
- **RunAsPPL** (LSASS as a protected process light):
  ```
  reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 1
  ```
- **The detection that pairs with it**: alert on any non-allowlisted process opening a handle to `lsass.exe` — Sysmon **Event ID 10**, `TargetImage` ending `lsass.exe`, with `GrantedAccess` like `0x1010`/`0x1410`. One of the highest-value endpoint detections there is ([endpoint detection](../3-detection/01-endpoint-detection.md)). Allowlist your EDR/AV and legitimate agents.

## Reduce cached and reusable secrets
- Disable **WDigest** cleartext caching: `UseLogonCredential = 0`.
- Lower cached domain credentials (`CachedLogonsCount`) on servers that don't need offline logon.
- **LAPS** (or Windows LAPS) so every local administrator password is unique and auto-rotated — this single control kills pass-the-hash *reuse* of a common local-admin hash across the fleet.
- Prefer **gMSA** for service accounts (machine-managed, auto-rotated 240-char password) — removes the Kerberoast payoff and the human-set weak service password.

## Tiering (the structural fix)
- **Tier-0 admins never log on to tier-1/2 hosts.** A stolen helpdesk token then can't reach a DC because DA creds were never exposed on a workstation.
- Put admins in **Protected Users** and use **authentication-policy silos**: blocks NTLM for those accounts, forces Kerberos, forbids delegation, and limits where they can authenticate.
- Use dedicated Privileged Access Workstations (PAWs) for tier-0 administration.

## Make theft detectable
- Alert on logon-type **9** (NewCredentials / `runas /netonly`) from unusual hosts — classic overpass/credential-overlay signal.
- Watch **4648** (explicit-credential logon) from hosts/users where it's abnormal, and Credential Manager / DPAPI access patterns.
- Honey credentials: seed fake creds in memory/scripts/GPP and alert on any use — they have no legitimate purpose, so any hit is malicious.
