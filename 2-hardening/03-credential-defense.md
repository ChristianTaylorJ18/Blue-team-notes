# 03 — Credential Defense

Mirror of credential dumping: make the credentials not be there to steal, and make stealing them loud.

## Stop LSASS theft at the source
- **Credential Guard** (VBS-isolated LSASS secrets) on supported Windows — defeats classic LSASS scraping.
- **RunAsPPL** (LSASS as a protected process):
  ```
  reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 1
  ```
- EDR rule: alert on any non-allowlisted process opening a handle to `lsass.exe` (Sysmon Event ID 10, `TargetImage` lsass). This is one of the highest-value detections you can deploy.

## Reduce cached and reusable secrets
- Lower cached domain credentials (`CachedLogonsCount`) on servers.
- Disable WDigest (stops cleartext in memory): `UseLogonCredential = 0`.
- **LAPS** so every local admin password is unique and rotated — kills pass-the-hash reuse across machines.

## Tiering (the structural fix)
- Tier-0 admins never log on to tier-1/2 hosts. A stolen helpdesk token then can't reach a DC.
- Use the "protected users" group and authentication policy silos for admins — blocks NTLM, forces Kerberos, no delegation.

## Make theft detectable
- Alert on logon-type 9 (new-credentials / `runas /netonly`) from unusual hosts, and on credential-manager access patterns.
