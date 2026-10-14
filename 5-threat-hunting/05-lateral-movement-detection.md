# 05 — Lateral Movement Detection

Mirror of Windows pivoting. The techniques that carry an attacker from the first box to the domain, and the telemetry that reveals each.

## Pass-the-hash / overpass-the-hash (T1550.002 / T1558)
- NTLM auth (4624 type 3) where the environment is Kerberos-first; same hash authenticating across many hosts rapidly.
- Logon with explicit creds (**4648**) from a host where that user never interactively logs on.

## Remote execution (T1021 / T1569 / T1053)
| Technique | Signal |
|-----------|--------|
| PsExec-style | Service install **7045** + binary in `ADMIN$`, random service name |
| WMI exec | Sysmon EID 1, parent `WmiPrvSE.exe` → `cmd`/`powershell` |
| WinRM | 5985/5986 between non-management hosts; `wsmprovhost.exe` spawning shells |
| Scheduled task | **4698** task created remotely; task running from temp/user dirs |
| Remote registry | `winreg` RPC from unexpected source |

## Pivoting / tunneling (T1090 / T1572)
- A host suddenly acting as a relay: inbound on an odd port + matching outbound to a new destination (port-forward).
- SSH/`chisel`/`ligolo`-style tunnels: long-lived connections carrying inner sessions; look for a workstation holding many simultaneous internal connections it never normally makes.
- SOCKS proxy behavior: one internal host fanning out to many internal hosts/ports it has no business reaching.

```splunk
# Fan-out: one source touching many internal hosts on admin ports in a short window
index=sysmon EventCode=3 dest_port IN (445,3389,5985,135,22)
| bin _time span=10m
| stats dc(dest_ip) as targets by src_ip,_time
| where targets > 10
```

## The through-line
Lateral movement is a *graph* of auth events. One type-3 logon is nothing; a user/host suddenly authenticating to ten new systems in ten minutes is the attacker spreading. Alert on the fan-out shape, then pivot into which creds and which persistence — that hands you the scope for [containment](../4-incident-response/05-containment-eradication.md).
