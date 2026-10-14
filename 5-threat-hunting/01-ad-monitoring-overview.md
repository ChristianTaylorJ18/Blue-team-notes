# 01 — AD Monitoring Overview

Active Directory is where lateral movement converges — nearly every path to domain dominance crosses it. Monitoring AD well catches movement that endpoint-only visibility misses.

## The events that carry the most signal
| Event ID | Meaning | Why you care |
|----------|---------|--------------|
| 4624 / 4625 | Logon success / failure | Type + source = movement & spray |
| 4648 | Logon with explicit creds | runas / credential injection |
| 4672 | Special privileges assigned | Privileged logon tracking |
| 4768 / 4769 / 4771 | Kerberos AS/TGS/pre-auth fail | Roasting, ticket abuse |
| 4662 | Operation on an object | DCSync (replication GUIDs) |
| 4720 / 4728 / 4732 / 4756 | Account created / added to group | Persistence, privilege grant |
| 5136 / 5137 | Directory object modified / created | GPO & ACL tampering |
| 7045 | Service installed | Remote-exec lateral movement (PsExec-style) |

## Logon types decode movement
- **Type 3** (network): SMB/share/WinRM — the bread and butter of lateral movement.
- **Type 10** (RemoteInteractive): RDP.
- **Type 9** (NewCredentials): `runas /netonly` — credential overlay, often pivoting.
- Baseline which accounts use which types where; deviations are leads.

## Instrument the DCs properly
- Ensure the audit policy actually logs these (many are off by default): Kerberos service ticket ops, directory service changes, detailed file share, process creation with command line.
- Forward DC security logs off-box in real time — a DC is exactly where an attacker will try to clear them.
