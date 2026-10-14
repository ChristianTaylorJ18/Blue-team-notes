# 5. Threat Hunting & Lateral-Movement Defense

Mirror of lateral movement. Once an attacker has one box, they move. This stage is about seeing that movement across the domain — the east-west activity that perimeter tools miss — and hunting proactively instead of waiting for an alert.

## Sections
1. [AD Monitoring Overview](./01-ad-monitoring-overview.md) — what to watch in AD and why it's the center of gravity.
2. [AD Protocol Monitoring](./02-ad-protocol-monitoring.md) — SMB, LDAP, RPC, WMI, WinRM signals.
3. [Kerberos Attack Detection](./03-kerberos-attack-detection.md) — roasting, delegation abuse, ticket forgery in depth.
4. [ACL & Object Change Auditing](./04-acl-change-auditing.md) — watching the permission edges attackers abuse.
5. [Lateral Movement Detection](./05-lateral-movement-detection.md) — pass-the-hash, remote exec, pivoting, tunneling.

> Hunting is hypothesis-driven: "if an attacker were doing X, the evidence would be Y — is Y present?" Write the hypothesis down, run it, record the result whether or not you found anything.
