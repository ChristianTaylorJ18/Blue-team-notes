# 04 — ACL & Object Change Auditing

Mirror of ACL abuse. Attackers escalate by granting themselves rights rather than exploiting code. Those grants are object changes you can see — if auditing is on.

## The dangerous rights to watch
- `GenericAll`, `GenericWrite`, `WriteDacl`, `WriteOwner`, `AllExtendedRights` on users/groups/OUs.
- `ForceChangePassword` on another user.
- `Replicating Directory Changes` / `...All` (DCSync rights) granted to a non-DC principal.
- Write access to GPOs, or GPO-link rights on an OU.
- `AddMember` to privileged groups.

## Detection
- Event **5136** (directory object modified) on `nTSecurityDescriptor` = an ACL was changed. Alert on changes to tier-0 objects and to the domain head.
```splunk
index=win EventCode=5136 Attribute_LDAP_Display_Name="nTSecurityDescriptor"
| table _time Subject_Account_Name DN Attribute_Value
```
- **AdminSDHolder**: changes here propagate to all protected groups via SDProp (hourly) — a classic stealth backdoor. Audit its ACL and alert on edits.
- Membership changes to protected groups: **4728/4732/4756** (added) and the `4729/4733/4757` removals.

## Baseline with the graph
- Run SharpHound as a defender and review the ACL edges into tier-0. Every unexpected edge is either a misconfig to fix or a backdoor to investigate.
- Snapshot ACLs on tier-0 objects; diff on a schedule. New rights nobody ticketed = incident.

## Prevention
- Least privilege on AD objects, remove legacy `Authenticated Users`/`Everyone` write grants, and protect tier-0 objects with explicit, reviewed ACLs.
