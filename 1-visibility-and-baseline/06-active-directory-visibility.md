# 06 — Active Directory Visibility

AD is the crown jewel and the attacker's primary target — nearly every path to domain dominance crosses it. You cannot defend it without a current map of privilege, trusts, delegation, and the attack paths between them.

## Inventory on a schedule (snapshot + diff)
- **Privileged group membership** (recursive): Domain Admins, Enterprise Admins, Schema Admins, Administrators, DnsAdmins, Backup Operators, Account Operators, Server/Print Operators, Cert Publishers. Snapshot weekly; diff for unexpected additions and nested groups that sneak privilege in.
- **Trusts**: direction, transitivity, SID-filtering status, forest vs external. Each trust is an extension of your attack surface.
- **Delegation**: unconstrained (standing risk — inventory every account/computer with it), constrained, and resource-based (RBCD). Watch the delegation attributes closely ([ACL auditing](../5-threat-hunting/04-acl-change-auditing.md)).
- **Kerberos surface**: accounts with SPNs (Kerberoast surface), accounts with pre-auth disabled (AS-REP), accounts with `PasswordNeverExpires`.
- **GPOs**: who can edit each, where linked, and any that push startup scripts/scheduled tasks.
- **AD CS**: CA config and vulnerable certificate templates (ESC1–ESC8 surface) — AD CS is now a primary escalation path.

```powershell
# Privileged group snapshot (recursive)
"Domain Admins","Enterprise Admins","Administrators","DnsAdmins","Backup Operators","Account Operators" |
  ForEach-Object { $g=$_; Get-ADGroupMember $g -Recursive | Select @{n='Group';e={$g}},SamAccountName }

# Unconstrained delegation (exclude DCs — those are expected)
Get-ADComputer -Filter {TrustedForDelegation -eq $true} -Properties TrustedForDelegation |
  Where {$_.DistinguishedName -notlike "*OU=Domain Controllers*"}

# RBCD configured (resource-based constrained delegation) — common escalation primitive
Get-ADObject -Filter {msDS-AllowedToActOnBehalfOfOtherIdentity -like "*"} `
  -Properties msDS-AllowedToActOnBehalfOfOtherIdentity

# Kerberoast surface: SPN accounts, flag non-expiring passwords
Get-ADUser -Filter {ServicePrincipalName -like "*"} -Properties ServicePrincipalName,PasswordNeverExpires,PasswordLastSet |
  Select SamAccountName,PasswordNeverExpires,PasswordLastSet

# AS-REP roastable: pre-auth not required
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth
```

## Use the attacker's map against them
Run **BloodHound** (SharpHound collector) as a defender on a schedule. The same graph that shows an attacker the shortest path to Domain Admin shows you which edges to cut. Each cycle: review the top paths to tier-0, and treat every unexpected ACL edge (GenericAll, WriteDacl, ForceChangePassword, AddMember) as a misconfig to fix or a backdoor to investigate.

## Tier model (write it down)
Explicitly list tier-0 (identity-controlling) assets: DCs, ADFS/Entra Connect, PKI/AD CS, backup infrastructure, and any account or group that administers them. Every detection severity and containment decision references this list — "is this a tier-0 object?" is the first question on an AD alert.

## Honey objects
Plant a decoy privileged-looking user (SPN set, attractive name, long random password) and a decoy admin group. Legitimate admins never touch them; any authentication, LDAP read in a collection sweep, or membership change is near-zero-FP malicious ([AD attack detection](../3-detection/05-ad-attack-detection.md)).
