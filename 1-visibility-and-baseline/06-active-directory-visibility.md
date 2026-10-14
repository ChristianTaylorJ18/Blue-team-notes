# 06 — Active Directory Visibility

AD is the crown jewel and the attacker's primary target. You cannot defend it without a current map of privilege, trusts, and delegation.

## Inventory on a schedule
- **Privileged group membership**: Domain Admins, Enterprise Admins, Schema Admins, Administrators, DnsAdmins, Backup Operators, Account Operators. Snapshot weekly; diff for unexpected adds.
- **Trusts**: direction, transitivity, SID filtering status.
- **Delegation**: unconstrained, constrained, resource-based. Unconstrained delegation is a standing risk — inventory every account that has it.
- **GPOs**: who can edit which, linked where.

```powershell
# Privileged group snapshot
"Domain Admins","Enterprise Admins","Administrators" | ForEach-Object {
  Get-ADGroupMember $_ -Recursive | Select @{n='Group';e={$_}}, SamAccountName
}

# Accounts trusted for unconstrained delegation (exclude DCs)
Get-ADComputer -Filter {TrustedForDelegation -eq $true} -Properties TrustedForDelegation |
  Where-Object {$_.DistinguishedName -notlike "*OU=Domain Controllers*"}

# Accounts with SPNs (Kerberoast surface) and no password expiry
Get-ADUser -Filter {ServicePrincipalName -like "*"} -Properties ServicePrincipalName,PasswordNeverExpires |
  Select SamAccountName,PasswordNeverExpires
```

## Use the attacker's map against them
Run **BloodHound** (SharpHound collector) as a defender on a schedule. The same graph that shows an attacker the shortest path to Domain Admin shows you which edges to cut. Review and prune the top attack paths each cycle.

## Tier model
- Document your tier-0 (identity-controlling) assets explicitly: DCs, ADFS, AAD Connect, PKI, backup. Every detection and containment decision references this list.
