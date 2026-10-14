# 04 — Service Inventory & Attack Surface

Mirror of service enumeration: the attacker maps your open ports, so maintain the authoritative list and alert on anything new.

## Per-host known-good port set
- Record the expected listening services for each host role (DC, web, file, workstation).
- A new listener is either a change you authorized or an attacker's foothold — there is no third option.

```bash
# Linux: current listeners with owning process
ss -tulpnH | awk '{print $1, $5, $7}' | sort -u
```
```powershell
# Windows: listeners + owning process
Get-NetTCPConnection -State Listen |
  Select-Object LocalAddress,LocalPort,OwningProcess,
    @{n='Proc';e={(Get-Process -Id $_.OwningProcess).Name}} | Sort-Object LocalPort
```

## External exposure
- Reconcile what *you* think is exposed with what the internet sees. Run your own external scan on a schedule; compare to the firewall's allowed inbound rules.
- Certificate transparency logs (`crt.sh`) reveal subdomains/hosts you may have forgotten — hunt your own name there before an attacker does.

## Change = ticket
Every legitimate new service has a change record. Detection content can then treat *un-ticketed* new services as incidents. Tie the service inventory to your change-management feed.
