# 04 — Service Inventory & Attack Surface

Mirror of service enumeration: the attacker maps your open ports and services, so maintain the authoritative list, know what each service *is*, and alert on anything new.

## Per-host known-good service set
Record the expected listening services for each host role (DC, web, file, DB, workstation). A new listener is either a change you authorized or an attacker's foothold — there is no third option.

```bash
# Linux: current listeners with owning process + user
ss -tulpnH | awk '{print $1,$5,$7}' | sort -u
# Diff against the host's golden listener list
ss -tulpnH | awk '{print $5}' | sed 's/.*://' | sort -u > now.ports
comm -13 golden.ports now.ports    # new ports since golden = investigate
```
```powershell
# Windows: listeners + owning process + signer
Get-NetTCPConnection -State Listen |
  Select LocalAddress,LocalPort,OwningProcess,
    @{n='Proc';e={(Get-Process -Id $_.OwningProcess).Path}} | Sort LocalPort
```

## External exposure (attacker's-eye view)
- Reconcile what *you* think is exposed with what the internet actually sees. Run your own external scan on a schedule and diff against the firewall's allowed-inbound rules — gaps both ways matter (unexpected exposure, and rules with no backing service).
- **Certificate Transparency** (`crt.sh`) surfaces subdomains/hosts you forgot you published — enumerate your own names there before an attacker does.
- Track cloud exposure separately: public S3/blob, security-group `0.0.0.0/0` rules, public-IP assignment, exposed management ports (22/3389/5985/kube-api).

```bash
# Subdomains your org has published certs for
curl -s "https://crt.sh/?q=%25.example.com&output=json" | jq -r '.[].name_value' | sort -u
```

## Service fingerprinting feeds detection
Knowing the exact product + version of each exposed service lets you (a) prioritize patching against KEV ([vuln mgmt](../2-hardening/01-vulnerability-management.md)), and (b) write precise detections for that service's known attack patterns.

## Change = ticket
Every legitimate new service has a change record. Detection content then treats *un-ticketed* new services/ports as incidents. Wire the service inventory to the change-management feed so the "new listener" alert fires only on unauthorized changes.
