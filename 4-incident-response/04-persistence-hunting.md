# 04 — Persistence Hunting

Mirror of persistence / stealth. Eradication fails if one mechanism survives. Sweep the full autostart surface on every in-scope host, not just the entry point.

## Windows persistence surface (ATT&CK T1053/T1543/T1547/T1546)
- Services, scheduled tasks, Run/RunOnce keys, Startup folders.
- **WMI event subscriptions** (`__EventFilter` + `CommandLineEventConsumer`) — stealthy, survives reboot, missed by casual checks.
- DLL search-order hijacks, IFEO debuggers, AppInit_DLLs, LSA providers, netsh helpers.
- New local admin / re-enabled default accounts; SID-history additions.

```powershell
# WMI subscription persistence — dump all three classes
Get-CimInstance -Namespace root\subscription -Class __EventFilter
Get-CimInstance -Namespace root\subscription -Class CommandLineEventConsumer
Get-CimInstance -Namespace root\subscription -Class __FilterToConsumerBinding
```

## Linux persistence surface
- cron (all dirs + per-user), systemd services + timers, `rc.local`, init scripts.
- SSH `authorized_keys`, trusted CA, `~/.ssh/config` ProxyCommand tricks.
- Shell rc files, `/etc/profile.d/`, `LD_PRELOAD` in `/etc/ld.so.preload`.
- SUID binaries, new UID-0 accounts, PAM module tampering, malicious kernel modules (`lsmod` vs known-good).

## AD / domain persistence
- krbtgt-based golden tickets (rotate twice to kill), silver tickets, forged certs (AD CS).
- AdminSDHolder / ACL backdoors granting rights that re-apply via SDProp.
- GPO-based autostart, logon scripts in SYSVOL.

## Method
1. Snapshot the autostart surface on a known-good image → that's your allowlist.
2. Diff each suspect host against it. The delta is the hunt.
3. For every mechanism found, ask *what dropped it* — don't remove the task and leave the dropper.
