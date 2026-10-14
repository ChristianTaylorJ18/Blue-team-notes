# 04 — Linux Compromise

**Trigger:** suspect Linux host (alert, odd outbound, new account, web-shell handoff). Counterpart to Linux privesc/persistence.

- [ ] **Preserve first** if it may matter: capture RAM (`avml mem.lime`) before isolating/rebooting ([forensics](../4-incident-response/06-forensic-preservation.md)).
- [ ] Start a `script -f` log so your actions are separable from the attacker's.
- [ ] Volatile state ([linux triage](../4-incident-response/01-linux-triage.md)):
```bash
ps auxww; ss -tulpnae
ls -l /proc/*/exe 2>/dev/null | grep deleted   # running deleted binary = malware tell
```
- [ ] Accounts & escalation:
```bash
awk -F: '$3==0{print $1}' /etc/passwd            # UID-0 accounts — any beyond root = backdoor
find / -perm -4000 -type f 2>/dev/null           # SUID (privesc leftovers)
grep -Ei "accepted|sudo|su:" /var/log/auth.log | tail -50
```
- [ ] Persistence sweep ([persistence hunting](../4-incident-response/04-persistence-hunting.md)):
```bash
for f in /etc/crontab /etc/cron.*/* /var/spool/cron/*; do echo "== $f"; cat "$f" 2>/dev/null; done
find /etc/systemd /lib/systemd -name '*.service' -newermt '-14 days' -ls
cat /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys 2>/dev/null
cat /etc/ld.so.preload 2>/dev/null               # LD_PRELOAD rootkit tell
grep -RnE "/dev/tcp|curl|wget|base64 -d|python -c" /etc/profile* /home/*/.bashrc /root/.bashrc 2>/dev/null
```
- [ ] What did it talk to? Map outbound to new destinations; add C2 IPs/domains to IOCs.
- [ ] Scope laterally: SSH `known_hosts`/history for where this host connected; reused keys/creds → [06](./06-credential-incident.md).
- [ ] For confirmed deep compromise (rootkit, kernel module, UID-0 backdoor): plan **rebuild from known-good image**, not clean.
- [ ] Hand to [07-containment](./07-containment.md).
