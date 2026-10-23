# 02 — Cronjobs

Cron runs scheduled tasks via the cron daemon, configured in crontab files. Attackers abuse cron for persistence and privesc.

Cron syntax: `min hour day-of-month month day-of-week command` (system crontab adds a **user** field before the command).
```
10 05 * * * /home/bob/backup_tmp.sh      # 5:10 AM daily
*/5 * * * * root /var/tmp/backup          # every 5 min, as root (system crontab)
```

## System cron locations
```bash
cat /etc/crontab                 # main system-wide cronjobs
ls /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly
```
Room finding: `/etc/crontab` ran `/var/tmp/backup` every 5 min **as root** — `/var/tmp` is world-writable, so any user can modify it (privesc/persistence). The script appended a malicious `curl ... | sh` pulling an XMRig cryptominer installer. Always `cat` the referenced scripts, not just list them.

## User cron locations
```bash
sudo ls -al /var/spool/cron/crontabs/    # one file per user
sudo crontab -l -u janice                # view a user's cron
```
Loop every user's crontab in one shot:
```bash
sudo bash -c 'for user in $(cut -f1 -d: /etc/passwd); do entries=$(crontab -u $user -l 2>/dev/null | grep -v "^#"); if [ -n "$entries" ]; then echo "$user: Crontab entry found!"; echo "$entries"; echo; fi; done'
```

## Cron execution logs
Debian/Ubuntu → `/var/log/syslog`; RHEL/CentOS → `/var/log/cron`.
```bash
sudo grep cron /var/log/syslog
sudo grep cron /var/log/syslog | grep -E 'failed|error|fatal'   # anomalies
sudo grep cron /var/log/syslog | grep -i 'bob'                  # per user (shows EDIT/REPLACE/RELOAD timestamps)
```

## pspy — real-time process monitor (no root needed)
Reads `/proc`, catches short-lived processes and cron-spawned commands.
```bash
pspy64        # let it run a few minutes; Ctrl+C to stop
```
Surfaces cronjobs firing (e.g. the janice bind-shell script) as they execute — great for catching scheduled malicious activity live.
