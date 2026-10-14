# 01 — Linux Triage

Mirror of Linux privesc / persistence. First goal on a suspect Linux host: capture volatile state, then look for the footholds a privesc chain leaves behind. Collect read-only first.

## Capture volatile state (before anything changes it)
```bash
date; uptime; w; last -20            # who is / was on
ps auxww                             # full process list with args
ss -tulpnae                          # listeners + established, with PID/UID
ls -l /proc/*/exe 2>/dev/null | grep -E "deleted"   # running-but-deleted binaries = classic malware
lsof -nP | grep -E "LISTEN|ESTABLISHED"
```

## Where footholds hide
```bash
# Unexpected SUID (privesc leftovers)
find / -perm -4000 -type f 2>/dev/null
# Cron across all locations
for f in /etc/crontab /etc/cron.*/* /var/spool/cron/*; do echo "== $f"; cat "$f" 2>/dev/null; done
# Systemd units recently changed
systemctl list-unit-files --state=enabled
find /etc/systemd /lib/systemd -name '*.service' -newermt '-14 days' -ls
# SSH persistence
cat /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys 2>/dev/null
# Shell-profile backdoors
grep -RnE "curl|wget|/dev/tcp|base64 -d|python -c" /etc/profile* /home/*/.bashrc /root/.bashrc 2>/dev/null
```

## Accounts & logs
```bash
awk -F: '$3==0{print $1" is UID 0"}' /etc/passwd    # any non-root UID-0 account = backdoor
awk -F: '$2!~/^[*!]/{print $1}' /etc/shadow         # accounts with real password hashes
grep -Ei "accepted|sudo|su:" /var/log/auth.log | tail -50
journalctl -k | grep -i -E "segfault|audit" | tail
```

## Note what you touch
You are changing the system by investigating it. Log every command you run with timestamps (`script -f`), so the forensic timeline can separate your actions from the attacker's.
