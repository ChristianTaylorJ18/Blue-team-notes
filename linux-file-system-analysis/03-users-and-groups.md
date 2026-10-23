# 03 — Users & Groups

## Backdoor accounts (UID 0)
Any account other than `root` with UID 0 is a backdoor with root privileges.
```bash
cat /etc/passwd | cut -d: -f1,3 | grep ":0$"
```

## Group membership
Users in critical groups like `sudo`/`wheel`:
```bash
getent group sudo
getent group 27        # by GID (sudo is usually 27)
cat /etc/group
```

## Login & activity history
```bash
last       # successful logins/sessions   (/var/log/wtmp)
lastb      # failed login attempts        (/var/log/btmp)
lastlog    # most recent login per user   (/var/log/lastlog)
who        # currently logged-in users, terminal, time, source IP
```
Also check `/var/log/auth.log` (or `/var/log/secure` on some distros) for authentication events, including failures.

## /etc/sudoers
Defines sudo privileges. Format:
```
username    host=(user_to_run_as) command_to_run
# e.g.  richard   ALL=(ALL) /sbin/ifconfig
```
Attackers abuse it by inserting their own account or widening an existing entry to run commands as root. Audit `/etc/sudoers` (and `/etc/sudoers.d/`) for unauthorized changes, restrict access to the file, and keep permissions/integrity tight.
