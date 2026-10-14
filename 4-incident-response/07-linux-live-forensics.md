# 07 — Linux Live Forensics & Artefact Hunting

Hands-on live analysis of a suspect Linux host: find the attacker's files, read their metadata and timestamps, hunt backdoor accounts and persistence, verify binary integrity, and sweep for rootkits. This is the artefact-level complement to [Linux Triage](./01-linux-triage.md) — triage captures volatile state; this note digs through the filesystem for what the attacker left behind.

> Live analysis changes the system (reading a file updates its `atime`, your commands leave shell history). Capture a forensically sound image/backup *first* where it matters, and treat the live box as evidence you are disturbing, not a system to repair. Don't remediate a live compromised host for reuse — restore from clean backups afterward.

## Work from known-good binaries
A compromised host may have trojaned `ls`, `find`, `ps`, `netstat`. Mount clean, trusted binaries and point your shell at them before you trust any output:

```bash
# Clean Debian-based /bin /sbin /lib /lib64 mounted at /mnt/usb
export PATH=/mnt/usb/bin:/mnt/usb/sbin
export LD_LIBRARY_PATH=/mnt/usb/lib:/mnt/usb/lib64
```

## Finding the foothold (web upload to shell)
If the entry was a file-upload vuln, the uploaded payload and dropped tools are the first artefacts:

```bash
# Non-image files in the web upload dir (webshells hide among JPEGs)
ls -al /var/www/html/uploads | grep -vi '\.jpe\?g$'
# A one-liner PHP/phtml webshell looks like: <?php system($_GET['cmd']);?>
cat /var/www/html/uploads/<suspect>.phtml

# Everything the web user owns - dropped reverse shells, staged tools
find / -user www-data -type f 2>/dev/null | less
```
A standalone ELF under the web root owned by `www-data` (e.g. `assets/reverse.elf`) executable by all is a classic dropped reverse shell (often a Meterpreter payload). ATT&CK: T1505.003 (web shell), T1059 (command exec).

## High-value `find` patterns
```bash
find / -user <user> -type f 2>/dev/null          # files owned by a (service) account
find / -group <group> 2>/dev/null                # files owned by a group
find / -perm -o+w -type f 2>/dev/null            # world-writable files
find / -perm -u=s -type f 2>/dev/null            # SUID binaries (privesc surface)
find / -type f -cmin -5 2>/dev/null              # metadata-changed in last 5 min
find / -type f -mmin -5 2>/dev/null              # contents-modified in last 5 min
find /home/<user> -newermt '-1 min' -type f 2>/dev/null   # recent drops by a user
```
Append `2>/dev/null` to suppress permission-denied noise. World-writable dirs attackers favour: `/tmp`, `/var/tmp`, `/dev/shm`.

## Metadata, checksums, timestamps
```bash
exiftool /path/suspect.elf          # type, size, arch, perms, timestamps
md5sum  /path/suspect.elf           # hash -> submit to VirusTotal / your TI
sha256sum /path/suspect.elf
```
Unix timestamps and how to read each:
| Timestamp | Meaning | Command |
|-----------|---------|---------|
| **mtime** | contents last modified | `ls -l <f>` |
| **ctime** | metadata (perms/owner/name) last changed | `ls -lc <f>` |
| **atime** | last accessed/read | `ls -lu <f>` |

```bash
stat /path/suspect.elf    # all three at once - build your timeline from mtime/ctime
```
`atime` is unreliable during live IR — *your own* reads (exiftool, md5sum, cat) update it. Lean on `mtime`/`ctime` for the attacker timeline. Attackers may also timestomp; corroborate with logs and the inode change time (`ctime`), which is harder to forge.

## Backdoor accounts, groups, sudo
```bash
# Any UID-0 account other than root = backdoor
cat /etc/passwd | cut -d: -f1,3 | grep ':0$'
awk -F: '$3==0{print $1}' /etc/passwd
# Who is in privileged groups
getent group sudo ; getent group 27 ; getent group 46
# Full sudoers - look for added users / overly broad NOPASSWD / dangerous binaries
cat /etc/sudoers /etc/sudoers.d/* 2>/dev/null
```
Login/activity history (reads wtmp/btmp/lastlog + auth log):
```bash
last           # successful logins/sessions (/var/log/wtmp)
lastb          # failed logins (/var/log/btmp)
lastlog        # most-recent login per account
who            # currently logged on, with source IP
grep -Ei 'accepted|sudo|su:|session opened' /var/log/auth.log | tail -50
```

## Home-directory artefacts
```bash
ls -al /home/<user>                          # ownership, unexpected files
cat /home/<user>/.bash_history               # attacker commands (if not cleared/linked to /dev/null)
ls -al /home/<user>/.ssh/
cat /home/<user>/.ssh/authorized_keys        # unexpected/"backdoor" keys = SSH persistence
stat /home/<user>/.ssh/authorized_keys       # when was the key added?
```
A world-writable `authorized_keys` (`rw-rw-rw-`) is the misconfig that lets any user append a key — a common SSH-persistence foothold. ATT&CK: T1098.004 (SSH authorized_keys), T1552.004 (private keys).

## Binary integrity & SUID abuse
```bash
# Executables owned by root (unexpected ones are suspect)
find / -type f -executable -user root 2>/dev/null
# Package integrity - flag modified files shipped by a package
sudo debsums -c -e            # -c: changed only, -e: config files only
sudo debsums -e -s            # config files, silence errors
# Strings in a suspect binary - function names, embedded IPs, messages
strings /var/tmp/suspect | less
md5sum /var/tmp/bash          # SUID-root copy of bash in a temp dir = privesc backdoor
```
Correlate SUID abuse with shell history, e.g. `grep -B2 -A2 'python\|find\|cp\|chmod' /home/<user>/.bash_history`.

## Rootkit sweep
```bash
sudo chkrootkit                 # quick checks for known rootkit files/patterns (.sh droppers, etc.)
sudo rkhunter --update          # refresh signatures first
sudo rkhunter -c -sk            # fuller check: file hashes vs known-good, perms, hidden files,
                                #   suspicious kernel-module strings, and the (UID 0) accounts check
```
`chkrootkit` is the fast first pass; `rkhunter` is the thorough one — run both. Neither is definitive against a modern kernel rootkit, so corroborate with memory analysis and known-good hash comparison. ATT&CK: T1014 (rootkit).

## From artefacts to timeline
Collect each finding (path, hash, mtime/ctime, owner) into the case log and order by `ctime`/`mtime`. The sequence — upload time of the webshell, drop time of the ELF, key added to `authorized_keys`, SUID binary created, backdoor account added — *is* the intrusion story, and it drives scope and [containment](./05-containment-eradication.md). Then feed the hashes/paths/accounts into your estate-wide IOC sweep.
