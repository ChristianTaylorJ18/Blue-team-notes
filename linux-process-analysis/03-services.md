# 03 — Services

Services are background daemons, usually managed by `systemd` via `systemctl`. Attackers create or modify services for persistence / startup execution.

## Enumerate
```bash
sudo systemctl list-units --all --type=service              # all services
sudo systemctl list-units --type=service --state=running    # running only
```
Scan for units that look out of place vs baseline. Room finding: `b4ckd00rftw.service` with a blank description stood out.

## Investigate a suspicious service
```bash
sudo systemctl status b4ckd00rftw.service
```
Status gives **Main PID**, state, start time, and the **CGroup** process tree — revealing the executable path (`/usr/local/bin/b4ckd00rftw.sh`) and that it loops with `sleep 60`. Read the script:
```bash
cat /usr/local/bin/b4ckd00rftw.sh
```
It re-created a sudo user `b4ckd00rftw` every 60s — persistence that survives deleting the backdoor account. (Why you rebuild from known-good backups, not clean live.)

## Unit file
Usually in `/etc/systemd/system/`. Status gave the exact path:
```bash
cat /etc/systemd/system/b4ckd00rftw.service
```
Key field: `ExecStart=` is the binary/script run on start. `Restart=always` + `WantedBy=multi-user.target` = persistent across boots.

## Service logs
```bash
sudo journalctl -u b4ckd00rftw.service      # -f to follow live
```
Shows the service's actions with timestamps (e.g. the repeated `useradd`/`usermod`), useful for confirming malicious behaviour in real time.
