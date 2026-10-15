# 04 — Autostart Scripts

Scripts/commands that run automatically at boot or user login. Attackers abuse them for persistence, backdoors, or privesc.

## System-wide autostart
- `/etc/init.d/` — SysV init service scripts.
- `/etc/rc.d/`
- `/etc/systemd/system/` — systemd unit files (see [Services](./03-services.md)).

## User autostart (`.desktop` files)
Run at login; live in `~/.config/autostart/`, format is a `.desktop` file with an `Exec=` line.
```bash
ls -a /home/*/.config/autostart            # enumerate for all users
cat /home/janice/.config/autostart/keygrabber.desktop
```
Room finding — a `.desktop` named innocuously ("Standard Desktop Configuration (DO NOT MODIFY)") whose `Exec=` ran `curl -X POST` sending `/home/janice/.ssh/id_rsa` (her **private SSH key**) to an attacker URL on startup. Read the `Exec=` line, not the `Name=`.

Example `.desktop`:
```
[Desktop Entry]
Type=Application
Name=Setup Development Environment
Exec=/bin/bash -c "/home/eduardo/setup_dev_env.sh"
```

## Other user config worth checking
- `~/.bash_history` — command history.
- `~/.ssh` — `id_rsa`, `id_rsa.pub`, `known_hosts`, `authorized_keys`.
- `~/.profile` / `.bashrc` — login/shell init; can hide malicious commands.
- **MOTD**: `/etc/update-motd.d/` and `/usr/lib/update-notifier/` — scripts run on SSH login; attackers plant backdoors here for per-login persistence.
