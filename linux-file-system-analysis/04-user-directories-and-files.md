# 04 — User Directories & Files

List home directories and a user's hidden files:
```bash
ls -l /home
ls -a /home/jane
```

Hidden files worth checking:
- `.bash_history` — the user's command history.
- `.bashrc` / `.profile` — shell-session and login-environment config.
- `.ssh/authorized_keys` — SSH public keys allowed to log in as that user.

## authorized_keys abuse (the finding in this room)
```bash
ls -al /home/jane/.ssh
cat /home/jane/.ssh/authorized_keys
stat /home/jane/.ssh/authorized_keys
```
The `authorized_keys` file contained an unintended public key labelled **"backdoor"**, and its permissions were far too open (`rw-rw-rw-`). Those permissions let the attacker append their own key, granting SSH access as Jane.

Mitigation: fix permissions on sensitive files like `authorized_keys`, audit their contents regularly, and restrict who can modify them.
