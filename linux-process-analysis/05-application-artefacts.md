# 05 — Application Artefacts

Data applications leave behind — config, logs, cache, history — useful for reconstructing activity. Build a methodology; the possibilities are endless.

## Installed packages
```bash
sudo dpkg -l           # all packages installed via the package manager
```
Note: only catches package-manager installs; manually-installed programs need filesystem analysis.

## Vim — .viminfo
Stores Vim version, last search pattern, command-line history — can reveal files tampered with and commands run.
```bash
find /home/ -type f -name ".viminfo" 2>/dev/null
sudo cat /home/janice/.viminfo
```
Similar: `.nano_history` (Nano), `.emacs` / `.emacs.d` (Emacs).

## Browser artefacts
History, downloads, cookies, bookmarks reveal visited sites, downloaded files, C2 contact.
- Firefox: `~/.mozilla/firefox/`
- Chrome: `~/.config/google-chrome/`
```bash
sudo find /home -type d \( -path "*/.mozilla/firefox" -o -path "*/.config/google-chrome" \) 2>/dev/null
sudo ls -al /home/eduardo/.mozilla/firefox     # pick the .default-release profile (not legacy .default)
```

### Dumpzilla (Firefox parser)
```bash
sudo python3 dumpzilla.py <profile>.default-release --Summary --Verbosity CRITICAL
sudo python3 dumpzilla.py <profile>.default-release --Cookies
# other options: --Addons --Search --Bookmarks --Downloads --History
```
Use sudo (profiles hold cookies/passwords). Surfaces exfiltrated data, stolen cookies, submitted forms, C2 contact.

## Other artefacts by system role
- Workstation: email client stores, word-processor recent/temp files, tmux/screen.
- Web server: access/error logs, config, web-app logs (URLs, user-agents, responses), CMS DBs (WordPress/Joomla).
- DB server: DB logs, config, SQL query logs.
Enumerate what's actually installed first, then go after that app's artefacts.
