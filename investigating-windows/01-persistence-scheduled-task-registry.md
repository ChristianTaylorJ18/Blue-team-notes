# 01 — Scheduled Task & Registry Persistence

Two persistence mechanisms that point at the same command — a common pattern worth cross-checking.

## Scheduled task
Open **Task Scheduler** and review tasks. A malicious task ran a credential-dumping command (`mim.exe` with a `sekurlsa`-style argument — Mimikatz-style).

## Matching registry logon script
Search **regedit** for that same command. It also lives in a logon-script registry value:
```
HKCU\Environment\UserInitMprLogonScript
```
> Uncertainty flagged: the room's answer key spells it `UserIntMprLogonScript`, but the real Windows value name is **`UserInitMprLogonScript`** (note the second `i` in `Init`). Go with `UserInitMprLogonScript`; the room text appears to have a typo.

`UserInitMprLogonScript` runs its command at user logon — a classic persistence spot (ATT&CK T1037.001, Logon Script).

## Cross-check with Autoruns
**Autoruns** (Sysinternals) surfaces autostart entries across tasks, registry Run keys, logon scripts, services, etc. in one view — use it to confirm the task/registry findings and catch anything missed.

Lesson: when a scheduled task and a registry value execute the *same* command, that's redundancy the attacker built for resilience — remove both.
