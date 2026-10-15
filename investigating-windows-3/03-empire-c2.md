# 03 — Empire C2 Profile

Identifying the command-and-control framework from a second decoded payload and its comms profile.

## Finding the payload's process
Examining running processes, the one running the encoded payload had **PID 3088**. Decoding its payload showed a visible partial path:
```
/admin/get.php
```

## Attributing the framework
The default comms profile variable was **`DefaultProfile`**, which identifies the framework as **Empire** (PowerShell Empire).
- Other URIs you'd expect in the logs from Empire's default profile: **`/news.php`**, **`/login/process.php`** (alongside `/admin/get.php`).
- MITRE ATT&CK software entry for Empire: **https://attack.mitre.org/software/S0363/**

## Attacker infrastructure
The suspicious process connected out to the attacker FQDN:
```
ec2-34-245-128-161.eu-west-1.compute.amazonaws.com
```
(An AWS EC2 host in eu-west-1.)

Lesson: Empire's default malleable profile leaves recognizable URI patterns (`/admin/get.php`, `/news.php`, `/login/process.php`) and a `DefaultProfile` string — matching those in network/process logs attributes the C2 and gives you IOCs (the FQDN) to sweep.
