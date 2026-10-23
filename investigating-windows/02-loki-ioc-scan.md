# 02 — LOKI IOC Scan

**LOKI** is an IOC/YARA scanner — run it to triage a host for known-bad files, hacktools, and suspicious artefacts instead of opening every tool by hand.

## Running it
- Save output to a log file so you can search it for answers:
```
loki.exe -p C:\ > loki_output.txt
```
- The scan takes a while — keep an eye on the prompt moving (it means it's still running). You can stop it once it reaches the `ntds.dit` warnings.

## Reading the output
- Each hit has a level (`NOTICE` / `WARNING` / `ALERT`), the matched file, the **reason/description**, and (for YARA/byte matches) the matched strings or `FIRST_BYTES`.
- The `Init` line names the scan module running — here **`WMIScan`** appeared after `Init`, i.e. LOKI scanned WMI subscriptions.
- WMI-related warnings named an **eventFilter** (`ProcessStartTrigger`) and the class **`__FilterToConsumerBinding`** — the WMI persistence pieces (see [WMI Backdoor](./03-wmi-backdoor.md)).

Lesson: LOKI is the fast first pass — it points you at files and artefacts to investigate deeper, and its reasons ("Known Bad / Dual use classics", "APT Cloaked", "Stuff running where it normally shouldn't") tell you *why* each was flagged.
