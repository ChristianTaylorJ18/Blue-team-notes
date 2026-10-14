# 02 — SIEM & Alerting

The pipeline that turns logs into decisions. Treat detections as code: version-controlled, tested, peer-reviewed, and measured.

## Pipeline
```
endpoints / network / apps / cloud → collector / forwarder → parse + normalize (ECS/CIM)
   → enrich (asset, identity, geo, TI) → detections → risk/alert queue → triage → verdict → tuning
```
- **Normalize early.** A user is `user` everywhere, not `AccountName`/`usr`/`SubjectUserName`. Detections written against a stable schema survive source and vendor changes.
- **Enrich before the analyst sees it.** Auto-attach asset owner + tier, identity context (is this account privileged?), geo, and threat-intel reputation. Every field the analyst would otherwise look up by hand shortens triage and reduces missed detections.

## Detection-as-code
Store rules in git. Each rule carries: title, hypothesis, ATT&CK ID(s), data source + required fields, logic, **expected false-positive source**, test case, and owner. If you can't state the FP source, the rule isn't finished.
- Use **Sigma** as the portable format and convert to your backend (`sigma convert -t splunk rule.yml`). One rule, many SIEMs, reviewable in PRs.

```yaml
title: Encoded PowerShell spawned by Office
logsource: {product: windows, category: process_creation}
detection:
  sel:
    ParentImage|endswith: ['\winword.exe','\excel.exe','\outlook.exe']
    Image|endswith: '\powershell.exe'
    CommandLine|contains: ['-enc',' -e ','FromBase64String','-w hidden']
  condition: sel
falsepositives: [admin logon scripts invoked from mail-merge macros]
level: high
tags: [attack.execution, attack.t1059.001]
```

## Map coverage to ATT&CK
Maintain a coverage matrix (technique → do we have a detection, and from which data source?). The gaps are your detection-engineering backlog, prioritized by what your threat model and real incidents show. Don't mistake *log coverage* for *detection coverage* — collecting Sysmon isn't detecting injection until a rule exists.

## The alert lifecycle
1. Fire → 2. Auto-enrich → 3. Triage → 4. Verdict (TP / FP / benign-TP) → 5. Verdict feeds tuning and, for TPs, the IR process.
- Track **alert-to-verdict time** and **FP rate per rule**. A rule over its FP budget gets tuned or retired — alert fatigue is precisely how real intrusions slip past.

## Risk-based alerting (RBA) beats one-event-one-alert
Accumulate low-signal observations per entity (user/host) with weighted scores and ATT&CK context; raise an incident when an entity crosses a threshold or lights up across multiple tactics. This surfaces the slow, multi-step intrusion that no single event would have flagged, and collapses noisy single-signal rules into context.

## Tuning discipline
Never silence a noisy rule by deleting it. Narrow with allowlists (path+signer), raise the aggregation window, add a correlating condition, or move it into RBA as a contributing signal. Document why.
