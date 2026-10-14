# 02 — SIEM & Alerting

The pipeline that turns logs into decisions. Treat detections as code: version-controlled, tested, peer-reviewed.

## Pipeline
```
endpoints/network/apps → collector/forwarder → normalize (ECS/CIM) → SIEM → detections → alert queue → triage
```
- Normalize field names early (a user is `user` everywhere, not `AccountName`/`usr`/`SubjectUserName`). Detections written against a schema survive source changes.

## Detection-as-code
- Store rules in git. Each rule: title, hypothesis, ATT&CK ID, data source, logic, false-positive notes, test case.
- **Sigma** as the portable rule format; convert to your backend (`sigma convert -t splunk`). One rule, many SIEMs.

```yaml
title: Encoded PowerShell from Office
logsource: {product: windows, category: process_creation}
detection:
  sel:
    ParentImage|endswith: ['\winword.exe','\excel.exe']
    Image|endswith: '\powershell.exe'
    CommandLine|contains: ['-enc',' -e ','FromBase64String']
  condition: sel
level: high
tags: [attack.execution, attack.t1059.001]
```

## The alert lifecycle
1. Fire → 2. Enrich (auto-add asset owner, user context, reputation) → 3. Triage → 4. Verdict (TP/FP/benign) → 5. Feed verdict back into tuning.
- Track **alert-to-verdict time** and **FP rate per rule**. A rule over its FP budget gets tuned or retired — alert fatigue is how real intrusions get missed.

## Tuning discipline
- Never silence a noisy rule by deleting it. Narrow with allowlists, raise the aggregation, or add a correlating condition.
- Prefer *risk-based alerting*: accumulate low-signal events per entity and alert when a host/user crosses a score, instead of one-event-one-alert.
