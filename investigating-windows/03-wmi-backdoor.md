# 03 — WMI Event-Subscription Backdoor

A fileless-ish persistence technique: a WMI **event subscription** watches for an event and runs an action when it fires. ATT&CK T1546.003. Here it was used to kill a defender's analysis tool.

## The symptom
Launching **Process Explorer** (`procexp64.exe`) made it close immediately — something was watching for it and killing it.

## The mechanism
A WMI permanent event subscription has three parts:
- **`__EventFilter`** — the trigger (named `ProcessStartTrigger` here), defined by a WQL query.
- **`CommandLineEventConsumer`** (or similar) — the action taken.
- **`__FilterToConsumerBinding`** — binds the filter to the consumer.

The filter's WQL query:
```sql
SELECT * FROM Win32_ProcessStartTrace WHERE ProcessName = 'procexp64.exe'
```
i.e. "when `procexp64.exe` starts, fire" → the consumer kills it. That's why Process Explorer wouldn't stay open.

## Tracing it back
- From the LOKI output, a backup **VBScript** implemented the same thing. Its metadata named the vendor **Motobit Software** (`motobit.com`, `Motobit.cz`) and a second script `LaunchBeaconingBackdoor`.
- Searching the script name + vendor online surfaced the public attack script **`WMIBackdoor.ps1`**, which matched the file found at **`C:\TMP`**.

## Hunting WMI persistence yourself
```powershell
Get-WmiObject -Namespace root\subscription -Class __EventFilter
Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer
Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding
```
Lesson: a tool that crashes on launch is a red flag — check WMI subscriptions (and LOKI's `WMIScan`) for a `Win32_ProcessStartTrace` filter targeting your analysis tools.
