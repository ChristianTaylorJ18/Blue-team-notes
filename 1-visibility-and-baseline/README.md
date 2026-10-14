# 1. Visibility & Asset Baseline

You cannot defend what you cannot see. Before any detection or hardening work, establish a ground-truth picture of what you own, what's talking to what, and what each system is logging. This is the defensive mirror of recon: the attacker enumerates your footprint, so you should know it better than they ever will.

## Sections
1. [Asset Inventory](./01-asset-inventory.md) — authoritative host/IP/owner inventory, discovery, drift detection.
2. [Network Visibility](./02-network-visibility.md) — taps/SPAN, NetFlow, east-west vs north-south, segmentation map.
3. [Logging Baseline](./03-logging-baseline.md) — what "normal" looks like, baselining before you alert.
4. [Service Inventory & Attack Surface](./04-service-inventory.md) — known-good services per host, external exposure.
5. [Log Sources & Retention](./05-log-sources.md) — which logs matter, where they go, how long you keep them.
6. [Active Directory Visibility](./06-active-directory-visibility.md) — privileged groups, trusts, GPO, delegation inventory.

> "The attacker only has to find one thing you forgot you had. Your job in this stage is to forget nothing." Inventory first — most incidents get worse because of an asset nobody was watching.
