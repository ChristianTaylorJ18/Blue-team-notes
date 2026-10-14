# 06 — Container & Cloud Defense

Mirror of container escape: detect escape attempts and the misconfigurations that enable them, and treat cloud audit logs as your control-plane equivalent of AD logs.

## Container runtime signals — T1611 / T1610
- A process in a container entering host namespaces, mounting the host filesystem, or writing to `/proc/<pid>/root`, `/host`, or a mounted `docker.sock`.
- **Docker socket access** (`/var/run/docker.sock`) from inside a container = effectively root on the host — alert on it unconditionally.
- Workloads requesting `--privileged`, `CAP_SYS_ADMIN`, `hostPID`/`hostNetwork`/`hostIPC`, or `hostPath` mounts — inventory them and alert on new ones.
- Spawning a shell inside a container that normally runs one static process; package-manager or compiler use at runtime; outbound from a pod that should never egress.

```bash
# Privileged or host-mounting pods right now
kubectl get pods -A -o json | jq -r '.items[] |
  select((.spec.containers[].securityContext.privileged==true) or (.spec.volumes[]?.hostPath)) |
  .metadata.namespace + "/" + .metadata.name'
```

## Runtime policy & prevention
- **Falco** (or EDR with container support) for syscall-level runtime detection: shell-in-container, sensitive mount, unexpected egress, write to a read-only rootfs.
- **Admission control** to *prevent* the dangerous shapes: OPA/Gatekeeper or Pod Security Standards (restricted) blocking privileged/hostPath/hostNetwork. Prevention beats detection here — most escapes need one of these misconfigs.
- Image hygiene: scan images in CI, pin digests, run non-root, read-only rootfs, drop capabilities.

## Cloud audit logs = your cloud AD
CloudTrail / Azure Activity + Entra sign-in / GCP Audit are the control-plane record. Alert on:
- New IAM user/access-key creation; policy attachment granting `*:*` or `AdministratorAccess`.
- Console/portal login **without MFA**, impossible travel, or from anomalous ASN; `GetSessionToken`/`AssumeRole` anomalies.
- **Logging disabled** (`StopLogging`, `DeleteTrail`, config-recorder off) — a classic first move; alert high.
- Snapshot created then **shared to an external account**, or a bucket/disk made public (exfil via cloud primitives — T1537).
- Security-group opened to `0.0.0.0/0` on management ports; new federation/identity-provider or app-consent grant.
- Baseline API calls per principal; a sudden `Describe*`/`List*` spike is enumeration/recon (T1526).

## Tie identity across planes
A compromised cloud identity and a compromised on-prem identity are often the same person (hybrid). Correlate Entra/Okta sign-ins with on-prem 4624s for the same user to catch movement across the boundary.
