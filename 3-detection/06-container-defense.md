# 06 — Container & Cloud Defense

Mirror of container escape: detect escape attempts and misconfigurations before they become host compromise.

## Container runtime signals
- A process in a container spawning host-namespace activity, mounting the host filesystem, or writing to `/proc/*/root`.
- Access to the Docker socket (`/var/run/docker.sock`) from inside a container = effectively root on the host. Alert on it.
- `cap_sys_admin`, `--privileged`, hostPath mounts, `hostPID/hostNetwork` — inventory and alert on pods/containers that request them.

```bash
# Flag privileged or host-mounting pods
kubectl get pods -A -o json | jq -r '.items[] |
  select(.spec.containers[].securityContext.privileged==true or (.spec.volumes[]?.hostPath)) |
  .metadata.namespace + "/" + .metadata.name'
```

## Runtime policy
- **Falco** for syscall-level runtime detection (shell in container, sensitive mount, outbound from a pod that shouldn't talk out).
- Admission control (OPA/Gatekeeper or Pod Security Standards) to *prevent* privileged/hostPath workloads — prevention beats detection here.

## Cloud audit logs
- CloudTrail / Azure Activity / GCP Audit are your AD-equivalent for cloud. Alert on: new IAM user/key, policy attachment granting `*:*`, console login without MFA, disabling of logging, snapshot/share of a disk to an external account (exfil).
- Baseline API calls per principal; an identity suddenly enumerating everything (`Describe*`/`List*` spike) is recon.
