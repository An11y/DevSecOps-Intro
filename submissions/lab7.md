# Lab 7 — Anton Bugaev (CBS-03) — an.bugaev@innopolis.university

**Deliverables:** Task 1 (Trivy image + Dockerfile) · Task 2 (PSS `restricted` + NetworkPolicy) · **Bonus Task** (`readOnlyRootFilesystem: true`, +2 pts)

## Task 1

### Severity counts and fix availability

```bash
trivy image bkimminich/juice-shop:v20.0.0 --severity HIGH,CRITICAL \
  --format json --output labs/lab7/results/trivy-image.json
```

| Severity | Count |
|----------|------:|
| CRITICAL | 10 |
| HIGH | 64 |
| **Total (HIGH+CRITICAL)** | **74** |

Of those **74** HIGH/CRITICAL findings, **71** list a `FixedVersion` and **3** do not. The no-fix rows are compensating-control territory, not a rebuild ticket for this sprint.

### Lab 4 Grype vs this Trivy image scan

| Tool / scope | CRITICAL | HIGH | HIGH+CRITICAL |
|--------------|--------:|-----:|--------------:|
| Lab 4 Grype (from CycloneDX SBOM) | 14 | 84 | **98** |
| Lab 7 Trivy image (`HIGH,CRITICAL`) | 10 | 64 | **74** |

Grype was fed the Lab 4 SBOM and counted more HIGH/CRITICAL matches (98 vs 74). The scanners disagree on advisory sources, package identity, and severity mapping, and Grype’s SBOM path can surface findings Trivy’s image scanner groups or downgrades differently. Same image, different engines — the delta is expected, not a sign that either run was broken.

### Ten fixable findings (7.2)

```text
CRITICAL	CVE-2023-46233	crypto-js 3.3.0 -> 4.2.0
CRITICAL	CVE-2026-71851	crypto-js 3.3.0 -> 4.0.0
CRITICAL	CVE-2015-9235	jsonwebtoken 0.1.0 -> 4.2.2
CRITICAL	CVE-2015-9235	jsonwebtoken 0.4.0 -> 4.2.2
CRITICAL	CVE-2019-10744	lodash 2.4.2 -> 4.17.12
CRITICAL	CVE-2026-59873	tar 4.4.19 -> 7.5.19
CRITICAL	CVE-2026-59873	tar 6.2.1 -> 7.5.19
CRITICAL	CVE-2026-59873	tar 7.5.15 -> 7.5.19
HIGH	CVE-2026-14456	libssl3t64 3.5.5-1~deb13u2 -> 3.5.7-1~deb13u2
HIGH	CVE-2026-45447	libssl3t64 3.5.5-1~deb13u2 -> 3.5.6-1~deb13u2
```

### Dockerfile findings (`trivy config`)

Demo `Dockerfile`: `FROM node:latest` / `USER root` / `EXPOSE 22` / remote `ADD`.

| ID | Severity | What an attacker gains |
|----|----------|------------------------|
| `DS-0001` | MEDIUM | Untagged `node:latest` can silently change; you may pull a compromised or broken base without noticing. |
| `DS-0002` | HIGH | Final `USER root` means a process breakout starts as root inside the container, which is the usual first step toward container escape / host impact. |
| `DS-0004` | MEDIUM | Publishing SSH (22) expands the attack surface for remote login if something actually listens there. |
| `DS-0026` | LOW | No `HEALTHCHECK` does not grant access by itself; it hides unhealthy instances so traffic keeps hitting a broken or partially compromised process. |

### No-fix vulnerabilities — what to tell a manager

A non-zero scanner total is normal when upstream has not shipped a patch yet. For those three HIGH/CRITICAL rows without a fix I would: (1) confirm exploitability in *our* runtime (is the package reachable?), (2) add compensating controls — network policy, least privilege, WAF/rate limits, monitoring — and (3) track the CVE until a fixed base or dependency lands, then rebuild. Telling a manager “the number is not zero because nobody patched upstream yet, and rebuilding cannot invent a fix that does not exist” is honest; promising zero findings without a rebuild pipeline and vendor patches is not.

## Task 2

### Namespace labels and securityContext blocks

Namespace `juice-shop` labels:

```text
pod-security.kubernetes.io/enforce=restricted
pod-security.kubernetes.io/warn=restricted
pod-security.kubernetes.io/audit=restricted
```

Pod `securityContext`:

```yaml
runAsNonRoot: true
runAsUser: 65532
runAsGroup: 65532
fsGroup: 65532
seccompProfile:
  type: RuntimeDefault
```

Container `securityContext` (app):

```yaml
allowPrivilegeEscalation: false
readOnlyRootFilesystem: true
capabilities:
  drop: ["ALL"]
```

Dedicated ServiceAccount `juice-shop` with `automountServiceAccountToken: false` on both the ServiceAccount and the pod spec. Image pinned by digest:

`bkimminich/juice-shop@sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0`

(`docker inspect … --format '{{.Config.User}}'` → `65532`, matching `runAsUser`.)

### Proof the pod runs as the image user

```bash
kubectl -n juice-shop wait --for=condition=ready pod -l app=juice-shop --timeout=180s
# READY 1/1 Running, 0 restarts

kubectl -n juice-shop get pod -l app=juice-shop \
  -o jsonpath='runAsUser={.items[0].spec.securityContext.runAsUser}{"\n"}'
# runAsUser=65532
```

(The distroless-style image has no `id` binary; the admitted pod spec is the authoritative UID.)

### Trivy k8s: plain vs restricted

| Namespace | Resource | Vulns C/H | Misconfig C/H |
|-----------|----------|-----------|---------------|
| `juice-plain` | Deployment/juice | 10 / 64 | 0 / **3** |
| `juice-shop` | Deployment/juice-shop | 20 / 128 | 0 / **0** |

Misconfigurations drop from **3 HIGH** on the default Deployment to **0** once PSS `restricted` + explicit `securityContext` / SA / limits are in place — that is the hardening Trivy can see. Vulnerability counts look higher on `juice-shop` only because the Deployment has **two** containers (init + app) that each pull the **same** image, so Trivy tallies the image findings twice (10+64 → 20+128). Per-image the CRITICAL/HIGH set is unchanged; only a rebuild changes those.

### What `restricted` blocked vs what I added voluntarily

- **Blocked by the profile:** creating a pod with `allowPrivilegeEscalation: true` is rejected:

```text
pods "bad-priv" is forbidden: violates PodSecurity "restricted:latest": allowPrivilegeEscalation != false (container "juice" must set securityContext.allowPrivilegeEscalation=false)
```
- **Voluntary (profile does not require it):** `readOnlyRootFilesystem: true` (bonus), plus the NetworkPolicy default-deny with only client-labelled ingress on 3000 and DNS egress to `kube-dns`.

## Bonus

### `docker diff` (paths that matter)

```text
C /juice-shop/logs          (+ access/audit logs)
C /juice-shop/data           (+ juiceshop.sqlite)
C /juice-shop/i18n           (+ locale JSON)
C /juice-shop/frontend/dist/frontend  (assets / index touched)
C /juice-shop/ftp            (+ legal.md)
C /juice-shop/.well-known    (CSAF metadata)
```

Also need writable `/tmp` for Node temp files.

### Volume layout

One `emptyDir` (`writable-paths`) with subPaths for `data`, `ftp`, `logs`, `i18n`, `frontend`, `wellknown`, and `tmp`. An initContainer from the **same digest** copies those directories from the image into the emptyDir (`fs.cpSync`), then the app mounts each subPath over the original path with `readOnlyRootFilesystem: true`.

### Directory that could not be a blank emptyDir

`/juice-shop/ftp`, `/juice-shop/i18n`, `/juice-shop/frontend/dist/frontend`, and `.well-known` already ship files in the image. Mounting a fresh emptyDir there hides them and the process exits. Seeding via initContainer preserves the shipped content while still allowing writes on top.

### Proof: Ready + HTTP 200

```text
pod READY 1/1, readOnlyRootFilesystem=true, runAsUser=65532
kubectl -n juice-shop port-forward deploy/juice-shop 13000:3000
curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:13000/
# 200
```
