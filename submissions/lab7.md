# Lab 7 — Anton Bugaev (CBS-03) — an.bugaev@innopolis.university

**Deliverables:** Task 1 (Trivy image + Dockerfile) · Task 2 (PSS `restricted` + NetworkPolicy) · **Bonus Task** (`readOnlyRootFilesystem: true`, +2 pts)

I scanned Juice Shop and the lab’s intentionally unsafe Dockerfile, then ran the same image under Pod Security `restricted` with a dedicated ServiceAccount, NetworkPolicy, digest pin, and a read-only root filesystem. Manifests: [`labs/lab7/k8s/`](../labs/lab7/k8s/). Raw scanner JSON and runtime evidence stay local in gitignored `labs/lab7/results/` (including `trivy-k8s.json` for Lab 10).

## Environment and reproducibility

| Item | Value |
|------|-------|
| Run date | 27 September 2026 |
| Image | `bkimminich/juice-shop:v20.0.0` |
| Digest (pinned) | `bkimminich/juice-shop@sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0` |
| Image `User` | `65532` (`docker inspect --format '{{.Config.User}}'`) |
| Trivy | 0.74.0 |
| k3d / kubectl | 5.8.3 / 1.34.1 |
| Cluster | `k3d cluster create lab7 --image rancher/k3s:v1.33.0-k3s1` |

## Task 1

### Image vulnerabilities and fix availability

```bash
trivy image bkimminich/juice-shop:v20.0.0 --severity HIGH,CRITICAL \
  --format json --output labs/lab7/results/trivy-image.json
```

Counts are vulnerability/package matches from `.Results[].Vulnerabilities` (secrets excluded). A fix means nonempty `FixedVersion`.

| Severity | Matches | With listed fix | Without listed fix |
|----------|--------:|----------------:|-------------------:|
| CRITICAL | 10 | 8 | 2 |
| HIGH | 64 | 63 | 1 |
| **Total** | **74** | **71** | **3** |

### Lab 4 Grype vs this Trivy scan

| Comparable severity | Lab 4 Grype (from CycloneDX SBOM) | Lab 7 Trivy image |
|---------------------|----------------------------------:|------------------:|
| CRITICAL | 14 | 10 |
| HIGH | 84 | 64 |
| **HIGH + CRITICAL** | **98** | **74** |

Grype’s all-severity total was 182; that must not be compared to a HIGH/CRITICAL-only Trivy run. The 98-vs-74 gap reflects different inventory/matching engines, severity sources, and advisory aliases — not that the unchanged image became safer.

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

Fix versions are per-advisory floors; e.g. `crypto-js` must satisfy both listed thresholds.

### Dockerfile findings (`trivy config`)

Demo file (literally named `Dockerfile`):

```dockerfile
FROM node:latest
USER root
EXPOSE 22
ADD https://example.com/app.tar /
```

| ID | Severity | What an attacker / failure mode gains |
|----|----------|----------------------------------------|
| `DS-0001` | MEDIUM | Mutable `latest` base: rebuilds can silently pick a different or compromised upstream layer. |
| `DS-0002` | HIGH | Final `USER root`: RCE inside the app starts as root in the container (wider filesystem + first step toward escape). |
| `DS-0004` | MEDIUM | `EXPOSE 22` advertises SSH surface if something actually listens; `EXPOSE` alone does not start SSH. |
| `DS-0026` | LOW | No `HEALTHCHECK`: unhealthy/compromised process can keep receiving traffic without a health signal. |

Four failures (1 HIGH, 2 MEDIUM, 1 LOW), as expected. This Trivy version **did not** emit a `DS-*` for the remote `ADD`; I am not inventing one. In a real build that download would still need integrity verification.

### Findings with no fix — what I would tell a manager

The three no-fix HIGH/CRITICAL matches are:

| Severity | ID | Package |
|----------|----|---------|
| CRITICAL | `CVE-2026-53486` | `decompress@4.2.1` |
| CRITICAL | `GHSA-5mrr-rgp6-x4gr` | `marsdb@0.6.11` |
| HIGH | `CVE-2020-8203` | `lodash.set@4.3.2` |

I would confirm reachability in our runtime, then remove/replace the dependency or constrain inputs that hit it. Meanwhile: least privilege, NetworkPolicy, read-only root, and monitoring limit blast radius but do not delete the vulnerable code. Each accepted exception needs an owner, justification, expiry, and a rescan date. To a manager: zero findings is not a reliable gate — the useful story is which risks remain reachable, which controls reduce them, and when remediation is reviewed. Waiting alone is not a plan.

## Task 2

### Namespace labels and securityContext

[`namespace.yaml`](../labs/lab7/k8s/namespace.yaml) — all three modes `restricted`:

```yaml
pod-security.kubernetes.io/enforce: restricted
pod-security.kubernetes.io/warn: restricted
pod-security.kubernetes.io/audit: restricted
```

Pod `securityContext` in [`deployment.yaml`](../labs/lab7/k8s/deployment.yaml):

```yaml
runAsNonRoot: true
runAsUser: 65532
runAsGroup: 65532
fsGroup: 65532
seccompProfile:
  type: RuntimeDefault
```

Container `securityContext` (app + init):

```yaml
allowPrivilegeEscalation: false
readOnlyRootFilesystem: true
capabilities:
  drop: ["ALL"]
```

Dedicated [`serviceaccount.yaml`](../labs/lab7/k8s/serviceaccount.yaml) and the pod both set `automountServiceAccountToken: false`. Requests/limits are set for CPU and memory. Image pinned by digest (not tag).

Apply namespace first (alphabetical `kubectl apply -f labs/lab7/k8s/` would otherwise hit the Deployment before the Namespace exists).

### Proof: Ready and UID 65532

```text
NAME                          READY   STATUS    RESTARTS
juice-shop-5ccbb869b9-c5mlh   1/1     Running   0
```

```bash
kubectl -n juice-shop exec deploy/juice-shop -c juice-shop -- \
  /nodejs/bin/node -e '…'   # see Bonus runtime JSON
# uid=65532, gid=65532
```

Matches `docker inspect … '{{.Config.User}}'` → `65532`. (No `id` binary in this image.)

### NetworkPolicy

[`networkpolicy.yaml`](../labs/lab7/k8s/networkpolicy.yaml): `policyTypes` Ingress+Egress; ingress TCP 3000 only from pods labelled `access=juice-shop-client`; egress DNS (TCP/UDP 53) only to `kube-dns` in `kube-system`.

| Probe | Result |
|-------|--------|
| Same-ns client with `access=juice-shop-client` | HTTP **200** |
| Same-ns client without that label | connection failed (curl exit 7 / HTTP 000) |
| App DNS lookup `kubernetes.default.svc.cluster.local` | `10.43.0.1` |
| App TCP to plain Juice Shop pod :3000 | `ECONNREFUSED` (destination was healthy) |

Port-forward uses the API/kubelet path and is **not** NetworkPolicy proof; the pod-to-pod probes are.

### Trivy k8s: plain vs hardened

```bash
kubectl create ns juice-plain
kubectl -n juice-plain create deployment juice --image=bkimminich/juice-shop:v20.0.0
trivy k8s --include-namespaces juice-plain --severity HIGH,CRITICAL --report=summary
trivy k8s --include-namespaces juice-shop  --severity HIGH,CRITICAL --report=summary
trivy k8s --include-namespaces juice-shop --severity HIGH,CRITICAL \
  --format json --output labs/lab7/results/trivy-k8s.json
```

**Raw summary rows** (bonus initContainer present on hardened Deployment):

| Workload | Vulns C / H | Misconfig C / H |
|----------|-------------|-----------------|
| `juice-plain` / Deployment/juice | 10 / 64 | 0 / **3** |
| `juice-shop` / Deployment/juice-shop | 20 / 128 | 0 / **0** |

Raw vulns double on `juice-shop` because init + app both use the **same** image; Trivy tallies it twice. Counting the identical image once:

| Same image, once | Plain | Hardened |
|------------------|------:|---------:|
| CRITICAL + HIGH vulns | **74** | **74** |
| HIGH/CRITICAL misconfigs | **3** | **0** |

Plain HIGH misconfigs: `KSV-0014` (root filesystem not read-only) and `KSV-0118` (default security context; appears twice in the plain object). Hardening clears the misconfig column; only a rebuild changes the package vulns. Misconfigurations differ; per-image vulnerability counts do not.

### What `restricted` blocked vs what I added voluntarily

Server-side dry-run with `allowPrivilegeEscalation: true` (otherwise valid non-root + seccomp + drop ALL):

```text
pods "bad-priv" is forbidden: violates PodSecurity "restricted:latest": allowPrivilegeEscalation != false (container "juice" must set securityContext.allowPrivilegeEscalation=false)
```

**Voluntary (not required by `restricted`):** `readOnlyRootFilesystem: true` (bonus), and the NetworkPolicy default-deny with labelled ingress + DNS-only egress.

## Bonus

### Baseline: read-only Docker crash

```bash
docker run --rm --read-only bkimminich/juice-shop:v20.0.0
```

Exits with `SQLITE_CANTOPEN: unable to open database file` — the app must write at runtime.

### `docker diff` (paths that matter)

```text
C /juice-shop/data          (+ juiceshop.sqlite)
C /juice-shop/logs          (+ access/audit logs)
C /juice-shop/i18n          (+ locale JSON)
C /juice-shop/ftp           (+ legal.md)
C /juice-shop/frontend/dist/frontend  (index/assets touched)
C /juice-shop/.well-known   (CSAF metadata)
```

Plus `/tmp` for Node scratch (defensive; not always in the startup diff).

### Volume layout

One `emptyDir` `writable-paths`, mounted as subPaths:

| Mount | Subpath | Why writable |
|-------|---------|--------------|
| `/juice-shop/data` | `data` | SQLite + packaged seed files must stay visible |
| `/juice-shop/logs` | `logs` | Access / audit logs |
| `/juice-shop/ftp` | `ftp` | Generated `legal.md` beside shipped FTP files |
| `/juice-shop/i18n` | `i18n` | Runtime locale generation |
| `/juice-shop/frontend/dist/frontend` | `frontend` | Startup asset/index updates |
| `/juice-shop/.well-known` | `wellknown` | CSAF provider metadata |
| `/tmp` | `tmp` | Bounded temp space |

InitContainer (same digest, UID 65532, read-only root, drop ALL) seeds those directories with Node `fs.cpSync` into the emptyDir; the app mounts the seeded subpaths over the image paths.

### Directory that cannot be a blank emptyDir

`/juice-shop/data` (and likewise `ftp`, `i18n`, frontend dist, `.well-known`) already contain files from the image. A fresh emptyDir hides them — e.g. missing `data/static/securityQuestions.yml` breaks startup. Seeding preserves packaged content while allowing writes. Final pod: `seedFile: true` for that path.

### Runtime proof

```json
{"uid":65532,"gid":65532,"rootWrite":"EROFS","seedFile":true,"tokenMounted":false}
```

`rootWrite` = attempt to create `/juice-shop/readonly-proof` (EROFS confirms read-only root).

```bash
kubectl -n juice-shop port-forward deploy/juice-shop 13000:3000 --address 127.0.0.1
curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:13000/
# 200
```

Pod Ready 1/1, zero restarts, `readOnlyRootFilesystem: true`. Cluster deleted after evidence: `k3d cluster delete lab7`.
