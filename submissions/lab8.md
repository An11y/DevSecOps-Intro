# Lab 8 — Anton Bugaev (CBS-03) — an.bugaev@innopolis.university

**Deliverables:** Task 1 (sign + tag swap) · Task 2 (CycloneDX + SLSA attestations) · **Bonus Task** (`cosign sign-blob`, +2 pts)

> Note: the registry is bound to `127.0.0.1:5000` (not `localhost`) because macOS AirPlay Receiver also listens on `*:5000`, and Cosign’s `localhost` resolution hit that listener with HTTP 403. Same plain-HTTP local registry as in the lab brief.

Cosign used for all steps: **v3.0.2** (`--tlog-upload=false` / `--insecure-ignore-tlog`).

## Task 1

### Digest signed

```text
127.0.0.1:5000/juice-shop@sha256:cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113
```

`docker inspect … RepoDigests` also listed the Hub content digest `sha256:fd58…`, but that digest is **not** what the local registry stored after a single-platform push (Docker reported `fd58… -> cbdfc00…`). Signing `fd58…` against the local registry returned 404. The digest Cosign can push signatures for is the **registry manifest digest** from `docker push` / `Docker-Content-Digest` on `127.0.0.1:5000/` — filtered away from any `docker.io/` digest.

### Successful `cosign verify`

```text
Verification for 127.0.0.1:5000/juice-shop@sha256:cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113 --
The following checks were performed on each of these signatures:
  - The cosign claims were validated
  - Existence of the claims in the transparency log was verified offline
  - The signatures were verified against the specified public key

[{"critical":{"identity":{"docker-reference":"127.0.0.1:5000/juice-shop@sha256:cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113"},"image":{"docker-manifest-digest":"sha256:cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113"},"type":"https://sigstore.dev/cosign/sign/v1"},"optional":null}]
```

### Tag overwrite (tamper)

Pushed `alpine:3.20` as `127.0.0.1:5000/juice-shop:v20.0.0` → new digest

`127.0.0.1:5000/juice-shop@sha256:45e09956dc667c5eff3583c9d94830261fb1ca0be10a0a7db36266edf5de9e1d`

Verify on the **new** digest fails:

```text
Error: no signatures found
error during command execution: no signatures found
```

Verify on the **original** digest still succeeds (same successful output as above). A signature is not a tag: the signature artifact is attached to the content digest we signed; moving the mutable tag leaves that digest’s signature intact and leaves the new digest unsigned.

### What the signature is bound to

Cosign signs the **image digest** (immutable bytes of the manifest), not the floating string `v20.0.0`. After the swap, the tag points at Alpine, which has no signature under our key — verify correctly says `no signatures found`. If signatures were bound to tags instead, an attacker who can push to the same tag name could keep a “valid” signature while serving different content, which is exactly the failure mode this demo is meant to kill.

## Task 2

### Component counts

| Source | `jq '.components \| length'` |
|--------|-----------------------------:|
| Lab 4 CycloneDX (`labs/lab4/juice-shop.cdx.json`) | **3068** |
| Extracted attestation predicate | **3068** |

### `predicateType` values (from verified payloads)

| Attestation | `predicateType` |
|-------------|-----------------|
| CycloneDX SBOM | `https://cyclonedx.org/bom` |
| SLSA provenance | `https://slsa.dev/provenance/v0.2` |

### Statement fields and who filled them

Decoded CycloneDX statement (same shape for SLSA, different `predicateType`):

```json
{
  "_type": "https://in-toto.io/Statement/v0.1",
  "subject": [
    {
      "name": "127.0.0.1:5000/juice-shop",
      "digest": {
        "sha256": "cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113"
      }
    }
  ],
  "predicateType": "https://cyclonedx.org/bom"
}
```

- `_type` — Cosign wraps the predicate in an in-toto Statement; I did not supply this.
- `subject` — Cosign fills it from the digest I attested (`name` + `sha256`).
- `predicateType` — comes from `--type cyclonedx` / `--type slsaprovenance` (Cosign maps the flag to the URI).
- `predicate` body — I supplied (`juice-shop.cdx.json` / `provenance.json`).

### Morning after Log4Shell

A signature alone answers “is this blob the same bytes I signed?” An SBOM attestation answers “which packages are inside?” — so I can query two thousand images for `log4j` / vulnerable versions without re-scanning every layer from scratch. That only works at 03:00 if (1) every image was attested at build time with a trustworthy SBOM, (2) I can verify those attestations with a key I trust, and (3) the SBOM was actually complete for the runtime I care about. Missing attestations or unsigned SBOMs put those images back into the slow path.

## Bonus

### Blob verify before / after modification

Original:

```text
Verified OK
```

After rewriting `install.sh` and rebuilding the tarball **without** re-signing:

```text
Error: failed to verify signature: could not verify message: invalid signature when validating ASN.1 encoded signature
```

### What a consumer needs

1. The artifact (`my-tool.tar.gz`)
2. The signature bundle (`my-tool.tar.gz.bundle`) **and** a **trusted** public key (`cosign.pub`) obtained out of band (or keyless identity pinning)

The bundle may travel next to the artifact on the same CDN; the **public key / trust root must not** be fetched from the same untrusted channel as the payload, or an attacker replaces both.

### Install instructions that survive a Codecov-style CDN swap

Publish something like:

```bash
curl -fsSL https://example.com/my-tool.tar.gz -o my-tool.tar.gz
curl -fsSL https://example.com/my-tool.tar.gz.bundle -o my-tool.tar.gz.bundle
# cosign.pub is pinned from your org’s key distribution (not the CDN above)
cosign verify-blob --key cosign.pub --bundle my-tool.tar.gz.bundle my-tool.tar.gz
tar -xzf my-tool.tar.gz && ./install.sh
```

The step most projects skip is **verify before execute** — `curl | bash` never checks a signature, so a modified uploader runs with full CI credentials. Sign the blob; verify the blob; only then run it.
