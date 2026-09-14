# Lab 2 — Anton Bugaev (CBS-03) — an.bugaev@innopolis.university

**Deliverables in this PR:** Task 1 (baseline Threagile) · Task 2 (`threagile-model-secure.yaml`) · **Bonus Task** (`threagile-model-auth.yaml`, +2 pts)

## Task 1

### Severity table (baseline)

| Severity | Count |
|----------|------:|
| critical | 0 |
| high | 0 |
| elevated | 4 |
| medium | 14 |
| low | 5 |
| **Total** | **23** |

### Top five risks (severity-ranked)

| Severity | Rule ID | Asset |
|----------|---------|-------|
| elevated | `cross-site-scripting` | `juice-shop` |
| elevated | `unencrypted-communication` | `user-browser` |
| elevated | `unencrypted-communication` | `reverse-proxy` |
| elevated | `missing-authentication` | `juice-shop` |
| medium | `cross-site-request-forgery` | `juice-shop` |

### STRIDE mapping

1. **`cross-site-scripting` (juice-shop)** — **T (Tampering)**. Stored/reflected XSS lets an attacker modify pages and execute script in victims’ browsers.
2. **`unencrypted-communication` (user-browser → juice-shop)** — **I (Information Disclosure)**. Cleartext HTTP can expose credentials, session IDs, and tokens to anyone on path.
3. **`unencrypted-communication` (reverse-proxy → juice-shop)** — **I (Information Disclosure)**. Internal hop still carries auth material; a compromised co-located process can sniff it.
4. **`missing-authentication` (proxy → app)** — **S (Spoofing)**. Without authenticating the proxy-to-app link, an attacker can impersonate the reverse proxy toward Juice Shop.
5. **`cross-site-request-forgery` (juice-shop)** — **S (Spoofing)**. A victim’s browser can be tricked into sending authenticated requests the user did not intend, acting as the user toward the app.

### Trust-boundary crossing

In `data-flow-diagram.png`, the **Direct to App (no proxy)** arrow from **User Browser** (inside the **Internet** trust boundary) to **Juice Shop Application** (inside **Container Network**, nested under **Host**) crosses every boundary in the stack. It is worth an attacker’s time because that link is in the top five as `unencrypted-communication` and carries authentication data (credentials/session/token) straight into the application.

## Task 2

### Baseline vs secure severity counts

| Severity | Baseline | Secure | Delta |
|----------|---------:|-------:|------:|
| critical | 0 | 0 | 0 |
| high | 0 | 0 | 0 |
| elevated | 4 | 1 | -3 |
| medium | 14 | 12 | -2 |
| low | 5 | 5 | 0 |
| **Total** | **23** | **18** | **-5** |

Total dropped by 5/23 ≈ 22% (roughly a fifth), not to zero.

### Rules in `gone:` and the field change that removed them

| Gone rule ID | Field change that removed it |
|--------------|------------------------------|
| `unencrypted-communication` | Inbound links to the app: `protocol: http` → `protocol: https` (browser→app and proxy→app) |
| `missing-authentication` | Proxy→app link: `authentication: none` → `authentication: client-certificate` (also set `authorization: technical-user`) |
| `unencrypted-asset` | `Juice Shop Application` and `Persistent Storage`: `encryption: none` → `encryption: transparent` |

### Two rules that still fire (and why YAML edits could not remove them)

1. **`cross-site-scripting` (elevated, juice-shop)** — Still the only elevated finding. Encryption and link authentication do not sanitize product reviews or other HTML sinks; XSS is a code/input-validation issue.
2. **`missing-identity-store` (medium, reverse-proxy)** — Still present because TLS and storage encryption do not add an identity provider/store asset to the model; Threagile continues to flag that architectural gap.

### What risk is left / what YAML cannot close

About four-fifths of the findings remain: application logic flaws (XSS), supply-chain/container risks, missing WAF/hardening, and architectural gaps like no identity store or vault. Closing those needs real controls — secure coding, dependency/base-image scanning, WAF, an IdP, and secret management — not just nicer YAML enums. One risk **no YAML edit can close** is **cross-site-scripting** in Juice Shop: it is intentional vulnerable-by-design behaviour in the application code, so changing protocol/encryption fields cannot eliminate it.

## Bonus Task — authentication flow model (+2 pts)

Threagile run (auth model):

```bash
docker run --rm -v "$(pwd)/labs/lab2":/app/work \
  threagile/threagile:0.9.1 \
  -model /app/work/threagile-model-auth.yaml -output /app/work/output-auth
jq 'length' labs/lab2/output-auth/risks.json
# 26
jq '[.[].severity] | group_by(.) | map({severity: .[0], count: length})' labs/lab2/output-auth/risks.json
```

### Auth-model severity table

| Severity | Count |
|----------|------:|
| critical | 0 |
| high | 1 |
| elevated | 8 |
| medium | 14 |
| low | 3 |
| **Total** | **26** |

Model file: `labs/lab2/threagile-model-auth.yaml` (built from the stub, not by copying the baseline). It includes ≥5 technical assets, ≥5 communication links, ≥4 data assets, a dedicated **JWT Signing Key** data asset, authentication+authorization on every link, and the admin endpoint’s `Verify Token And Role` link as the authorization gate.

### Three auth-specific risks (not in the baseline architecture model)

| Rule ID | STRIDE | Mitigation (one sentence) |
|---------|--------|---------------------------|
| `sql-nosql-injection` | **T (Tampering)** | Use parameterized queries / ORM bindings on the login→credential-store path so credential lookups cannot alter the query. |
| `missing-authentication-second-factor` | **S (Spoofing)** | Require MFA (TOTP/WebAuthn) on login and especially before admin actions so stolen passwords alone are insufficient. |
| `missing-vault` | **I (Information Disclosure)** | Store the JWT signing key in a secrets vault with rotation and least-privilege access instead of co-locating it only as process memory/config. |

### Feature-level vs architecture-level

The auth-flow model surfaces login-path issues the deployment DFD never named — SQL injection on credential verification, missing 2FA on login/admin, and a missing vault for the JWT signing key. An architecture model of containers and proxies cannot show those feature-level auth failures; you only see them when login, token minting, and admin AuthZ are first-class assets and links.
