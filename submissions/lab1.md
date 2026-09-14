# Lab 1 — Anton Bugaev (CBS-03)

## Triage report

### Asset
- Image tag: `bkimminich/juice-shop:v20.0.0`
- Image digest: `bkimminich/juice-shop@sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0`
- Host OS: macOS 26.6.2 (Darwin 25.6.0 arm64, Build 25G83)
- Docker version: Docker version 29.2.1, build a5c7197

### Deployment
- Run command:
  ```bash
  docker run -d --name juice-shop -p 127.0.0.1:3000:3000 bkimminich/juice-shop:v20.0.0
  ```
- Access URL: http://127.0.0.1:3000
- Port binding: bound to `127.0.0.1:3000` only (not `0.0.0.0`). That matters because Juice Shop is deliberately vulnerable; publishing it on every interface would expose it on dorm/shared Wi-Fi.
- Restart policy: `no` (default; container does not restart automatically after stop/crash)

### Health
- HTTP code on `/`: `HTTP 200`
- Version endpoint: `{"version":"20.0.0"}`
- Product count: `46`
- `docker ps` line:
  ```
  NAMES        STATUS          PORTS
  juice-shop   Up 40 seconds   127.0.0.1:3000->3000/tcp
  ```

### Surface
1. **Login and registration.** Account menu (top right) exposes Login; the login form has email/password, “Forgot your password?”, Google login, and a “Not yet a customer?” link to registration. Registration is reachable at `/#/register`.
2. **Products.** Homepage lists the catalog (“All Products”, 15 items per page). `/api/Products` returns 46 items; individual product details are available without authentication.
3. **Admin / account area.** Side navigation and account flows exist; `/rest/admin/application-configuration` is reachable without a session and returns a `config` object. Unauthenticated `whoami` returns `{"user":{}}`.
4. **Console errors.** After dismissing the welcome banner and cookie notice, the UI loads the product grid without hard failures; no blocking console errors observed during basic browsing of home and login.
5. **Local storage and cookies.** After dismissing banners, cookies included `language=en` and `welcomebanner_status=dismiss`. Application Local Storage was empty before login. Cookie consent banner sets cookie-related preferences in the browser.

Network observation: opening a product triggers unauthenticated calls such as `/api/Products/:id` and `/rest/products/:id/reviews` (HTTP 200 with a `data` envelope) — no auth token required for catalog/reviews reads.

### Headers
`curl -sI http://127.0.0.1:3000 | head -20` output:

```
HTTP/1.1 200 OK
Access-Control-Allow-Origin: *
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Feature-Policy: payment 'self'
X-Recruiting: /#/jobs
Accept-Ranges: bytes
Cache-Control: public, max-age=0
Last-Modified: Mon, 14 Sep 2026 07:32:39 GMT
ETag: W/"26af-1a09ed51353"
Content-Type: text/html; charset=UTF-8
Content-Length: 9903
Vary: Accept-Encoding
Date: Mon, 14 Sep 2026 07:33:18 GMT
Connection: keep-alive
Keep-Alive: timeout=5
```

Four-header checklist:
| Header | Status |
|--------|--------|
| Content-Security-Policy | **missing** |
| Strict-Transport-Security | **missing** |
| X-Content-Type-Options | present (`nosniff`) |
| X-Frame-Options | present (`SAMEORIGIN`) |

Missing CSP and HSTS fall under OWASP Top 10:2025 **A02 Security Misconfiguration**.

### Top 3 risks

1. **Missing CSP and HSTS (security headers gap)** — Without Content-Security-Policy, XSS payloads can load arbitrary scripts; without Strict-Transport-Security there is no browser-enforced HTTPS policy if the app is later exposed beyond localhost. Combined with `Access-Control-Allow-Origin: *`, client-side attack surface is wide. **OWASP Top 10:2025 A02 — Security Misconfiguration.**

2. **Unauthenticated sensitive/admin-adjacent APIs** — Catalog, product reviews, and `/rest/admin/application-configuration` respond without authentication. That leaks configuration and review content and makes it trivial to probe for further privilege issues. **OWASP Top 10:2025 A01 — Broken Access Control.**

3. **Cleartext HTTP local service with intentional vulnerabilities** — Traffic to `http://127.0.0.1:3000` is unencrypted. On a shared host or if the bind is ever widened, session tokens and credentials can be sniffed; Juice Shop also ships with known XSS/injection challenges that become exploitable once reachable. **OWASP Top 10:2025 A04 — Cryptographic Failures.**

## PR template

- File path: `.github/PULL_REQUEST_TEMPLATE.md`
- Section names: **Goal**, **Changes**, **Testing**, **Artifacts & Screenshots**
- Checklist items:
  - title follows `feat(labN): `
  - no secrets or large temp files committed
  - `submissions/labN.md` exists
- Draft PR (auto-filled description): _will be updated after PR creation_

## GitHub community

Stars signal that a project is used and valued, which helps maintainers justify time, attract contributors, and make the work discoverable. Following classmates and staff keeps course updates and peer work in your feed so collaboration and review loops stay visible during the semester.

Stars completed for `inno-devops-labs/DevSecOps-Intro` and `simple-container-com/api`. Follows for `@Cre-eD`, `@Naghme98`, `@pierrepicaud`, and classmates require the GitHub `user` OAuth scope (current token has `gist, read:org, repo, workflow` only); complete those follows in the GitHub UI if the API follow calls return 404.

## Bonus: CI smoke test

- Workflow path: `.github/workflows/lab1-smoke.yml`
- Run URL: _will be updated after the draft PR Actions run_
- Run duration: _pending_
- Curl output excerpt: _pending_
