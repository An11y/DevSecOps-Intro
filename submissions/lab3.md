# Lab 3 — Anton Bugaev (CBS-03) — an.bugaev@innopolis.university

**Deliverables:** Task 1 (SSH signed commits) · Task 2 (`.pre-commit-config.yaml` + gitleaks) · **Bonus Task** (git filter-repo purge, +2 pts)

## Task 1

### Signing config

| Setting | Value |
|---------|-------|
| `gpg.format` | `ssh` |
| `user.signingkey` | `/Users/an11y/.ssh/id_ed25519.pub` |
| `commit.gpgsign` | `true` |
| `user.email` (allowed_signers) | `an.bugaev@innopolis.university` |

Public key fingerprint: `SHA256:eF+DLv75…prfKkRryIMCSjeIk` (full value from `ssh-keygen -lf ~/.ssh/id_ed25519.pub`)

### `git log --show-signature -1`

```
commit b042b2e0a7084c90331676addeeb370244349635
Good "git" signature for an.bugaev@innopolis.university with ED25519 key  eF+DLv75XHUOhb8msEzUOWu5W7QprfKkRryIMCSjeIk
Author: Anton Bugaev <an.bugaev@innopolis.university>
Date:   Mon Sep 14 18:01:00 2026 +0300

    test: first signed commit
```

*(Exact SHA may update if the tip commit on `feature/lab3` changes; every commit on this PR is SSH-signed with the same key.)*

### Verified badge

Draft PR (Moodle): https://github.com/inno-devops-labs/DevSecOps-Intro/pull/1710

- First signed commit: https://github.com/An11y/DevSecOps-Intro/commit/b042b2e0a7084c90331676addeeb370244349635
- Tip commit on `feature/lab3`: https://github.com/An11y/DevSecOps-Intro/commit/851920ce91690d2306c2ac53c7f7df059e365b79

GitHub shows a green **Verified** badge once the same SSH public key is uploaded as a **Signing Key** (Settings → SSH and GPG keys). Locally `git log --show-signature` already reports a Good ED25519 signature for every commit on this branch.


### Repudiation (Lab 2 link)

Without signed commits, anyone who can push (or who spoofs `Author:` locally and gets a merge) can attribute malicious changes to `Anton Bugaev <an.bugaev@innopolis.university>` and I could not prove I did not write them — that is the **repudiation** risk from Lab 2. The GitHub **Verified** badge binds the commit bytes to my SSH signing key registered on the account, so a forged author line without my private key cannot produce a Verified commit. That turns “maybe Anton wrote this” into cryptographic evidence of who signed it.

## Task 2

### `.pre-commit-config.yaml`

```yaml
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.30.1
    hooks:
      - id: gitleaks

  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v5.0.0
    hooks:
      - id: detect-private-key
      - id: check-added-large-files
        args: ["--maxkb=500"]
```

### Blocked commit (planted GitHub PAT)

Attempt:

```bash
printf 'GH_PAT=ghp_<LAB_FAKE_GITHUB_PAT>\n' > submissions/leak-attempt.txt
git add submissions/leak-attempt.txt
git commit -m "test: should be blocked"
```

gitleaks output (excerpt):

```
Finding:     GH_PAT=REDACTED
RuleID:      github-pat
File:        submissions/leak-attempt.txt
Line:        1
Fingerprint: submissions/leak-attempt.txt:github-pat:1
...
WRN leaks found: 1
```

Proof it was blocked — tip commit unchanged:

```
$ git log --oneline -1
b042b2e test: first signed commit
```

Cleanup: `git restore --staged submissions/leak-attempt.txt && rm submissions/leak-attempt.txt`

### Allowlist vs path exclusion for `AKIA...` docs

**`.gitleaks.toml` `[allowlist]`** (regex/stopwords for the exact example strings) is appropriate when a few known fake values must appear in prose, and each entry is reviewed. It stops being safe when the allowlist grows into broad patterns (e.g. any `AKIA` prefix) or when real keys are copy-pasted into docs and match the same rule.

**Path exclusion for `docs/`** is appropriate when an entire documentation tree is full of intentionally fake credentials and you accept scanning that tree less strictly. It stops being safe the moment real secrets are committed under `docs/` (READMEs, runbooks, screenshots of env files) — the hook will never see them.

## Bonus Task — purge a secret from history (+2 pts)

Throwaway repo under `/tmp/lab3-bonus` (not the course fork).

### `git log --oneline` before

```
7d1d89d docs: usage notes
e5bfe45 feat: empty log
cd878aa feat: add config
de86e72 init
```

`git log -p | grep -c 'ghp_AAAA'` → **2**

### filter-repo refusal (first run without `--force`)

```
Aborting: Refusing to destructively overwrite repo history since
this does not look like a fresh clone.
  (expected at most one entry in the reflog for HEAD)
Please operate on a fresh clone instead.  If you want to proceed
anyway, use --force.
```

What I did: re-ran with the documented workaround for a throwaway sandbox:

```bash
echo 'ghp_<LAB_FAKE_HISTORY_PAT>==>[REDACTED]' > /tmp/replace.txt
git filter-repo --force --replace-text /tmp/replace.txt
```

### `git log --oneline` after

```
329eba7 docs: usage notes
49d540e feat: empty log
c380b24 feat: add config
c64d5b2 init
```

Counts after rewrite:

- `git log -p | grep -c 'ghp_AAAA'` → **0**
- `git log -p | grep -c 'REDACTED'` → **2**

### What ends the incident

Rewriting history only removes the secret from *this* clone’s reachable commits. The step that ends the incident is **rotating (revoking and re-issuing) the credential**, because the old token may already be in forks, CI logs, backups, or an attacker’s hands. Without rotation, anyone who already cloned or scraped the old SHA still has a working secret.

### Two surprises

1. filter-repo refused even on a brand-new `/tmp` repo with no remotes — it keys off **reflog depth**, not “fresh clone from origin”, which I did not expect from the wording alone.
2. After a successful rewrite, all commit SHAs changed and the tool reported packing/cleaning; the planted string vanished from `git log -p`, but the placeholder `REDACTED` remained in exactly two places — confirming replace-text rewrote both commits that had held the token.
