# Vigía — Google Workspace Security Posture Scanner

Freemium web app that connects to a Google Workspace tenant **read-only** and produces a
**security posture score (0–100)** plus a prioritized, actionable list of findings.
Solo-maintainable by design: Flask + SQLite + React, no paid third-party APIs.

**Hard guarantees**

- **Read-only, always.** There is no write code path — the Google client only implements GET.
- **Four sensitive but NON-restricted scopes** (plus basic `openid email` identity, which is
  non-sensitive). No Gmail/Drive/restricted scopes → standard OAuth verification is enough,
  **no CASA Tier 2 assessment**.
- Checks that would need a restricted scope are rendered as **Manual checks** with
  instructions instead of calling any API.
- Refresh tokens encrypted at rest (Fernet). Disconnect = delete everything + revoke grant.

## Monorepo layout

```
backend/
  app.py                    # entrypoint (dev: python app.py · prod: gunicorn app:app)
  vigia/
    config.py               # Settings from env
    db.py                   # SQLite data-access layer (swap for Postgres by editing this file)
    crypto.py               # Fernet encryption for refresh tokens
    scoring.py              # documented severity-weighted score
    dns_email_auth.py       # SPF/DKIM/DMARC engine (injectable resolver, no Google API)
    scan.py                 # ScanContext (cached API data) + orchestrator
    mock_data.py            # seeded tenant for MOCK_MODE
    auth/                   # OAuth admin-consent flow (start/callback/disconnect)
    google_client/          # thin GET-only wrappers: Directory + Reports (+ mocks)
    checks/                 # one file per check → list[Finding]; manual.py = manual checks
    api/                    # REST routes + free/pro gating (server-side)
  tests/                    # scoring + DNS/DMARC parser tests
frontend/                   # Vite + React 19 + TypeScript + Tailwind 4
```

## Quick start (mock mode — no Google setup needed)

```bash
# backend
cd backend
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
MOCK_MODE=1 .venv/bin/python app.py            # http://localhost:8110

# frontend (dev server proxies /api to :8110)
cd frontend
npm install && npm run dev                     # http://localhost:5173
```

Click **Connect Workspace** — mock mode skips Google entirely and seeds a demo tenant with a
realistic mess (admin without 2SV, risky OAuth app…). Run a scan and explore.

**Domains are never mocked.** The SPF/DKIM/DMARC checks always run against real public DNS,
and only against domains you configure in the dashboard's **Domains** panel (`/api/domains`).
In real mode your Google Workspace domains sync into that list automatically on every scan;
manually-added domains work in both modes.

For production-style serving, `npm run build` and let Flask serve `frontend/dist` on :8110.

## Google Cloud setup (real mode)

1. Create a project at [console.cloud.google.com](https://console.cloud.google.com).
2. **Enable the Admin SDK API** (APIs & Services > Library > "Admin SDK API").
2b. **Enable the Cloud Identity API** (APIs & Services > Library > "Cloud Identity API").
    This powers the automatic reading of Admin console settings (Drive sharing, Gmail
    forwarding, password policy, session length, Marketplace allowlist, Groups access).
    Skip it and the app still works — those checks just fall back to manual cards.
3. Configure the **OAuth consent screen** (APIs & Services > OAuth consent screen):
   - User type: **External** (or Internal if only your own org will use it).
   - Add these five scopes:
     - `https://www.googleapis.com/auth/admin.directory.user.readonly`
     - `https://www.googleapis.com/auth/admin.directory.domain.readonly`
     - `https://www.googleapis.com/auth/admin.reports.audit.readonly`
     - `https://www.googleapis.com/auth/admin.reports.usage.readonly`
     - `https://www.googleapis.com/auth/cloud-identity.policies.readonly`
   - All five are **sensitive, non-restricted** scopes: publishing to production requires
     standard **OAuth verification** (brand + scope justification video), but **NOT** a CASA
     security assessment. Google's restricted list covers Gmail, Drive, Fit, Chat, Data
     Portability, Photos and Health APIs — Cloud Identity is not on it, which is why reading
     Workspace policies stays CASA-free. Do not add any Gmail/Drive scope — that changes the
     answer.
   - The app also requests `openid email` (non-sensitive) to identify the connecting admin.
   - The policy scope requires a **super admin** to connect (delegated admins get 403 and the
     checks degrade to `undetermined`, never to a false pass).
4. Create an **OAuth client ID** (Credentials > Create credentials > OAuth client ID > Web):
   - Authorized redirect URI: `http://localhost:8110/api/auth/google/callback`
     (or your production `OAUTH_REDIRECT_URI`).
5. Put the client id/secret in `.env` (see `.env.example`).

The connecting user must be a **super admin** (or a delegated admin with Users *and* Reports
read privileges); the app verifies this at connect time via the admin's OAuth grant — no
service account or domain-wide delegation to set up.

> **Use a dedicated OAuth project.** Vigía needs a server-side "Web application" client
> (authorization code + `access_type=offline` for a refresh token) with the Admin SDK scopes.
> Do **not** reuse a client from a client-side "Sign in with Google" app — that flow has no
> secret and adding admin scopes to a shared consent screen would prompt your other apps'
> users for admin access.

**Shortcut:** run `bash scripts/setup-google.sh`. It walks you through the console-only steps
(which Google does not allow via API), then automates the rest: it writes the credentials to
`.env`, flips `MOCK_MODE=0`, restarts the service and verifies the real Google flow starts.

## Environment variables

| Variable | Default | Purpose |
| --- | --- | --- |
| `VIGIA_SECRET_KEY` | dev value | Flask session signing — set a long random string |
| `VIGIA_ENCRYPTION_KEY` | auto-generated to `data/fernet.key` | Fernet key for tokens at rest (`python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`) |
| `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` | — | OAuth client credentials |
| `OAUTH_REDIRECT_URI` | `http://localhost:8110/api/auth/google/callback` | Must match the OAuth client |
| `VIGIA_APP_URL` | same origin | Where the browser lands after OAuth (set `http://localhost:5173` in dev) |
| `MOCK_MODE` | `0` | `1` = seeded demo tenant, no Google calls |
| `VIGIA_PRO_OVERRIDE` | `0` | Feature flag: treat every org as Pro (preview/dev) |
| `VIGIA_DATA_DIR` / `VIGIA_DB_PATH` | `./data` | SQLite + key file location |
| `VIGIA_PORT` | `8110` | Backend port |
| `VIGIA_SUPER_ADMIN_THRESHOLD` | `3` | Warn above this many super admins |
| `VIGIA_DORMANT_DAYS` | `90` | Dormant-account cutoff |
| `VIGIA_DKIM_SELECTORS` | `google,selector1,…` | Comma-separated DKIM selectors to probe |
| `VIGIA_CONTACT_EMAIL` | — | GDPR contact shown on the Privacy page |
| `VIGIA_PREFIX` | — | Public mount path behind a reverse proxy (e.g. `/vigia`). Re-applied to same-origin redirects only for requests that arrive via the Tailscale Funnel |
| `VIGIA_COOKIE_SECURE` | `0` | Set `1` only if every access path is HTTPS |

### Per-organization scan options

Beyond env defaults, each connected org can tune its own scan from the dashboard's
**Scan options** panel (persisted per org, applied from the next scan):

- `super_admin_threshold`, `dormant_days`, `widely_granted_threshold` (validated ranges)
- `dkim_selectors` — the list of DKIM selectors probed by the email-auth check

These are exposed at `GET/PUT /api/settings`; env vars remain the fallback default and the
"Reset to defaults" button restores them.

### Public deployment (diegofarina.com/vigia)

The app is served publicly through the existing Cloudflare Worker → Tailscale Funnel chain,
mounted at `/vigia`. The Funnel strips the `/vigia` prefix before the request reaches Flask,
so the frontend detects its mount prefix at runtime (`src/prefix.ts`, injected `<base>` tag)
and the backend re-applies the prefix to OAuth redirects when it sees the
`Tailscale-Funnel-Request` header. The same build also works at `/` for direct Tailscale
access. To (re)publish: `tailscale funnel --bg --set-path=/vigia http://127.0.0.1:8110`.

## Docker

```bash
cp .env.example .env   # fill in secrets
docker compose up --build   # http://localhost:8110  (SQLite persisted in ./data)
```

## Checks

Eleven check modules run per scan (`vigia/checks/`), all read-only:

| Module | Covers |
| --- | --- |
| `composite` | **Signals that only matter together** — e.g. super admin + no 2SV + never signed in = a permanent, unwatched back door (critical). Declarative rules; each account is attributed to one rule only |
| `check_2sv` | 2SV enrollment + enforcement; any admin without 2SV is **critical** |
| `check_login_security` | Compromised accounts Google flagged (leaked password, hijack, state-backed attack), suspicious sign-ins, failed-login bursts |
| `check_super_admins` | Super-admin sprawl and single-admin lockout risk |
| `check_dormant` / `check_stale` | Inactive, never-signed-in and suspended accounts |
| `check_oauth_apps` | Third-party apps holding high-risk scopes, widely-granted apps, domain-wide delegation |
| `check_policies` | **Admin console settings** — see below |
| `check_audit_log` | Audit-log reachability + risky admin changes, bucketed by risk category |
| `check_email_auth` | SPF / DKIM / DMARC per domain (public DNS) |
| `check_mail_transport` | MTA-STS, TLS-RPT, DNSSEC (public DNS) |

### Admin console settings (Policy API)

`check_policies` reads what used to be manual, via the **Cloud Identity Policy API**: Drive
external sharing, Gmail auto-forwarding, password policy, session length, Marketplace allowlist
and Groups external access. Policies are evaluated **per organizational unit** — one insecure OU
is reported even when the org default is safe.

The API only returns values that were *explicitly set*, so an absent policy yields
`undetermined` (Google's default cannot be confirmed) and the matching manual card stays
visible. When the API is unreachable (scope not granted, API disabled, not a super admin) the
scan emits a single `policy-automation` card explaining exactly what to switch on, and nothing
else breaks. The manual list therefore shrinks to precisely what still needs a human — see
`scan.remaining_manual_checks`.

## The report

Reading order is deliberate — it answers the reader's questions in the order they ask them:

1. **How bad is it** — severity counts and the people-at-risk sentence are the headline. The
   score is a secondary metric for tracking movement, because "31/100" means nothing to a
   reader without a reference.
2. **What do I do first** — `remediation.py` holds the finding→action graph. `rank_actions()`
   takes the open findings that declare each action, recomputes the score with them resolved,
   and ranks by **findings closed per minute of effort** (not by severity). Impact numbers are
   always derived; nothing is hardcoded. Actions that break something for end users (enforcing
   2SV locks out anyone unenrolled) carry an explicit warning.
3. **What changed** — delta vs the previous scan, or an explicit "first scan, no comparison
   available" instead of an empty gap.
4. **The detail** — findings, every person at risk (the export never truncates), per-domain DNS
   records, and whatever still needs a human.
5. **Show your work** — the full score derivation, line by line.

PDF export sets `print-color-adjust: exact`, because browsers drop background colours when
printing and severity colour carries half the meaning.

## Three states, not two

A check can be verified-bad, verified-good, or **not verifiable**. DKIM is discovered by
guessing selector names, so a miss proves nothing — the domain may sign with a custom selector.
Those results read "DKIM not verified — no key found at the N selectors probed", get dashed,
colourless styling in both the UI and the PDF, and are **excluded from the score entirely**.
Custom selectors can be added in Scan options, which flips an unverified result to verified.

Authoritative lookups (SPF, DMARC, MTA-STS, TLS-RPT, DNSSEC — all at a known DNS name) do
assert absence, because there absence is a fact.

## Scoring methodology

Documented in `backend/vigia/scoring.py` and surfaced in the UI:

- Severity weights: critical 10 · high 6 · medium 3 · low 1 · info 0.
- Status credit: pass 100% · warn 50% · fail 0%.
- `undetermined`, `info` and manual checks are **excluded** — uncertainty is never punished
  (nor rewarded). The DNS engine follows the same policy: an unknown DKIM selector is
  `undetermined`, never `fail`.
- `score = round(100 × earned / total)`; no scorable findings → `N/A`.

## Free vs Pro (billing stubbed)

Gating is enforced **server-side** (`vigia/api/gating.py`); locked detail never leaves the
backend. Free: score, counts by severity, full critical findings, the DNS email-auth check,
manual checks, trend vs previous scan. Pro: everything, full history. `POST /api/billing/upgrade`
returns 501 — **TODO: Stripe** (Checkout + webhook → `db.set_plan(org_id, "pro")`).

## Tests

```bash
cd backend && .venv/bin/python -m pytest -q   # scoring + DNS/DMARC parser (32 tests)
```

## Notes & known limitations (MVP)

- CIS mappings use descriptive labels ("CIS GWS §1 — 2-Step Verification"); pin them to exact
  control ids of your benchmark version before marketing claims.
- Reports API `token` events cover ~180 days — the OAuth-apps check sees grants in that
  window, and says so.
- The public `/dmarc-checker` rate limit is in-memory (fine single-process; move to Redis if
  scaled out).
- Single org per browser session; multi-tenant switcher is a Pro TODO.
