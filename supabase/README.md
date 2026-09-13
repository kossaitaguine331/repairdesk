# RepairDesk Supabase Backend — Deploy Guide

This is the complete, end-to-end deployment guide for the RepairDesk Supabase
backend. It covers bootstrapping the database (`schema.sql`), deploying all 12
Edge Functions, wiring up the keepalive GitHub Action, issuing codes and bans,
and verifying the whole stack once a live project exists.

The backend itself:

- **Database schema** (`schema.sql`) — tables for accounts, access codes,
  sessions (opaque 64-hex tokens), login audit logs and rate-limit counters,
  closed-by-default row-level security, server-side helper functions
  (`redeem_access_code`, `ban_user`, `unban_user`, `cleanup_old_logs`), a weekly
  cleanup cron job, and a seeded admin account.
- **API functions** (`functions/`) — 12 HTTP endpoints written as Deno Edge
  Functions sharing one helper module `functions/_shared/helpers.ts` (CORS,
  auth, rate limiting, password hashing, session checks).

Every function reads `SUPABASE_URL` and `SUPABASE_SERVICE_ROLE_KEY` from the
environment variables the Supabase platform auto-injects into Edge Functions.
Those values never appear in repository code (see `createDb()` in
`helpers.ts`). The only secret you set explicitly is `ALLOWED_ORIGIN`.

---

## Prerequisites

1. Create a free-tier Supabase project at https://supabase.com/dashboard
   (**New project**). Any region works for this backend.
2. **Record the project ref.** You will see it in the project URL and in the
   dashboard breadcrumb: it is the `xxxx` in `https://xxxx.supabase.co`. Keep it
   handy — every Edge Function URL below is `https://<project-ref>.supabase.co`
   + a path. Wherever you see `<project-ref>` in this guide, replace it with
   your project ref.
3. When you later run the end-to-end verification at the bottom of this guide,
   you will also need the project's **anon key**: **Project Settings → API** →
   `anon` / `public`.

---

## Apply the schema

1. Open **SQL Editor → New query**.
2. Paste the entire contents of `supabase/schema.sql` and click **Run**.
   Expected: no errors. A `NOTICE: relation "..." already exists, skipping`
   message on re-run is fine — the schema is idempotent.
3. Verify the schema state:

```sql
select table_name from information_schema.tables
 where table_schema='public'
 order by table_name;
-- expects: access_codes, accounts, login_attempts, login_logs, sessions

select uid, email, role, approved, banned from public.accounts;
-- expects: one row  u_admin | akuma | admin | true | false

select cron.jobid from cron.job where jobname='cleanup-old-logs';
-- expects: one row
```

The schema seeds one admin account (`email` = `akuma`, `password` = `gouki`).
These are the credentials used by the verification script at the end of this
guide.

4. Seed an initial test access code (keep it — it is your test code for later
   checks):

```sql
insert into public.access_codes (email, code, note)
values ('owner1@example.com','OWNR-0001-CODE','task-test')
on conflict do nothing;
```

---

## Deploy the Edge Functions

There are 12 HTTP endpoints implemented as 10 function deployments (5 admin
endpoints are nested under `admin/`). Each is deployed the same way through the
dashboard:

1. **Edge Functions → Deploy a new function → Via editor**, and name it exactly
   as shown in the URL table below (`health`, `login`, `signup`, `reset`,
   `validate-session`, `logout`, `cleanup`, `admin/list-accounts`,
   `admin/login-history`, `admin/ban`, `admin/issue-code`, `admin/list-sessions`).
   The function's editor supports multiple files — add the deploy file listed
   below **and** the shared helper under `_shared/helpers.ts` from
   `functions/_shared/helpers.ts`.
2. **Project Settings → Edge Functions → Secrets**, add:
   - `ALLOWED_ORIGIN` = `https://kossaitaguine331.github.io`
   - (No others are needed: `SUPABASE_URL` and `SUPABASE_SERVICE_ROLE_KEY` are
     auto-injected by the platform and must never be added by hand.)
3. **Deploy.**

> Verify JWT: if a function's dashboard **Verify JWT** toggle is enabled, the
> platform rejects requests whose `Authorization` header is not a valid Supabase
> JWT/anon key before the code runs. This backend authenticates in code, and the
> keepalive ping (below) uses a random token, so leave **Verify JWT OFF** on
> every function — otherwise bare curl calls and the keepalive will get `401`.

### Function URLs

Replace `<project-ref>` with your project ref. Every URL is
`https://<project-ref>.supabase.co` + path:

| # | Method | Path | Function name | Success response |
|---|--------|------|---------------|------------------|
| 1 | GET    | `/functions/v1/health` | `health` | `200 {status:"ok"}` |
| 2 | POST   | `/functions/v1/login` | `login` | `200 {token, uid, name, role}` |
| 3 | POST   | `/functions/v1/signup` | `signup` | `200 {token, uid, name, role}` |
| 4 | POST   | `/functions/v1/reset` | `reset` | `200 {success:true}` |
| 5 | POST   | `/functions/v1/validate-session` | `validate-session` | `200 {valid:true, uid, name, role, banned}` or `{valid:false}` |
| 6 | POST   | `/functions/v1/logout` | `logout` | `200 {success:true}` |
| 7 | POST   | `/functions/v1/cleanup` | `cleanup` | `200 {success:true}` |
| 8 | GET    | `/functions/v1/admin/list-accounts` | `admin/list-accounts` | `200` array of accounts |
| 9 | GET    | `/functions/v1/admin/login-history` | `admin/login-history` | `200` array of login-log rows |
| 10 | POST  | `/functions/v1/admin/ban` | `admin/ban` | `200 {success:true}` |
| 11 | POST  | `/functions/v1/admin/issue-code` | `admin/issue-code` | `200 {code, reused}` |
| 12 | GET   | `/functions/v1/admin/list-sessions` | `admin/list-sessions` | `200` array of masked sessions |

Each endpoint also has its own section below with request/response details.

---

## Health endpoint and keepalive

### `health`

Minimal probe used by the keepalive Action and for manual uptime checks.
GET returns `200 {status:"ok"}`; anything else returns 405. Non-browser
callers (curl, cron) are allowed — only requests with a disallowed `Origin`
header are rejected (403).

Deploy as described above: name `health`, function file
`functions/health/index.ts`, helper `functions/_shared/helpers.ts`,
secret `ALLOWED_ORIGIN`.

Invoke URL: `https://<project-ref>.supabase.co/functions/v1/health`.

### Keepalive GitHub Action

`.github/workflows/supabase-keepalive.yml` pings the health endpoint every 4
days (cron `0 4 */4 * *` → 04:00 on the 1st, 5th, 9th… of each month, plus a
manual `workflow_dispatch` trigger) to keep the free-tier project awake. It
requires two repository secrets (see **GitHub secrets** below):

- `SUPABASE_HEALTH_URL` — the **full** health Invoke URL, e.g.
  `https://<project-ref>.supabase.co/functions/v1/health`. The workflow calls
  this URL directly; nothing is appended to it.
- `SUPABASE_HEALTH_TOKEN` — any long random string. The workflow sends it as an
  `Authorization: Bearer <SUPABASE_HEALTH_TOKEN>` header.

The workflow runs `curl -s -o /dev/null -w "%{http_code}" -H "Authorization:
Bearer $SUPABASE_HEALTH_TOKEN" "$SUPABASE_HEALTH_URL"` and fails the job unless
the response status is exactly `200`. Note that the shipped `health` function
does **not** validate that bearer token — it only rejects disallowed `Origin`
headers and non-GET methods — so the token identifies the caller but is not
enforced server-side. Because the token is not a Supabase JWT, the `health`
function's dashboard **Verify JWT** setting must be OFF (see deploy notes above)
or the ping will be rejected with `401`.

## GitHub secrets

Set these once in the repository (**Settings → Secrets and variables →
Actions → New repository secret**):

| Secret | Value |
|--------|-------|
| `SUPABASE_HEALTH_URL` | Full health Invoke URL: `https://<project-ref>.supabase.co/functions/v1/health` |
| `SUPABASE_HEALTH_TOKEN` | A long random string (same value the workflow sends as `Authorization: Bearer`) |

No other repository secrets are needed. Database credentials live only in the
Supabase project environment variables, never in the repo.

---

## Login endpoint

### `login`

`POST /functions/v1/login` with body `{"email", "password"}`.

Success returns `200` `{token, uid, name, role}` (token = 64-hex session token,
expires 30 days). Failures return `{error}` with one of these statuses:

- `400 missing_fields` — email or password absent
- `401 auth_invalid` — unknown account or wrong password
- `403 banned` — account is banned
- `403 access_blocked` — account not yet approved (non-admin)
- `405 method_not_allowed` — non-POST
- `429 too_many_attempts` — 5+ failed attempts in the last 15 min

Every attempt is written to `login_logs`; failures also to `login_attempts`
(except when already rate-limited, so retries don't extend the lockout window).
Deploy like `health` (dashboard editor, name `login`, include `_shared/helpers.ts`,
same `ALLOWED_ORIGIN` secret).

## Signup endpoint

### `signup`

`POST /functions/v1/signup` with body `{"email", "name", "password", "confirmPassword", "code"}`.

Flow: validate input, IP rate-limit, reject duplicate email, atomically redeem the
one-time access code, then create the account (approved immediately, role `user`)
and mint a 30-day session. Success returns `200` `{token, uid, name, role}`.
Failures return `{error}` with one of these statuses:

- `400 auth_email_invalid` — malformed email
- `400 full_name_required` — missing name
- `400 auth_password_short` — password under 6 characters
- `400 auth_password_mismatch` — password ≠ confirmPassword
- `400 access_code_invalid` — no active unused code for the email
- `400 auth_exists` — an account with this email already exists
- `405 method_not_allowed` — non-POST
- `429 too_many_attempts` — 5+ failed signups in the last 15 min (IP-based)

Failed code redemptions are written to `login_attempts` for rate-limiting.
Deploy like `health` (dashboard editor, name `signup`, include `_shared/helpers.ts`,
same `ALLOWED_ORIGIN` secret).

## Reset endpoint

### `reset`

`POST /functions/v1/reset` with body `{"email", "code", "newPassword", "confirmPassword"}`.

Flow: validate input, rate-limit by email, require an existing account, atomically
redeem the one-time access code, then re-salt + re-hash the new password, mark the
account approved, and delete ALL of the user's sessions (forcing re-login).
Success returns `200` `{success:true}`. Failures return `{error}` with one of
these statuses:

- `400 auth_email_invalid` — malformed email
- `400 auth_password_short` — new password under 6 characters
- `400 auth_password_mismatch` — newPassword ≠ confirmPassword
- `400 reset_no_account` — no account with this email
- `400 reset_code_invalid` — no active unused access code (a failed redemption
  is written to `login_attempts`)
- `405 method_not_allowed` — non-POST
- `429 too_many_attempts` — 5+ failed attempts in the last 15 min (email-based)

Deploy like `health` (dashboard editor, name `reset`, include `_shared/helpers.ts`,
same `ALLOWED_ORIGIN` secret).

---

## Session endpoints

### `validate-session`

`POST /functions/v1/validate-session` with body `{"token"}`.

Reads the session joined to its account. Returns `200 {valid:false}` when the token
is empty/unknown, expired, the account is banned, or the account is not approved.
Otherwise slides the session (sets `last_seen_at` to now and `expires_at` to
now + 30 days) and returns `200 {valid:true, uid, name, role, banned:false}`.
Failures return `{error}` (`405 method_not_allowed` for non-POST, `500 server_error`).

### `logout`

`POST /functions/v1/logout` with body `{"token"}`.

Deletes the session row server-side. Always returns `200 {success:true}` —
idempotent: an unknown or empty token still succeeds.

Deploy both like `health` (dashboard editor, include `_shared/helpers.ts`,
same `ALLOWED_ORIGIN` secret).

---

## Admin endpoints

All five endpoints require `Authorization: Bearer <admin-token>` (enforced by
`requireAdmin`). Error codes: `401 unauthorized` (no/invalid token), `403 forbidden`
(non-admin token).

### `admin/list-accounts`

`GET /functions/v1/admin/list-accounts` — returns an array of all accounts with
`uid`, `email`, `name`, `approved`, `banned`, `created_at`, and `last_login`
(timestamp of the most recent successful login, or `null`).

### `admin/login-history`

`GET /functions/v1/admin/login-history?uid=...` or `?email=...` — returns up to
100 login-log rows (`success`, `ip`, `device`, `attempted_at`) filtered by uid
or email. Omitting both returns the 100 most recent entries.

### `admin/ban`

`POST /functions/v1/admin/ban` — body `{"uid", "banned": true|false}`. Bans via
the atomic `ban_user(p_uid)` RPC (which also deletes the user's sessions) or
unbans by flipping `banned=false`. Returns `{success:true}`. Errors: `400
missing_fields` (uid absent), `400 cannot_ban_self`, `404 not_found` (unban
target doesn't exist).

### `admin/issue-code`

`POST /functions/v1/admin/issue-code` — body `{"email", "note"}`. Generates a
one-time access code in `XXXX-XXXX-XXXX` format (alphabet excludes `0/O/1/I`)
and inserts it into `access_codes`. Returns `{code, reused}` (reused = an unexpired
unused code already existed for that email). Errors: `400 auth_email_invalid`.

### `admin/list-sessions`

`GET /functions/v1/admin/list-sessions?uid=...` — returns up to 100 session rows
with `token_id` (first 8 chars + "…"), `device`, `created_at`, `last_seen_at`,
`expires_at`, optionally filtered by uid.

Deploy all five like `health` (dashboard editor, name each exactly as in the URL
table, include `_shared/helpers.ts`, same `ALLOWED_ORIGIN` secret).

---

## Cleanup endpoint

### `cleanup`

`POST /functions/v1/cleanup` — on-demand trigger of the `cleanup_old_logs()`
RPC, i.e. the same function the weekly pg_cron job (`cleanup-old-logs`,
`0 3 * * 1`) already runs. Success returns `200 {success:true}`; failures
return `{error}`. This endpoint is intentionally NOT admin-gated — it is
idempotent, deletes only rows older than the retention window (login logs
> 90 days, expired sessions), and mirrors the privilege of the scheduled cron job.

Deploy like `health` (dashboard editor, name `cleanup`, include
`_shared/helpers.ts`, same `ALLOWED_ORIGIN` secret).

---

## Issuing access codes

Two ways to create an access code for an email:

**1. SQL editor (no function call needed):**

```sql
insert into public.access_codes (email, code, note)
values ('owner3@example.com','OWNR-0003-CODE','some-note')
on conflict do nothing;
```

Access codes are one-time use: `redeem_access_code` marks them `used` atomically,
so a code can never be redeemed twice. Codes are independent of account status —
they are needed both for signup (`POST /signup`) and password reset
(`POST /reset`).

**2. Admin endpoint (runtime, from an admin session):**

```
POST /functions/v1/admin/issue-code
Authorization: Bearer <admin-token>
{"email":"owner3@example.com","note":"some-note"}
```

returns `200 {"code":"V2F7-K3QL-X9RM","reused":false}` (or `reused:true` if an
active unused code already exists for that email).

## Banning a user

```
POST /functions/v1/admin/ban
Authorization: Bearer <admin-token>
{"uid":"u_...","banned":true}     # ban
{"uid":"u_...","banned":false}    # unban
```

Bans are atomic: the `ban_user(p_uid)` RPC sets `banned=true` **and** deletes
every session for that uid in one transaction, so a banned user is logged out
immediately everywhere. Unban flips `banned=false` back (the schema also exposes
an `unban_user(p_uid)` RPC for the same purpose). Banning the calling admin's own
uid returns `400 cannot_ban_self`; unbanning an unknown uid returns `404
not_found`.

You can also ban directly in the SQL editor:

```sql
select public.ban_user('u_...');     -- ban + kill sessions
select public.unban_user('u_...');   -- unban
```

---

## Error code reference

Every `error` string the API can return, with its HTTP status and meaning. All
failing responses share the shape `{"error": "<code>"}`.

| Error code | HTTP | Where | Meaning |
|------------|------|-------|---------|
| `access_blocked` | 403 | `login` | account exists but is not yet approved (non-admin) |
| `access_code_invalid` | 400 | `signup` | no active, unused access code for the email |
| `auth_email_invalid` | 400 | `signup`, `reset`, `admin/issue-code` | malformed email address |
| `auth_exists` | 400 | `signup` | an account with this email already exists |
| `auth_invalid` | 401 | `login` | unknown account or wrong password |
| `auth_password_mismatch` | 400 | `signup`, `reset` | password ≠ confirmPassword |
| `auth_password_short` | 400 | `signup`, `reset` | password under 6 characters |
| `banned` | 403 | `login` | account is banned |
| `cannot_ban_self` | 400 | `admin/ban` | target uid is the calling admin's own uid |
| `forbidden` | 403 | all `admin/*` | bearer token valid but account is not admin |
| `full_name_required` | 400 | `signup` | missing `name` in the body |
| `invalid_session` | — (n/a) | `validate-session` | documentary: for empty/unknown/expired/banned tokens the endpoint returns `200 {"valid":false}` instead of an error string |
| `method_not_allowed` | 405 | every endpoint | request used the wrong HTTP method |
| `missing_fields` | 400 | `login`, `admin/ban` | required body field(s) absent (email/password; uid) |
| `not_found` | 404 | `admin/ban` | unban target account does not exist |
| `origin_not_allowed` | 403 | every endpoint | request carried an `Origin` header not on the CORS allow-list (browser cross-origin only; curl/cron have no Origin and pass) |
| `reset_code_invalid` | 400 | `reset` | no active, unused access code for the email |
| `reset_no_account` | 400 | `reset` | no account with this email |
| `server_error` | 500 | every endpoint | unexpected server or database error |
| `too_many_attempts` | 429 | `login`, `signup`, `reset` | 5+ failed attempts in the last 15 min (`login`/`reset` by email, `signup` by IP) |
| `unauthorized` | 401 | all `admin/*` | missing or invalid bearer token |

---

## End-to-end verification (pending Supabase project)

This section documents the **future** live verification pass. It has **not been
run**: the Supabase project does not exist yet, and no project ref has been
provided. It will be executed once the user provides the project ref and anon
key, and the results compared against the expected values below.

The pass runs from any browser-free shell (PowerShell here uses `curl.exe`,
never the aliased `Invoke-WebRequest`):

```powershell
# Variable setup (PowerShell)
$base = "https://<project-ref>.supabase.co/functions/v1"

# health
curl.exe -s -o NUL -w "%{http_code}`n" "$base/health"            # 200

# login as admin
$login = curl.exe -s -X POST "$base/login" -H "Content-Type: application/json" -d '{"email":"akuma","password":"gouki"}'
$token = ($login | ConvertFrom-Json).token

# list-accounts with admin token
curl.exe -s "$base/admin/list-accounts" -H "Authorization: Bearer $token"

# issue a code, ban, login-history, sessions — all with the token
# (see Task 8 Step 7 for expected values)
```

Replace `<project-ref>` in `$base` with the actual project ref. Expected values
for the admin calls (from Task 8 Step 7 of the implementation plan):

- `list-accounts` → `200` array containing `u_admin` and the signup test
  accounts; a non-admin user token returns `403 {"error":"forbidden"}`.
- `login-history?uid=u_admin` → rows with `success`/`ip`/`device`/`attempted_at`.
- `issue-code {"email":"owner3@example.com","note":"v3"}` → `{code}` in
  `XXXX-XXXX-XXXX` format.
- `ban {"uid":"<owner1's uid>","banned":true}` → `{success:true}`; the following
  `login` for that account returns `403 {"error":"banned"}` and its session rows
  are gone (instant kill). Unban → login works again.
- `list-sessions?uid=u_admin` → masked tokens + device + last_seen.
- Banning self (`{"uid":"u_admin","banned":true}`) → `400 {"error":"cannot_ban_self"}`.

Each observed response should also match the endpoint sections and the error
code table above. Record the outputs; any mismatch is a bug to fix in the
relevant function.