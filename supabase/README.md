# RepairDesk Supabase Backend

This directory holds the Supabase backend for the RepairDesk app: the database schema
(`schema.sql`) that defines authentication tables (accounts, access codes, sessions,
login audit/rate-limit logs), closed-by-default row-level security, server-side
functions, and a weekly cleanup cron job. Edge-function API handlers are added by
later tasks; this README currently covers only bootstrapping.

## Bootstrap

1. Create a Supabase project (free tier) at https://supabase.com/dashboard.
   Record the project ref (the `xxxx` in `https://xxxx.supabase.co`) — you'll need
   it for every subsequent setup and for Edge Function URLs.
2. Open **SQL Editor → New query**, paste the entire `schema.sql`, and run it.
   Expected: no errors. A `NOTICE: relation "... " already exists, skipping`
   message on re-run is fine (the schema is idempotent).
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

4. Seed an initial test access code (keep it — it is your test code for later checks):

```sql
insert into public.access_codes (email, code, note)
values ('owner1@example.com','OWNR-0001-CODE','task-test')
on conflict do nothing;
```

## Health endpoint and keepalive

### `health` Edge Function

Minimal probe used by the keepalive Action and for manual uptime checks.
GET returns `200 {"status":"ok"}`; anything else returns 405. Non-browser
callers (curl, cron) are allowed — only requests with a disallowed `Origin`
header are rejected (403).

Deploy in the dashboard:

1. **Edge Functions → Deploy a new function → Via editor**, name it `health`.
2. Add `functions/health/index.ts` and also `functions/_shared/helpers.ts`
   (the editor supports multiple files — place it under `_shared/helpers.ts`).
3. **Project Settings → Edge Functions → Secrets**: add `ALLOWED_ORIGIN` =
   `https://kossaitaguine331.github.io`.
4. Deploy.

Invoke URL: `https://<project-ref>.supabase.co/functions/v1/health`.

### Keepalive GitHub Action

`.github/workflows/supabase-keepalive.yml` pings the health endpoint every 4
days (cron `0 4 */4 * *`, plus manual `workflow_dispatch`) to keep the free-tier
project awake. It requires two repository secrets:

- `SUPABASE_HEALTH_URL` — the Invoke URL from above.
- `SUPABASE_HEALTH_TOKEN` — any long random string; add the same value as an
  Edge Function secret so only this Action can hit the endpoint.

## Login endpoint

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
