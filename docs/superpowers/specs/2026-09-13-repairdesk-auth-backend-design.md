# RepairDesk Auth Backend — Design Spec

- **Date:** 2026-09-13
- **Status:** Approved for implementation
- **Scope:** Convert RepairDesk auth from client-side localStorage to a Supabase-backed central backend. Shop data (customers, receipts, settings) stays in localStorage per-tenant, unchanged. Only accounts/access/auth move server-side.

## Section 1: Architecture

```text
[Client browser]                      [Supabase free tier]
  RepairDesk static page      ⇄        Edge Functions (Deno, TS)
  (stay on GitHub Pages)              |   login, signup, reset,
                                      |   validate-session, admin ops
                                      |
                                      ⇄   Postgres DB (RLS-protected)
                                          accounts | access_codes |
                                          sessions | login_logs |
                                          login_attempts
```

- Front-end stays on GitHub Pages, unchanged in look/behavior. `authSubmit`, `beginSession`, `getRegistry`, and the Users view get rewired to call the API instead of `localStorage`. Shop data (customers, receipts, settings) stays in `localStorage` exactly as today — this migration only touches accounts/access/auth.
- Edge Functions are the only path to the DB, using a server-side service key. The static page holds only the public anon key. Postgres RLS is `FORCE`d closed with zero client policies — a stolen anon key gets nothing.
- Session model: login returns an opaque random token stored in a `sessions` table (not a self-contained JWT), so a ban can kill access instantly, sessions can be tied to a device, and no client-side crypto/secrets are needed. Client keeps the token in `localStorage` (`rd_sess`) and sends it on every API call.
- Keep the existing SHA-256/salt password scheme and account fields (including the `akuma`/`gouki` admin login) rather than switching to Supabase Auth (GoTrue), since GoTrue can't import existing hashes.
- Deploy via Supabase's web dashboard — no local npm/CLI required.

### Section 1b — Hardening

1. **Free-tier keepalive**: Supabase free projects auto-pause after 7 days of inactivity. Add a `GET /health` Edge Function returning `200 OK`, plus a GitHub Actions cron (every 4 days) in this repo that pings it.
2. **Rate limiting on auth endpoints**: Before checking a password in `login`, count failed attempts for that email in the last 15 minutes; if ≥5, reject regardless of correctness. Apply the same pattern to `signup`, keyed by IP.
3. **Restrict CORS**: Every Edge Function sets `Access-Control-Allow-Origin` to the exact GitHub Pages origin (e.g. `https://kossaitaguine331.github.io`), never `*`. Reject preflight from other origins.
4. **Atomic access-code redemption**: Mark a code used via a single atomic `UPDATE ... WHERE code = $1 AND used = false RETURNING *`. Zero rows returned = invalid/already-used. No read-then-write.
5. **Log retention**: A weekly scheduled Edge Function (Supabase cron) deletes `login_logs` rows older than 90 days.
6. **IP handling**: Read `x-forwarded-for` for logging/rate-limiting only. Label it "reported IP" in the admin UI — never use it for security decisions.
7. **Ban = instant kill**: Banning sets `accounts.banned = true` AND deletes all rows from `sessions` for that uid, atomically — open tabs get logged out on their next API call.
8. **Secrets**: The service role key exists only as a Supabase Edge Function environment variable — never in any repo file, including comments or example env files.

## Section 2: Data model

### Tables

```sql
-- accounts
uid (text PK), email (text unique, lowercased), name, salt, hash,
role ('admin'|'user'), approved (bool), banned (bool default false),
approved_at, created_at, updated_at (timestamptz, default now())

-- access_codes
id (PK), email, code (unique), note, active (bool), used (bool),
issued_at, used_at (nullable)

-- sessions
token (text PK, 32-byte random), uid (FK → accounts, ON DELETE CASCADE),
created_at, last_seen_at, expires_at (30d sliding), device (user-agent)

-- login_logs
id (bigserial PK), email, uid (nullable), success (bool),
ip (text, "reported IP"), device (text), attempted_at (timestamptz)

-- login_attempts
id (bigserial PK), email, ip, success (bool), created_at,
index on (email, created_at) and (ip, created_at)
```

Tables are `FORCE RLS`, no client policies — only Edge Functions (via service key) touch the DB.

### Section 2b — Schema hardening

- `access_codes.code`: cryptographically random 10-char alphanumeric, never sequential.
- `CREATE INDEX ON sessions(uid);`
- `accounts.updated_at`, maintained via trigger on any row change.
- `sessions.uid REFERENCES accounts(uid) ON DELETE CASCADE`.
- Rate-limit access-code redemption attempts by IP (same 5/15min pattern).
- Every admin-only Edge Function resolves the caller's identity from their session token server-side and checks `role = 'admin'` in the DB — never trust a client-supplied role flag.

## Section 3: Edge Functions

| Function | Method | Auth required | Request body | Response |
|---|---|---|---|---|
| `/health` | GET | none | — | `200 OK` |
| `/signup` | POST | none | `{email, name, password, confirmPassword, code}` | `{token, uid, name, role}` or `{error}` |
| `/login` | POST | none | `{email, password}` | `{token, uid, name, role}` or `{error}` |
| `/reset` | POST | none | `{email, code, newPassword, confirmPassword}` | `{success: true}` or `{error}` |
| `/validate-session` | POST | session token | `{token}` | `{valid, uid, name, role, banned}` |
| `/logout` | POST | session token | `{token}` | `{success: true}` |
| `/admin/list-accounts` | GET | session token, role=admin | — | `[{uid, email, name, approved, banned, created_at, last_login}]` |
| `/admin/login-history` | GET | session token, role=admin | `?uid=` or `?email=` | `[{success, ip, device, attempted_at}]` |
| `/admin/ban` | POST | session token, role=admin | `{uid, banned: true\|false}` | `{success: true}` |
| `/admin/issue-code` | POST | session token, role=admin | `{email, note}` | `{code}` |
| `/admin/list-sessions` | GET | session token, role=admin | `?uid=` | `[{token_id, device, created_at, last_seen_at}]` |
| `/cleanup-logs` | POST (cron) | internal/service key only | — | `{deleted: n}` |

Every non-public endpoint must: validate the session token against `sessions`, reject if expired/missing, reject if `accounts.banned = true`, and for `/admin/*` additionally reject if `role != 'admin'`.

`/login` additionally rejects accounts where `approved = false` (role `admin` bypasses, matching today's `isApproved()` behavior).

## Section 4: Migration

- The existing `akuma`/`gouki` **admin** is seeded into `accounts` on first migration run (role `admin`, `approved = true`, `banned = false`), with its SHA-256 hash computed with the same `salt + '::' + pw` scheme so the existing admin login keeps working unchanged.
- **Existing store-owner accounts** (per-browser, SHA-256) are imported with their identity fields only — `email`, `name`, `role`, `created_at` — because hashes use a custom scheme that cannot be moved. Their password is set via the existing one-time re-register flow: the client signs up again with a fresh/admin-issued valid `access_codes.code` for their email, which the `/signup` endpoint uses to set the new password (this is the approved "import accounts, one-time re-register" path).
- The old `EMBEDDED_REGISTRY` publish-and-redeploy mechanism is retired; `access_codes` in the DB is the single source of truth.

## Section 5: Keepalive workflow YAML

```yaml
name: supabase-keepalive

on:
  schedule:
    - cron: "0 4 */4 * *"    # 04:00 on the 1st, 5th, 9th... of every month
  workflow_dispatch: {}

jobs:
  ping:
    runs-on: ubuntu-latest
    steps:
      - name: Ping Supabase health endpoint
        run: |
          code=$(curl -s -o /dev/null -w "%{http_code}" \
            -H "Authorization: Bearer ${{ secrets.SUPABASE_HEALTH_TOKEN }}" \
            "${{ secrets.SUPABASE_HEALTH_URL }}" || echo 000)
          echo "health status: $code"
          test "$code" = "200"
```

Repo secrets to configure: `SUPABASE_HEALTH_URL`, `SUPABASE_HEALTH_TOKEN`.

## Non-Goal / Guarantee

This backend solves "track and cut off customers who misuse or stop paying." It does **not** stop someone technical from deleting the auth screen entirely and running the static file with zero backend calls, since shop data lives independently in localStorage. That gap is closed with licensing/ToS terms your buyers agree to, not more code.