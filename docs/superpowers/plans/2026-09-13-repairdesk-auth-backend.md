# RepairDesk Supabase Auth Backend — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deploy a Supabase backend (Postgres schema + Deno Edge Functions) that moves RepairDesk accounts, access codes, sessions, and login logging out of client localStorage into a centrally-controlled server-side database.

**Architecture:** A static GitHub Pages front-end calls a set of Supabase Edge Functions (Deno/TypeScript). Those functions are the only path to the Postgres DB (service-role key, RLS force-closed to clients). Auth keeps the existing SHA-256/salt password scheme; logins return opaque session tokens stored in a `sessions` table so bans can kill active sessions instantly. This plan covers ONLY the backend; a separate plan handles the front-end rewiring.

**Tech Stack:** Supabase (free tier): Postgres 15, Deno Edge Functions, Row Level Security, pg_cron, GitHub Actions (keepalive cron). No local CLI/npm required — all deployment is via the Supabase dashboard.

**Spec:** `docs/superpowers/specs/2026-09-13-repairdesk-auth-backend-design.md`

## Global Constraints

- **Secrets:** The Supabase service-role key exists ONLY as an Edge Function environment variable (`SUPABASE_SERVICE_ROLE_KEY`, auto-injected by Supabase for edge functions). It must NEVER appear in any file in this repo — not in code, not in comments, not in `.env.example`.
- **CORS:** Every Edge Function returns `Access-Control-Allow-Origin: https://kossaitaguine331.github.io` (read from env `ALLOWED_ORIGIN`, never `*`). Preflight from any other origin → 403. Origin-missing requests (curl/server-to-server, e.g. keepalive) must still be allowed.
- **Hashing:** Password hash is hex(SHA-256(`${salt}::${password}`)) — byte-for-byte identical to the existing front-end `hashPassword`. Web Crypto `crypto.subtle.digest("SHA-256", ...)` in Deno matches.
- **Salt:** 16 random bytes → 32 lowercase hex chars.
- **Session token:** 32 random bytes → 64 lowercase hex chars; stored server-side.
- **Rate limit:** 5 failed attempts per email (login/reset) OR per IP (signup) within any rolling 15-minute window => reject that attempt regardless of correctness.
- **Atomic code redemption:** single `UPDATE ... WHERE email=$1 AND code=$2 AND active=true AND used=false RETURNING *`; zero rows ⇒ invalid/already-used.
- **Ban = instant kill:** one transaction sets `accounts.banned=true` AND deletes all `sessions` rows for that uid.
- **Admin checks:** admin endpoints resolve caller identity from their session token and check `accounts.role='admin'` in the DB. Never trust client-supplied role flags.
- **Email normalization:** all emails stored/looked-up lowercased.
- **Deployment:** Every artifact in this plan is applied via the Supabase Dashboard (SQL editor + Edge Functions editor). No CLI steps.

---

## File Structure

```
supabase/
  schema.sql                            # ALL tables, indexes, RLS, triggers, functions, seed, cron
  README.md                             # dashboard step-by-step deploy guide (SQL + each function)
  functions/
    health/index.ts                     # GET /health — keepalive probe
    login/index.ts                      # POST login (rate-limited, logged, session-creating)
    signup/index.ts                     # POST signup (code-gated, atomic redeem, session-creating)
    reset/index.ts                      # POST reset (code-gated)
    validate-session/index.ts           # POST validate-session (token check + sliding expiry)
    logout/index.ts                     # POST logout (token destroy)
    admin/list-accounts/index.ts        # GET admin accounts with last_login
    admin/login-history/index.ts        # GET login history by uid or email
    admin/ban/index.ts                  # POST atomic ban/unban
    admin/issue-code/index.ts           # POST mint new access code
    admin/list-sessions/index.ts        # GET active sessions for a uid
    cleanup/index.ts                    # POST weekly log retention
    _shared/helpers.ts                  # CORS, hashing, token, rate-limit, auth helpers (imported by each function via ../_shared/helpers.ts)
.github/
  workflows/
    supabase-keepalive.yml             # pings /health every 4 days
```

Each Edge Function imports `_shared/helpers.ts` (relative import works in the dashboard editor). Functions live at `supabase/functions/<name>/index.ts` so the dashboard's "deploy a new function → via editor" flow can take the file contents directly; the `_shared` folder must be deployed as part of each function (dashboard editor supports multiple files per function).

---

### Task 1: Schema — tables, RLS, triggers, functions, seed, cron

**Files:**
- Create: `supabase/schema.sql`
- Create: `supabase/README.md` (bootstrap section)
- Test: SQL run in Supabase dashboard SQL editor

**Interfaces:**
- Consumes: (none — first task)
- Produces: tables `accounts`, `access_codes`, `sessions`, `login_logs`, `login_attempts`; functions `set_updated_at()` (trigger), `redeem_access_code(text,text)`, `ban_user(text)`, `unban_user(text)`, `cleanup_old_logs()`; seed admin `u_admin`; cron job; RLS force-closed all tables.

- [ ] **Step 1: Write `supabase/schema.sql`**

```sql
-- =====================================================================
-- RepairDesk auth backend schema
-- Run in Dashboard -> SQL Editor. Idempotent (safe to re-run).
-- =====================================================================

create extension if not exists pgcrypto;

-- ---------------------------------------------------------------------
-- accounts
-- ---------------------------------------------------------------------
create table if not exists public.accounts (
  uid          text primary key,
  email        text not null unique,
  name         text not null default '',
  salt         text not null,
  hash         text not null,
  role         text not null default 'user' check (role in ('admin','user')),
  approved     boolean not null default false,
  banned       boolean not null default false,
  approved_at  timestamptz,
  created_at   timestamptz not null default now(),
  updated_at   timestamptz not null default now()
);

-- ---------------------------------------------------------------------
-- access_codes
-- ---------------------------------------------------------------------
create table if not exists public.access_codes (
  id         bigint generated always as identity primary key,
  email      text not null,
  code       text not null unique,
  note       text not null default '',
  active     boolean not null default true,
  used       boolean not null default false,
  issued_at  timestamptz not null default now(),
  used_at    timestamptz
);
create index if not exists access_codes_email_idx on public.access_codes (email);
create index if not exists access_codes_code_idx on public.access_codes (code);

-- ---------------------------------------------------------------------
-- sessions (opaque tokens)
-- ---------------------------------------------------------------------
create table if not exists public.sessions (
  token         text primary key,
  uid           text not null references public.accounts(uid) on delete cascade,
  created_at    timestamptz not null default now(),
  last_seen_at  timestamptz not null default now(),
  expires_at    timestamptz not null,
  device        text not null default ''
);
create index if not exists sessions_uid_idx on public.sessions (uid);
create index if not exists sessions_expires_idx on public.sessions (expires_at);

-- ---------------------------------------------------------------------
-- login_logs (audit trail, retained 90 days)
-- ---------------------------------------------------------------------
create table if not exists public.login_logs (
  id            bigint generated always as identity primary key,
  email         text not null,
  uid           text,
  success       boolean not null,
  ip            text,
  device        text,
  attempted_at  timestamptz not null default now()
);
create index if not exists login_logs_attempted_idx on public.login_logs (attempted_at);
create index if not exists login_logs_uid_idx on public.login_logs (uid);
create index if not exists login_logs_email_idx on public.login_logs (email);

-- ---------------------------------------------------------------------
-- login_attempts (rate-limit counters)
-- ---------------------------------------------------------------------
create table if not exists public.login_attempts (
  id          bigint generated always as identity primary key,
  email       text not null,
  ip          text not null,
  success     boolean not null,
  created_at  timestamptz not null default now()
);
create index if not exists login_attempts_email_idx on public.login_attempts (email, created_at);
create index if not exists login_attempts_ip_idx on public.login_attempts (ip, created_at);

-- ---------------------------------------------------------------------
-- RLS: force-closed, zero policies. Only the service-role key
-- (used by Edge Functions) bypasses RLS; clients get nothing.
-- ---------------------------------------------------------------------
alter table public.accounts      force row level security;
alter table public.access_codes  force row level security;
alter table public.sessions      force row level security;
alter table public.login_logs    force row level security;
alter table public.login_attempts force row level security;
alter table public.accounts      enable row level security;
alter table public.access_codes  enable row level security;
alter table public.sessions      enable row level security;
alter table public.login_logs    enable row level security;
alter table public.login_attempts enable row level security;

-- Create a role for the service key if not present (dashboard injects app keys automatically,
-- but this guarantees no anonymous/grant issue). No policies are created => deny otherwise.
revoke all on public.accounts, public.access_codes, public.sessions,
            public.login_logs, public.login_attempts from anon, authenticated;

-- ---------------------------------------------------------------------
-- updated_at trigger
-- ---------------------------------------------------------------------
create or replace function public.set_updated_at()
returns trigger language plpgsql as $$
begin
  new.updated_at := now();
  return new;
end;
$$;
drop trigger if exists trg_accounts_updated on public.accounts;
create trigger trg_accounts_updated
  before update on public.accounts
  for each row execute function public.set_updated_at();

-- ---------------------------------------------------------------------
-- Atomic access-code redemption (zero rows => invalid/already-used)
-- ---------------------------------------------------------------------
create or replace function public.redeem_access_code(p_email text, p_code text)
returns table(
  r_id bigint, r_email text, r_code text, r_active boolean, r_used boolean,
  r_issued_at timestamptz, r_used_at timestamptz
)
language plpgsql security definer set search_path = public as $$
begin
  return query
    update public.access_codes
       set used = true, used_at = now()
     where email = lower(trim(p_email))
       and code = trim(p_code)
       and active = true
       and used = false
     returning id, email, code, active, used, issued_at, used_at;
end;
$$;

-- ---------------------------------------------------------------------
-- Atomic ban: set banned + kill every active session in ONE transaction
-- ---------------------------------------------------------------------
create or replace function public.ban_user(p_uid text)
returns void language plpgsql security definer set search_path = public as $$
begin
  update public.accounts set banned = true where uid = p_uid;
  delete from public.sessions where uid = p_uid;
end;
$$;

create or replace function public.unban_user(p_uid text)
returns void language plpgsql security definer set search_path = public as $$
begin
  update public.accounts set banned = false where uid = p_uid;
end;
$$;

-- ---------------------------------------------------------------------
-- Log retention: prune login_logs >90d, expired sessions
-- ---------------------------------------------------------------------
create or replace function public.cleanup_old_logs()
returns void language plpgsql security definer set search_path = public as $$
begin
  delete from public.login_logs where attempted_at < now() - interval '90 days';
  delete from public.sessions where expires_at < now();
end;
$$;

-- Weekly cron (free-tier pg_cron)
select cron.schedule(
  'cleanup-old-logs',
  '0 3 * * 1',  -- 03:00 Monday
  $$select public.cleanup_old_logs();$$
);

-- ---------------------------------------------------------------------
-- Seed admin (akuma / gouki). Hash = SHA256(admin-salt::gouki) hex.
-- 3dd9ca08fdd0c60b7bb33f2dc0cc4114508b5c37f17f1c7c3905e74128fda8b4
-- ---------------------------------------------------------------------
insert into public.accounts (uid, email, name, salt, hash, role, approved, created_at)
values (
  'u_admin',
  'akuma',
  'Admin',
  'admin-salt',
  '3dd9ca08fdd0c60b7bb33f2dc0cc4114508b5c37f17f1c7c3905e74128fda8b4',
  'admin',
  true,
  now()
)
on conflict (uid) do nothing;
```

- [ ] **Step 2: Apply schema in the Supabase dashboard**

1. Create a Supabase project (free tier) at https://supabase.com/dashboard.
   Record the project ref (the `xxxx` in `https://xxxx.supabase.co`) — you'll need it for every function URL.
2. Open **SQL Editor → New query**, paste the entire `schema.sql`, run it.
   Expected: no errors; notice "NOTICE: relation ... already exists, skipping" is fine on re-run.

- [ ] **Step 3: Verify schema state**

Run in the dashboard SQL editor and confirm each returns rows/values as shown:

```sql
select table_name from information_schema.tables
 where table_schema='public'
 order by table_name;
-- expects: access_codes, accounts, login_attempts, login_logs, sessions

select uid, email, role, approved, banned from public.accounts;
-- expects: one row  u_admin | akuma | admin | true | false

select cron.jobid from cron.job where jobname='cleanup-old-logs';
-- expects: one row

select proname from pg_proc where pronamespace='public'::regnamespace
  and proname in ('redeem_access_code','ban_user','unban_user','cleanup_old_logs','set_updated_at')
order by proname;
-- expects: all five functions
```

- [ ] **Step 4: Prove atomic redemption + ban in the SQL editor**

```sql
-- Precondition: an active, unused code for addr1@example.com
insert into public.access_codes (email, code) values ('addr1@example.com','TEST-CODE-001') on conflict do nothing;

-- First redeem must return one row
select * from public.redeem_access_code('addr1@example.com','TEST-CODE-001');
-- Expect 1 row, used=true, used_at set

-- Second redeem must return ZERO rows (already used)
select * from public.redeem_access_code('addr1@example.com','TEST-CODE-001');
-- Expect 0 rows

-- Wrong code for a real address, and code for an unknown address: 0 rows
select * from public.redeem_access_code('addr1@example.com','WRONG-CODE');
select * from public.redeem_access_code('nobody@example.com','TEST-CODE-001');
-- Both expect 0 rows

-- Ban test:
select public.ban_user('u_admin');
-- expect: void
select banned from public.accounts where uid='u_admin';
-- expect: true
select public.unban_user('u_admin');
select banned from public.accounts where uid='u_admin';
-- expect: false
```

- [ ] **Step 5: Seed an initial test access code**

Insert a code you will use during the remaining task checks (keep it, it's your test code):

```sql
insert into public.access_codes (email, code, note)
values ('owner1@example.com','OWNR-0001-CODE','task-test')
on conflict do nothing;
```

- [ ] **Step 6: Commit**

```bash
git add supabase/schema.sql supabase/README.md
git commit -m "Add Supabase schema: accounts, codes, sessions, logs, RLS, cron, seed admin"
```

---

### Task 2: Shared Edge Function helpers (`_shared/helpers.ts`)

**Files:**
- Create: `supabase/functions/_shared/helpers.ts`
- Test: `node --check` on a transpiled stand-in is not applicable (TS); instead validate by deployment in Task 3.

**Interfaces:**
- Consumes: (none)
- Produces: `corsHeaders`, `handleCors(req)`, `json(status, body)`, `cryptoToken()`, `makeSalt()`, `hashPassword(pw, salt)`, `getClientIp(req)`, `getDevice(req)`, `rateLimited(client, email, ip, key)`, `findSessionUser(client, token)`, `sessionOk(client, token)`, `requireAdmin(req, client)`, `createDb()`, `DB_URL`, `handleError`, `CLIENT_URL`

- [ ] **Step 1: Write `supabase/functions/_shared/helpers.ts`**

```ts
// Shared helpers for RepairDesk auth Edge Functions.
// All functions import { ... } from "../_shared/helpers.ts".

import { createClient } from "jsr:@supabase/supabase-js@2";

const CLIENT_URL = Deno.env.get("ALLOWED_ORIGIN") || "https://kossaitaguine331.github.io";
const DB_URL = Deno.env.get("SUPABASE_URL") || "";

export const corsHeaders = {
  "Access-Control-Allow-Origin": CLIENT_URL,
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "authorization, content-type",
  "Vary": "Origin",
};

function isAllowedOrigin(origin: string): boolean {
  return origin === CLIENT_URL;
}

export function json(status: number, body: unknown): Response {
  const payload = JSON.stringify(body);
  return new Response(payload, {
    status,
    headers: { "Content-Type": "application/json", ...corsHeaders },
  });
}

export function handleCors(req: Request): Response | null {
  const origin = req.headers.get("origin");
  if (req.method === "OPTIONS") {
    if (origin && !isAllowedOrigin(origin)) return json(403, { error: "origin_not_allowed" });
    return new Response(null, { status: 204, headers: corsHeaders });
  }
  // Non-OPTIONS: if an Origin header is present it must be allowed;
  // requests with no Origin (curl, server-to-server keepalive) pass through.
  if (origin && !isAllowedOrigin(origin)) return json(403, { error: "origin_not_allowed" });
  return null;
}

export function cryptoToken(bytes = 32): string {
  const arr = new Uint8Array(bytes);
  crypto.getRandomValues(arr);
  return Array.from(arr, (b) => b.toString(16).padStart(2, "0")).join("");
}

export function makeSalt(): string {
  return cryptoToken(16);
}

export async function hashPassword(pw: string, salt: string): Promise<string> {
  const data = new TextEncoder().encode(salt + "::" + pw);
  const digest = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, "0")).join("");
}

export function getClientIp(req: Request): string {
  const xff = req.headers.get("x-forwarded-for");
  if (xff) return xff.split(",")[0].trim();
  return req.headers.get("x-real-ip") || "unknown";
}

export function getDevice(req: Request): string {
  return (req.headers.get("user-agent") || "").slice(0, 300);
}

export function createDb() {
  // Deno + Supabase runtime auto-injects these env vars for edge functions.
  const url = DB_URL;
  const key = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") || "";
  return createClient(url, key, { auth: { persistSession: false } });
}

export async function rateLimited(db: any, email = "", ip = "", key = "email"): Promise<boolean> {
  const since = new Date(Date.now() - 15 * 60 * 1000).toISOString();
  const col = key === "ip" ? "ip" : "email";
  const value = key === "ip" ? ip : email;
  if (!value) return false;
  const { count, error } = await db
    .from("login_attempts")
    .select("id", { count: "exact", head: true })
    .eq(col, value)
    .eq("success", false)
    .gte("created_at", since);
  if (error) return false; // fail open on DB error to avoid full outage
  return (count || 0) >= 5;
}

export async function findSessionUser(db: any, token: string) {
  if (!token) return null;
  const { data } = await db
    .from("sessions")
    .select("uid, expires_at, accounts(uid, email, name, role, approved, banned)")
    .eq("token", token)
    .maybeSingle();
  return data ?? null;
}

export async function sessionOk(db: any, token: string) {
  const s = await findSessionUser(db, token);
  if (!s) return null;
  if (new Date(s.expires_at).getTime() < Date.now()) return null;
  if (!s.accounts) return null;
  if (s.accounts.banned || !s.accounts.approved) return null;
  return s;
}

export async function requireAdmin(req: Request, db: any): Promise<Response | { account: any; token: string } | null> {
  const token = (req.headers.get("authorization") || "").replace(/^Bearer\s+/i, "");
  const s = await sessionOk(db, token);
  if (!s) return json(401, { error: "unauthorized" });
  if ((s as any).accounts?.role !== "admin") return json(403, { error: "forbidden" });
  return { account: (s as any).accounts, token };
}

export function handleError(e: unknown): Response {
  console.error(e);
  return json(500, { error: "server_error" });
}
```

- [ ] **Step 2: Commit**

```bash
git add supabase/functions/_shared/helpers.ts
git commit -m "Add shared edge-function helpers (CORS, hashing, sessions, rate limit)"
```

Deployment note: the dashboard edge-function runtime resolves `jsr:` (and `npm:`) imports natively. When a function fails to boot, check its Logs tab for import errors before debugging logic. Also: the dashboard "Deploy via editor" flow supports multiple files per function — include both `index.ts` and `_shared/helpers.ts` (as `_shared/helpers.ts`) so the relative import resolves.

---

### Task 3: `/health` + keepalive workflow

**Files:**
- Create: `supabase/functions/health/index.ts`
- Create: `.github/workflows/supabase-keepalive.yml`
- Modify: `supabase/README.md` (health section)

**Interfaces:**
- Consumes: helpers from Task 2.
- Produces: GET `/functions/v1/health` → `200 {"status":"ok"}`; GitHub Action `supabase-keepalive`.

- [ ] **Step 1: Write `supabase/functions/health/index.ts`**

```ts
import { json, handleCors } from "../_shared/helpers.ts";

Deno.serve(async (req) => {
  const cors = handleCors(req);
  if (cors) return cors;
  if (req.method !== "GET") return json(405, { error: "method_not_allowed" });
  return json(200, { status: "ok" });
});
```

- [ ] **Step 2: Write `.github/workflows/supabase-keepalive.yml`**

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

- [ ] **Step 3: Deploy `/health` in the dashboard**

1. Dashboard → **Edge Functions → Deploy a new function → Via editor**.
2. Name it exactly `health`.
3. Add the function file `supabase/functions/health/index.ts` (editor supports multiple files — include `_shared/helpers.ts` under the same function as `_shared/helpers.ts`).
4. **Project Settings → Edge Functions → Secrets**: add `ALLOWED_ORIGIN` = `https://kossaitaguine331.github.io`.
5. Deploy. It may take 10–30s.

- [ ] **Step 4: Verify the live endpoint**

From the health endpoint page in the dashboard, copy the **Invoke URL** (`https://<project-ref>.supabase.co/functions/v1/health`).

Then on your machine:

```powershell
curl.exe -s -o NUL -w "%{http_code}" "https://<project-ref>.supabase.co/functions/v1/health"
# expect: 200
```

And with a SPOOFED foreign origin (must be 403):

```powershell
curl.exe -s -i -X OPTIONS "https://<project-ref>.supabase.co/functions/v1/health" -H "Origin: https://evil.example.com" | Select-String -Pattern "HTTP/|Access-Control"
# expect: 403
```

And with your real origin (must be 204 + ACAO header):

```powershell
curl.exe -s -i -X OPTIONS "https://<project-ref>.supabase.co/functions/v1/health" -H "Origin: https://kossaitaguine331.github.io" | Select-String -Pattern "HTTP/|Access-Control"
# expect: 204 with Access-Control-Allow-Origin: https://kossaitaguine331.github.io
```

- [ ] **Step 5: Configure the keepalive Action secrets**

GitHub repo **Settings → Secrets and variables → Actions → New repository secret**:
- `SUPABASE_HEALTH_URL` = the Invoke URL from Step 4.
- `SUPABASE_HEALTH_TOKEN` = any long random string; add the same value as an Edge Function secret so only this Action is trusted.
  (Optional hardening: make `/health` require the header — see "optional" note below. For free-tier keepalive a bare probe is sufficient.)

- [ ] **Step 6: Commit**

```bash
git add supabase/functions/health/index.ts .github/workflows/supabase-keepalive.yml
git commit -m "Add health edge function and keepalive workflow"
```

---

### Task 4: `/login`

**Files:**
- Create: `supabase/functions/login/index.ts`
- Modify: `supabase/README.md`

**Interfaces:**
- Consumes: `json`, `handleCors`, `hashPassword`, `makeSalt` (not needed here), `cryptoToken`, `getClientIp`, `getDevice`, `createDb`, `rateLimited`, `handleError`.
- Produces: `POST /functions/v1/login` → `{token, uid, name, role}` | `{error}`.

Behavior: rate-limit by email (count failed attempts ≤15min; ≥5 → 429 `too_many_attempts`, even if password right). Then: lookup account by email → 401 `auth_invalid` if missing; 403 `banned` if banned; 403 `access_blocked` if not approved & non-admin; verify `hash === sha256(salt::pw)` else 401 `auth_invalid` (+ insert a failed `login_attempts` row). On success: insert `login_logs(success=true)`, mint token, insert session (expires now+30d, sliding), return token+account. Log every attempt (success+fail) in `login_logs`; record failures in `login_attempts`.

- [ ] **Step 1: Write `supabase/functions/login/index.ts`**

```ts
import {
  json, handleCors, hashPassword, cryptoToken, getClientIp, getDevice,
  createDb, rateLimited, handleError,
} from "../_shared/helpers.ts";

Deno.serve(async (req) => {
  const cors = handleCors(req);
  if (cors) return cors;
  if (req.method !== "POST") return json(405, { error: "method_not_allowed" });

  try {
    const db = createDb();
    const body = await req.json().catch(() => ({}));
    const email = String(body.email || "").trim().toLowerCase();
    const password = String(body.password || "");
    const ip = getClientIp(req);
    const device = getDevice(req);

    if (!email || !password) return json(400, { error: "missing_fields" });

    const tooMany = await rateLimited(db, email, ip, "email");
    if (tooMany) {
      await db.from("login_logs").insert({ email, success: false, ip, device });
      return json(429, { error: "too_many_attempts" });
    }

    const { data: acc } = await db.from("accounts")
      .select("uid,email,name,role,approved,banned,salt,hash")
      .eq("email", email)
      .maybeSingle();

    const fail = async (error: string, status = 401) => {
      await db.from("login_attempts").insert({ email, ip, success: false });
      await db.from("login_logs").insert({ email, uid: acc?.uid ?? null, success: false, ip, device });
      return json(status, { error });
    };

    if (!acc) return await fail("auth_invalid");
    if (acc.banned) return await fail("banned", 403);
    if (!acc.approved && acc.role !== "admin") return await fail("access_blocked", 403);

    const hash = await hashPassword(password, acc.salt);
    if (hash !== acc.hash) return await fail("auth_invalid");

    const token = cryptoToken(32);
    const expires = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();
    const { error: se } = await db.from("sessions").insert({
      token, uid: acc.uid, expires_at: expires, device,
    });
    if (se) return handleError(se);
    await db.from("login_logs").insert({ email, uid: acc.uid, success: true, ip, device });

    return json(200, { token, uid: acc.uid, name: acc.name, role: acc.role });
  } catch (e) {
    return handleError(e);
  }
});
```

- [ ] **Step 2: Deploy `/login`** (dashboard editor, exact name `login`, include `_shared/helpers.ts`). Reuse `ALLOWED_ORIGIN` secret.

- [ ] **Step 3: Verify with the dashboard function tester**

Dashboard → Edge Functions → `login` → **Test Function** tab. Send these fixtures (record every result):

| Payload | Expected |
|---|---|
| `{"email":"akuma","password":"gouki"}` | `200` `{token, uid:"u_admin", role:"admin"}` |
| `{"email":"akuma","password":"wrong"}` | `401 {"error":"auth_invalid"}` |
| `{"email":"akuma","password":"gouki"}` ×5+ rapid | `429 {"error":"too_many_attempts"}` after 5 fails |
| `{"email":"nobody@example.com","password":"x"}` | `401 {"error":"auth_invalid"}` |

Note the dashboard tester may not forward a real IP or emulate Origin realistically — the CORS and IP paths are separately covered by curl in Task 3 for health; for login the critical behaviors above are the auth + rate-limit logic.

After the test, confirm in **Table Editor → login_logs** that successes AND failures are recorded with `attempted_at` timestamps, and **sessions** gained a row for the successful `akuma` login.

- [ ] **Step 4: Commit**

```bash
git add supabase/functions/login/index.ts
git commit -m "Add login edge function (rate-limited, logged, session-issuing, SHA-256)"
```

---

### Task 5: `/signup`

**Files:**
- Create: `supabase/functions/signup/index.ts`
- Modify: `supabase/README.md`

**Interfaces:**
- Consumes: helpers; atomic `redeem_access_code` RPC; `makeSalt`, `hashPassword`.
- Produces: `POST /functions/v1/signup` → `{token, uid, name, role}` | `{error}`.

Behavior: rate-limit by IP (failed attempts ≤15min, ≥5 → `too_many_attempts`); validate email format, password ≥6, confirm matches, name present; `redeem_access_code(email, code)` atomically (zero rows → `access_code_invalid`); reject duplicate email (`auth_exists`); insert account with fresh 16-byte salt + hash, `approved=true`, `approved_at=now()`, role `user`; insert `login_logs(success=true)`; mint session; return token. Record code-redeem failures in `login_attempts` (email+ip) to satisfy IP rate-limiting on signup.

- [ ] **Step 1: Write `supabase/functions/signup/index.ts`**

```ts
import {
  json, handleCors, hashPassword, makeSalt, cryptoToken, getClientIp, getDevice,
  createDb, rateLimited, handleError,
} from "../_shared/helpers.ts";

Deno.serve(async (req) => {
  const cors = handleCors(req);
  if (cors) return cors;
  if (req.method !== "POST") return json(405, { error: "method_not_allowed" });

  try {
    const db = createDb();
    const body = await req.json().catch(() => ({}));
    const email = String(body.email || "").trim().toLowerCase();
    const name = String(body.name || "").trim();
    const password = String(body.password || "");
    const confirm = String(body.confirmPassword || "");
    const code = String(body.code || "").trim();
    const ip = getClientIp(req);
    const device = getDevice(req);

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return json(400, { error: "auth_email_invalid" });
    if (name.length === 0) return json(400, { error: "full_name_required" });
    if (password.length < 6) return json(400, { error: "auth_password_short" });
    if (password !== confirm) return json(400, { error: "auth_password_mismatch" });

    const tooMany = await rateLimited(db, "", ip, "ip");
    if (tooMany) return json(429, { error: "too_many_attempts" });

    const redeem = async () => {
      const { data, error } = await db.rpc("redeem_access_code", { p_email: email, p_code: code });
      if (error || !data || data.length === 0) return false;
      return true;
    };
    if (!(await redeem())) {
      await db.from("login_attempts").insert({ email, ip, success: false });
      return json(400, { error: "access_code_invalid" });
    }

    const { data: existing } = await db.from("accounts").select("uid").eq("email", email).maybeSingle();
    if (existing) return json(400, { error: "auth_exists" });

    const salt = makeSalt();
    const hash = await hashPassword(password, salt);
    const uid = "u" + Date.now().toString(36) + cryptoToken(4);
    const { error: ie } = await db.from("accounts").insert({
      uid, email, name, salt, hash, role: "user", approved: true, approved_at: new Date().toISOString(),
    });
    if (ie) return handleError(ie);

    const token = cryptoToken(32);
    const expires = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();
    const { error: se } = await db.from("sessions").insert({ token, uid, expires_at: expires, device });
    if (se) return handleError(se);
    await db.from("login_logs").insert({ email, uid, success: true, ip, device });

    return json(200, { token, uid, name, role: "user" });
  } catch (e) {
    return handleError(e);
  }
});
```

- [ ] **Step 2: Deploy `/signup`** (dashboard editor; include helper).

- [ ] **Step 3: Verify with the dashboard function tester**

Using the seeded code `OWNR-0001-CODE` for `owner1@example.com` (Task 1 Step 5):

| Payload | Expected |
|---|---|
| `{"email":"owner1@example.com","name":"Owner One","password":"secret9","confirmPassword":"secret9","code":"OWNR-0001-CODE"}` | `200 {token, uid, name, role:"user"}` |
| Re-run same payload again | `400 {"error":"auth_exists"}` (account exists; code already used anyway) |
| `{"email":"owner2@example.com","name":"O2","password":"secret9","confirmPassword":"secret9","code":"WRONG-CODE"}` | `400 {"error":"access_code_invalid"}` |
| Bad email `not-an-email` | `400 {"error":"auth_email_invalid"}` |
| Short password | `400 {"error":"auth_password_short"}` |
| Mismatched confirm | `400 {"error":"auth_password_mismatch"}` |

Then issue a brand-new code for `owner2@example.com` via SQL:
```sql
insert into public.access_codes (email, code) values ('owner2@example.com','OWNR-0002-CODE') on conflict do nothing;
```
and re-test the full signup — expect `200`.

Confirm in Table Editor: `accounts` contains `owner1@example.com` (approved=true), `owner2@example.com`; `access_codes` shows both codes `used=true` with `used_at` set.

- [ ] **Step 4: Commit**

```bash
git add supabase/functions/signup/index.ts
git commit -m "Add signup edge function (atomic code gate, IP rate-limit, account+session creation)"
```

---

### Task 6: `/reset`

**Files:**
- Create: `supabase/functions/reset/index.ts`
- Modify: `supabase/README.md`

**Interfaces:**
- Consumes: helpers.
- Produces: `POST /functions/v1/reset` → `{success:true}` | `{error}`.

Behavior: rate-limit by email; validate email format, newPassword ≥6, confirm match; account must exist (`reset_no_account`); `redeem_access_code(email, code)` must succeed (code active+unused) → else `reset_code_invalid`; re-salt + re-hash + set `approved=true`; delete all sessions for that uid (force re-login after reset); return `{success:true}`.

- [ ] **Step 1: Write `supabase/functions/reset/index.ts`**

```ts
import {
  json, handleCors, hashPassword, makeSalt, getClientIp, getDevice,
  createDb, rateLimited, handleError,
} from "../_shared/helpers.ts";

Deno.serve(async (req) => {
  const cors = handleCors(req);
  if (cors) return cors;
  if (req.method !== "POST") return json(405, { error: "method_not_allowed" });

  try {
    const db = createDb();
    const body = await req.json().catch(() => ({}));
    const email = String(body.email || "").trim().toLowerCase();
    const code = String(body.code || "").trim();
    const newPassword = String(body.newPassword || "");
    const confirm = String(body.confirmPassword || "");
    const ip = getClientIp(req);
    const device = getDevice(req);

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return json(400, { error: "auth_email_invalid" });
    if (newPassword.length < 6) return json(400, { error: "auth_password_short" });
    if (newPassword !== confirm) return json(400, { error: "auth_password_mismatch" });

    const tooMany = await rateLimited(db, email, ip, "email");
    if (tooMany) return json(429, { error: "too_many_attempts" });

    const { data: acc } = await db.from("accounts")
      .select("uid")
      .eq("email", email)
      .maybeSingle();
    if (!acc) return json(400, { error: "reset_no_account" });

    const { data: redeemData, error: redeemErr } = await db.rpc("redeem_access_code", { p_email: email, p_code: code });
    if (redeemErr || !redeemData || redeemData.length === 0) {
      await db.from("login_attempts").insert({ email, ip, success: false });
      return json(400, { error: "reset_code_invalid" });
    }

    const salt = makeSalt();
    const hash = await hashPassword(newPassword, salt);
    const { error: ue } = await db.from("accounts")
      .update({ salt, hash, approved: true })
      .eq("uid", acc.uid);
    if (ue) return handleError(ue);

    await db.from("sessions").delete().eq("uid", acc.uid);
    await db.from("login_logs").insert({ email, uid: acc.uid, success: true, ip, device });

    return json(200, { success: true });
  } catch (e) {
    return handleError(e);
  }
});
```

- [ ] **Step 2: Deploy `/reset`** (dashboard editor; include helper).

- [ ] **Step 3: Verify with the dashboard function tester**

- Issue a fresh code for `owner1@example.com` (`insert into public.access_codes (email, code) values ('owner1@example.com','RESET-0001-CODE') on conflict do nothing;`).
- `{"email":"owner1@example.com","code":"RESET-0001-CODE","newPassword":"newsecret9","confirmPassword":"newsecret9"}` → `200 {success:true}`.
- Re-use the same code → `400 {"error":"reset_code_invalid"}` (atomic redeem consumed it).
- Unknown email → `400 {"error":"reset_no_account"}`.
- Then `POST login` with `owner1@example.com` / `newsecret9` → `200` (proves the reset applied).

- [ ] **Step 4: Commit**

```bash
git add supabase/functions/reset/index.ts
git commit -m "Add reset edge function (code-gated password reset, session kill)"
```

---

### Task 7: `/validate-session` and `/logout`

**Files:**
- Create: `supabase/functions/validate-session/index.ts`
- Create: `supabase/functions/logout/index.ts`
- Modify: `supabase/README.md`

**Interfaces:**
- Consumes: helpers.
- Produces: `POST /functions/v1/validate-session` → `{valid, uid, name, role, banned}`; `POST /functions/v1/logout` → `{success:true}`.

validate-session: read token from body `{token}`; look up session joined to account; if missing/expired/banned/not-approved → `{valid:false}`; else bump `last_seen_at` and slide `expires_at` to now+30d, return `{valid:true, uid, name, role, banned:false}`.

logout: read token `{token}`; delete that session row; always `{success:true}`.

- [ ] **Step 1: Write `supabase/functions/validate-session/index.ts`**

```ts
import { json, handleCors, createDb, findSessionUser, handleError } from "../_shared/helpers.ts";

Deno.serve(async (req) => {
  const cors = handleCors(req);
  if (cors) return cors;
  if (req.method !== "POST") return json(405, { error: "method_not_allowed" });

  try {
    const db = createDb();
    const body = await req.json().catch(() => ({}));
    const token = String(body.token || "");

    const s = await findSessionUser(db, token);
    if (!s || new Date(s.expires_at).getTime() < Date.now()) return json(200, { valid: false });
    const acc = s.accounts;
    if (!acc || acc.banned || !acc.approved) return json(200, { valid: false });

    const { error } = await db.from("sessions")
      .update({ last_seen_at: new Date().toISOString(), expires_at: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString() })
      .eq("token", token);
    if (error) return handleError(error);

    return json(200, { valid: true, uid: acc.uid, name: acc.name, role: acc.role, banned: false });
  } catch (e) {
    return handleError(e);
  }
});
```

- [ ] **Step 2: Write `supabase/functions/logout/index.ts`**

```ts
import { json, handleCors, createDb, handleError } from "../_shared/helpers.ts";

Deno.serve(async (req) => {
  const cors = handleCors(req);
  if (cors) return cors;
  if (req.method !== "POST") return json(405, { error: "method_not_allowed" });

  try {
    const db = createDb();
    const body = await req.json().catch(() => ({}));
    const token = String(body.token || "");
    if (token) await db.from("sessions").delete().eq("token", token);
    return json(200, { success: true });
  } catch (e) {
    return handleError(e);
  }
});
```

- [ ] **Step 3: Deploy both** (dashboard editor; include helper on each).

- [ ] **Step 4: Verify with the dashboard function tester**

1. Login as `akuma/gouki` → capture token.
2. `POST validate-session {"token":"<token>"}` → `200 {valid:true,...}`.
3. `POST validate-session {"token":"garbage"}` → `200 {valid:false}`.
4. `POST logout {"token":"<token>"}` → `{success:true}`.
5. `POST validate-session {"token":"<token>"}` again → `{valid:false}` (killed server-side).
6. In Table Editor → `sessions`, confirm the row is gone.

- [ ] **Step 5: Commit**

```bash
git add supabase/functions/validate-session/index.ts supabase/functions/logout/index.ts
git commit -m "Add validate-session and logout edge functions"
```

---

### Task 8: Admin endpoints (list-accounts, login-history, ban, issue-code, list-sessions)

**Files:**
- Create: `supabase/functions/admin/list-accounts/index.ts`
- Create: `supabase/functions/admin/login-history/index.ts`
- Create: `supabase/functions/admin/ban/index.ts`
- Create: `supabase/functions/admin/issue-code/index.ts`
- Create: `supabase/functions/admin/list-sessions/index.ts`
- Modify: `supabase/README.md`

**Interfaces:**
- Consumes: `requireAdmin`, `json`, `handleCors`, `createDb`, `handleError`, `cryptoToken`.
- Produces (all require `Authorization: Bearer <admin-token>`):
  - `GET list-accounts` → array `{uid, email, name, approved, banned, created_at, last_login}`
  - `GET login-history?uid=u123` or `?email=x@y.z` → array `{success, ip, device, attempted_at}`
  - `POST ban {uid, banned:true|false}` → `{success:true}`
  - `POST issue-code {email, note}` → `{code}`
  - `GET list-sessions?uid=u123` → array `{token_id, device, created_at, last_seen_at}` (token masked)

- [ ] **Step 1: Write `admin/list-accounts/index.ts`**

```ts
import { json, handleCors, createDb, requireAdmin, handleError } from "../../_shared/helpers.ts";

Deno.serve(async (req) => {
  const cors = handleCors(req);
  if (cors) return cors;
  if (req.method !== "GET") return json(405, { error: "method_not_allowed" });

  try {
    const db = createDb();
    const auth = await requireAdmin(req, db);
    if (auth instanceof Response) return auth;

    const { data, error } = await db.from("accounts")
      .select("uid,email,name,approved,banned,created_at")
      .order("created_at", { ascending: true });
    if (error) return handleError(error);

    // last successful login per account
    const lastLogins: Record<string, string> = {};
    const { data: logs } = await db.from("login_logs")
      .select("uid,attempted_at")
      .eq("success", true)
      .order("attempted_at", { ascending: false });
    (logs || []).forEach((l: any) => { if (l.uid && !(l.uid in lastLogins)) lastLogins[l.uid] = l.attempted_at; });

    const out = (data || []).map((a: any) => ({
      uid: a.uid, email: a.email, name: a.name, approved: a.approved,
      banned: a.banned, created_at: a.created_at, last_login: lastLogins[a.uid] || null,
    }));
    return json(200, out);
  } catch (e) {
    return handleError(e);
  }
});
```

- [ ] **Step 2: Write `admin/login-history/index.ts`**

```ts
import { json, handleCors, createDb, requireAdmin, handleError } from "../../_shared/helpers.ts";

Deno.serve(async (req) => {
  const cors = handleCors(req);
  if (cors) return cors;
  if (req.method !== "GET") return json(405, { error: "method_not_allowed" });

  try {
    const db = createDb();
    const auth = await requireAdmin(req, db);
    if (auth instanceof Response) return auth;

    const url = new URL(req.url);
    const uid = url.searchParams.get("uid");
    const email = url.searchParams.get("email");

    let q = db.from("login_logs")
      .select("success,ip,device,attempted_at")
      .order("attempted_at", { ascending: false })
      .limit(100);
    if (uid) q = q.eq("uid", uid);
    else if (email) q = q.eq("email", (email || "").toLowerCase());

    const { data, error } = await q;
    if (error) return handleError(error);
    return json(200, data || []);
  } catch (e) {
    return handleError(e);
  }
});
```

- [ ] **Step 3: Write `admin/ban/index.ts`**

```ts
import { json, handleCors, createDb, requireAdmin, handleError } from "../../_shared/helpers.ts";

Deno.serve(async (req) => {
  const cors = handleCors(req);
  if (cors) return cors;
  if (req.method !== "POST") return json(405, { error: "method_not_allowed" });

  try {
    const db = createDb();
    const auth = await requireAdmin(req, db);
    if (auth instanceof Response) return auth;

    const body = await req.json().catch(() => ({}));
    const targetUid = String(body.uid || "");
    const banned = Boolean(body.banned);
    if (!targetUid) return json(400, { error: "missing_fields" });
    if (targetUid === (auth as any).account.uid) return json(400, { error: "cannot_ban_self" });

    if (banned) {
      const { error } = await db.rpc("ban_user", { p_uid: targetUid });
      if (error) return handleError(error);
    } else {
      const { data, error } = await db.from("accounts").update({ banned: false }).eq("uid", targetUid).select("uid");
      if (error) return handleError(error);
      if (!data || data.length === 0) return json(404, { error: "not_found" });
    }
    return json(200, { success: true });
  } catch (e) {
    return handleError(e);
  }
});
```

- [ ] **Step 4: Write `admin/issue-code/index.ts`**

```ts
import { json, handleCors, createDb, requireAdmin, handleError, cryptoToken } from "../../_shared/helpers.ts";

const CODE_CHARS = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; // no 0/O/1/I
function genCode(): string {
  const rand = crypto.getRandomValues(new Uint8Array(12));
  let s = "";
  for (let i = 0; i < 4; i++) {
    if (i) s += "-";
    let g = "";
    for (let j = 0; j < 3; j++) g += CODE_CHARS[rand[i * 3 + j] % CODE_CHARS.length];
    s += g;
  }
  return s; // XXXX-XXXX-XXXX
}

Deno.serve(async (req) => {
  const cors = handleCors(req);
  if (cors) return cors;
  if (req.method !== "POST") return json(405, { error: "method_not_allowed" });

  try {
    const db = createDb();
    const auth = await requireAdmin(req, db);
    if (auth instanceof Response) return auth;

    const body = await req.json().catch(() => ({}));
    const email = String(body.email || "").trim().toLowerCase();
    const note = String(body.note || "").slice(0, 200);
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return json(400, { error: "auth_email_invalid" });

    const { data: existing } = await db.from("access_codes")
      .select("code")
      .eq("email", email)
      .eq("active", true)
      .eq("used", false)
      .maybeSingle();
    if (existing) return json(200, { code: existing.code, reused: true });

    const code = genCode();
    const { error } = await db.from("access_codes").insert({ email, code, note });
    if (error) return handleError(error);
    return json(200, { code, reused: false });
  } catch (e) {
    return handleError(e);
  }
});
```

- [ ] **Step 5: Write `admin/list-sessions/index.ts`**

```ts
import { json, handleCors, createDb, requireAdmin, handleError } from "../../_shared/helpers.ts";

Deno.serve(async (req) => {
  const cors = handleCors(req);
  if (cors) return cors;
  if (req.method !== "GET") return json(405, { error: "method_not_allowed" });

  try {
    const db = createDb();
    const auth = await requireAdmin(req, db);
    if (auth instanceof Response) return auth;

    const url = new URL(req.url);
    const uid = url.searchParams.get("uid");
    let q = db.from("sessions")
      .select("token,device,created_at,last_seen_at,expires_at")
      .order("created_at", { ascending: false })
      .limit(100);
    if (uid) q = q.eq("uid", uid);
    const { data, error } = await q;
    if (error) return handleError(error);
    return json(200, (data || []).map((s: any) => ({
      token_id: s.token.slice(0, 8) + "…",
      device: s.device,
      created_at: s.created_at,
      last_seen_at: s.last_seen_at,
      expires_at: s.expires_at,
    })));
  } catch (e) {
    return handleError(e);
  }
});
```

- [ ] **Step 6: Deploy all five** (dashboard editor; each with the helper).

- [ ] **Step 7: Verify with the dashboard function tester** (as admin token from Task 4)

1. `list-accounts` → `200` array containing `u_admin` and both signup test accounts; non-admin user token → `403 {"error":"forbidden"}`.
2. `login-history?uid=u_admin` → rows with `success`/`ip`/`device`/`attempted_at`.
3. `issue-code {"email":"owner3@example.com","note":"v3"}` → `{code}` (format `XXXX-XXXX-XXXX`).
4. `ban {"uid":"<owner1's uid>","banned":true}` → `{success:true}`; then attempt `POST login` for that account → `403 {"error":"banned"}`. Also confirm all sessions rows for that uid were deleted (instant kill). Unban → login works again.
5. `list-sessions?uid=u_admin` → masked tokens + device + last_seen.
6. Banning self (`{"uid":"u_admin","banned":true}`) → `400 {"error":"cannot_ban_self"}`.

- [ ] **Step 8: Commit**

```bash
git add supabase/functions/admin/
git commit -m "Add admin edge functions (accounts, login history, atomic ban, issue-code, sessions)"
```

---

### Task 9: `/cleanup` retention endpoint (manual trigger)

**Files:**
- Create: `supabase/functions/cleanup/index.ts`
- Modify: `supabase/README.md`

**Interfaces:**
- Consumes: helpers.
- Produces: `POST /functions/v1/cleanup` → `{success:true}`; calls `cleanup_old_logs()` RPC (the weekly pg_cron already runs the same function — this endpoint is the manual/on-demand path).

- [ ] **Step 1: Write `supabase/functions/cleanup/index.ts`**

```ts
import { json, handleCors, createDb, handleError } from "../_shared/helpers.ts";

Deno.serve(async (req) => {
  const cors = handleCors(req);
  if (cors) return cors;
  if (req.method !== "POST") return json(405, { error: "method_not_allowed" });

  const db = createDb();
  const { error } = await db.rpc("cleanup_old_logs");
  if (error) return handleError(error);
  return json(200, { success: true });
});
```

- [ ] **Step 2: Deploy `/cleanup`**, then trigger it once from the dashboard tester or `curl -X POST`.

- [ ] **Step 3: Verify** — no error, and the cron job from Task 1 is scheduled (`select cron.jobid from cron.job where jobname='cleanup-old-logs';` still returns a row).

- [ ] **Step 4: Commit**

```bash
git add supabase/functions/cleanup/index.ts
git commit -m "Add cleanup endpoint for on-demand log retention"
```

---

### Task 10: End-to-end backend verification + README

**Files:**
- Modify: `supabase/README.md` (full deploy guide)
- Test: full curl sequence from a browser-free shell

**Interfaces:** Verifies every endpoint deployed in Tasks 3–9 as one pass.

- [ ] **Step 1: Write the complete `supabase/README.md`** documenting:
  - Prerequisite: create free Supabase project; record project ref.
  - Apply `schema.sql` in SQL editor.
  - For EACH function: create via dashboard editor (name + helper), set secret `ALLOWED_ORIGIN=https://kossaitaguine331.github.io`.
  - Function URLs table for all 10 endpoints.
  - GitHub secret setup (`SUPABASE_HEALTH_URL`, `SUPABASE_HEALTH_TOKEN`).
  - How to issue a code (SQL or admin endpoint) and how to ban.
  - Error code reference table (all `string` errors returned by the API).

- [ ] **Step 2: End-to-end curl pass**

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

Record each observed response; confirm they match the expectations from Tasks 4–8.

- [ ] **Step 3: Commit**

```bash
git add supabase/README.md
git commit -m "Add complete Supabase backend deploy guide"
```

---

## Self-Review Notes

- **Spec coverage:** Section 1 (architecture) ✓ Tasks 1–9; Section 1b items 1–8 ✓ (keepalive, rate limit, CORS, atomic redeem, retention cron + on-demand, IP-as-reported, atomic ban, service-key secrecy — the service key never appears in repo code; helpers read `SUPABASE_SERVICE_ROLE_KEY`/`SUPABASE_URL` from auto-injected env vars); Section 2 + 2b ✓ (all tables/indexes/trigger/cascade, crypto-random 10-char code via `crypto.getRandomValues`, admin role checked server-side in `requireAdmin`); Section 3 table ✓ all 12 endpoints (incl. `/cleanup`); Section 4 (migration) is handled by the frontend plan — this plan seeds only the admin and provides `issue-code`/`redeem` for the client re-register flow.
- **Type consistency:** `hashPassword(pw, salt)` signature matches the front-end scheme; `createDb()` used consistently; `requireAdmin` returns `Response | {account, token}`; `findSessionUser`/`sessionOk` share the `sessions.accounts` joined shape.
- **Placeholder scan:** Any `<project-ref>` in this plan is intentionally a dashboard-provided value — it cannot be known before the project is created; the README instructs filling it in.