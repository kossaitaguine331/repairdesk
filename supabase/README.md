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
