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
