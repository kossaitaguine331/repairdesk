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
)
on conflict do nothing;

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
