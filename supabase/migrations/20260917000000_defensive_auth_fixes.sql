begin;

set local lock_timeout = '10s';

lock table public.access_codes in share row exclusive mode;

with ranked as (
  select id, row_number() over (partition by email order by issued_at, id) as position
    from public.access_codes
   where active = true and used = false
)
update public.access_codes as codes
   set active = false
  from ranked
 where codes.id = ranked.id and ranked.position > 1;

create unique index if not exists access_codes_one_active_unused_email_idx
  on public.access_codes (email) where active = true and used = false;

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

create or replace function public.cleanup_old_logs()
returns void language plpgsql security definer set search_path = public as $$
begin
  delete from public.login_logs where attempted_at < now() - interval '90 days';
  delete from public.sessions where expires_at < now();
end;
$$;

create or replace function public.signup_with_access_code(
  p_email text, p_code text, p_uid text, p_name text,
  p_salt text, p_hash text, p_token text, p_device text
)
returns void language plpgsql security definer set search_path = public as $$
declare
  v_email text := lower(trim(p_email));
begin
  perform pg_advisory_xact_lock(hashtextextended(v_email, 0));
  if exists (select 1 from public.accounts where email = v_email) then
    raise exception 'auth_exists';
  end if;

  perform 1 from public.redeem_access_code(v_email, p_code);
  if not found then
    raise exception 'access_code_invalid';
  end if;

  insert into public.accounts (uid, email, name, salt, hash, role, approved, approved_at)
  values (p_uid, v_email, p_name, p_salt, p_hash, 'user', true, now())
  on conflict (email) do nothing;
  if not found then
    raise exception 'auth_exists';
  end if;

  insert into public.sessions (token, uid, expires_at, device)
  values (p_token, p_uid, now() + interval '30 days', p_device);
end;
$$;

create or replace function public.reset_with_access_code(
  p_email text, p_code text, p_salt text, p_hash text
)
returns text language plpgsql security definer set search_path = public as $$
declare
  v_email text := lower(trim(p_email));
  v_uid text;
begin
  perform pg_advisory_xact_lock(hashtextextended(v_email, 0));
  select uid into v_uid from public.accounts where email = v_email for update;
  if not found then
    raise exception 'reset_no_account';
  end if;

  perform 1 from public.redeem_access_code(v_email, p_code);
  if not found then
    raise exception 'reset_code_invalid';
  end if;

  update public.accounts set salt = p_salt, hash = p_hash, approved = true where uid = v_uid;
  delete from public.sessions where uid = v_uid;
  return v_uid;
end;
$$;

create or replace function public.issue_access_code(p_email text, p_code text, p_note text)
returns jsonb language plpgsql security definer set search_path = public as $$
declare
  v_email text := lower(trim(p_email));
  v_code text;
begin
  perform pg_advisory_xact_lock(hashtextextended(v_email, 0));
  loop
    select code into v_code from public.access_codes
     where email = v_email and active = true and used = false
     for update;
    if found then
      return jsonb_build_object('code', v_code, 'reused', true);
    end if;

    insert into public.access_codes (email, code, note)
    values (v_email, p_code, p_note)
    on conflict (email) where active = true and used = false do nothing
    returning code into v_code;
    if found then
      return jsonb_build_object('code', v_code, 'reused', false);
    end if;
  end loop;
end;
$$;

revoke execute on function public.redeem_access_code(text, text) from PUBLIC, anon, authenticated;
grant execute on function public.redeem_access_code(text, text) to service_role;
revoke execute on function public.ban_user(text) from PUBLIC, anon, authenticated;
grant execute on function public.ban_user(text) to service_role;
revoke execute on function public.unban_user(text) from PUBLIC, anon, authenticated;
grant execute on function public.unban_user(text) to service_role;
revoke execute on function public.cleanup_old_logs() from PUBLIC, anon, authenticated;
grant execute on function public.cleanup_old_logs() to service_role;
revoke execute on function public.signup_with_access_code(text, text, text, text, text, text, text, text) from PUBLIC, anon, authenticated;
grant execute on function public.signup_with_access_code(text, text, text, text, text, text, text, text) to service_role;
revoke execute on function public.reset_with_access_code(text, text, text, text) from PUBLIC, anon, authenticated;
grant execute on function public.reset_with_access_code(text, text, text, text) to service_role;
revoke execute on function public.issue_access_code(text, text, text) from PUBLIC, anon, authenticated;
grant execute on function public.issue_access_code(text, text, text) to service_role;

do $$
begin
  if exists (select 1 from pg_extension where extname = 'pg_cron') then
    perform cron.schedule('cleanup-old-logs', '0 3 * * 1', 'select public.cleanup_old_logs();');
  else
    raise notice 'pg_cron is not enabled; enable it and rerun this script to schedule cleanup-old-logs.';
  end if;
end;
$$;

commit;
