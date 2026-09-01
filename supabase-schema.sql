-- RepairDesk SaaS - Supabase schema
-- Run these statements in the Supabase SQL editor:
-- Dashboard -> SQL -> New query -> paste -> Run.

create table if not exists public.tenants (
  id text primary key,
  user_id uuid not null default auth.uid(),
  name text not null default '',
  business_type text not null default 'phone_repair',
  settings jsonb not null default '{}',
  created_at bigint,
  updated_at bigint
);

create table if not exists public.templates (
  id text primary key,
  user_id uuid not null default auth.uid(),
  tenant_id text not null,
  name text not null default '',
  format text not null default 'receipt_80',
  is_default boolean not null default false,
  field_defs jsonb not null default '[]',
  elements jsonb not null default '[]',
  styles jsonb not null default '{}',
  created_at bigint,
  updated_at bigint
);

create table if not exists public.receipts (
  id text primary key,
  user_id uuid not null default auth.uid(),
  tenant_id text not null,
  template_id text,
  fields jsonb not null default '{}',
  format text not null default 'receipt_80',
  repaired boolean not null default false,
  paid boolean not null default false,
  created_at bigint,
  updated_at bigint
);

create index if not exists idx_tenants_user on public.tenants(user_id);
create index if not exists idx_templates_user on public.templates(user_id);
create index if not exists idx_receipts_user on public.receipts(user_id);
create index if not exists idx_templates_tenant on public.templates(tenant_id);
create index if not exists idx_receipts_tenant on public.receipts(tenant_id);

alter table public.tenants enable row level security;
alter table public.templates enable row level security;
alter table public.receipts enable row level security;

-- Policies: users only see / modify their own rows
create policy tenants_select on public.tenants for select using (auth.uid() = user_id);
create policy tenants_insert on public.tenants for insert with check (auth.uid() = user_id);
create policy tenants_update on public.tenants for update using (auth.uid() = user_id) with check (auth.uid() = user_id);
create policy tenants_delete on public.tenants for delete using (auth.uid() = user_id);

create policy templates_select on public.templates for select using (auth.uid() = user_id);
create policy templates_insert on public.templates for insert with check (auth.uid() = user_id);
create policy templates_update on public.templates for update using (auth.uid() = user_id) with check (auth.uid() = user_id);
create policy templates_delete on public.templates for delete using (auth.uid() = user_id);

create policy receipts_select on public.receipts for select using (auth.uid() = user_id);
create policy receipts_insert on public.receipts for insert with check (auth.uid() = user_id);
create policy receipts_update on public.receipts for update using (auth.uid() = user_id) with check (auth.uid() = user_id);
create policy receipts_delete on public.receipts for delete using (auth.uid() = user_id);