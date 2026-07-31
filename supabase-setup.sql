-- Vestor production security migration.
-- Run the complete file in Supabase SQL Editor while signed in as project owner.
create extension if not exists pgcrypto;

create schema if not exists private;
revoke all on schema private from public, anon, authenticated;

create table if not exists private.vestor_config (
  singleton boolean primary key default true check (singleton),
  owner_email text not null,
  invite_secret uuid not null default gen_random_uuid()
);
insert into private.vestor_config (singleton, owner_email)
values (true, 'calabraaa@gmail.com')
on conflict (singleton) do update set owner_email = excluded.owner_email;

create table if not exists public.user_roles (
  user_id uuid primary key references auth.users(id) on delete cascade,
  role text not null check (role in ('owner','user')) default 'user',
  created_at timestamptz not null default now()
);
alter table public.user_roles enable row level security;
revoke all on public.user_roles from anon;
grant select on public.user_roles to authenticated;

-- Email is used only once to seed the owner's immutable UUID. Runtime
-- authorization below checks auth.uid(), never an editable e-mail claim.
insert into public.user_roles (user_id, role)
select id, 'owner' from auth.users
where lower(email) = 'calabraaa@gmail.com'
on conflict (user_id) do update set role = 'owner';

create or replace function private.has_role(required_role text)
returns boolean language sql stable security definer
set search_path = public, auth, pg_catalog
as $$ select exists (
  select 1 from public.user_roles
  where user_id = auth.uid() and role = required_role
) $$;
revoke all on function private.has_role(text) from public, anon, authenticated;

create or replace function public.get_my_role()
returns text language sql stable security definer
set search_path = public, auth, pg_catalog
as $$ select coalesce((select role from public.user_roles where user_id=auth.uid()), 'user') $$;
revoke all on function public.get_my_role() from public, anon;
grant execute on function public.get_my_role() to authenticated;

drop policy if exists "Users read their own role" on public.user_roles;
create policy "Users read their own role"
on public.user_roles for select to authenticated
using (user_id = auth.uid() or private.has_role('owner'));

create or replace function private.current_vestor_invite_code()
returns text language sql stable security definer
set search_path = private, extensions, pg_catalog
as $$
  select lpad(((('x' || substr(encode(digest(
    invite_secret::text || ':' || floor(extract(epoch from now()) / 1800)::text,
    'sha256'), 'hex'), 1, 15))::bit(60)::bigint % 100000000))::text, 8, '0')
  from private.vestor_config where singleton = true
$$;

create or replace function public.get_current_invite_code()
returns text language plpgsql stable security definer
set search_path = public, private, auth, pg_catalog
as $$
begin
  if auth.uid() is null or not private.has_role('owner') then
    raise exception 'Owner access required';
  end if;
  return private.current_vestor_invite_code();
end $$;
revoke all on function public.get_current_invite_code() from public, anon;
grant execute on function public.get_current_invite_code() to authenticated;

create or replace function private.validate_vestor_signup()
returns trigger language plpgsql security definer
set search_path = private, auth, pg_catalog
as $$
declare supplied_code text;
begin
  -- The first pre-existing owner is handled by the UUID seed above. Every new
  -- account, including attempts using the owner's address, requires an invite.
  supplied_code := regexp_replace(
    coalesce(new.raw_user_meta_data ->> 'invitation_code', ''),
    '[[:space:]]', '', 'g'
  );
  if supplied_code = '' or supplied_code <> private.current_vestor_invite_code() then
    raise exception 'Invalid or expired invitation code';
  end if;
  return new;
end $$;
drop trigger if exists vestor_validate_signup on auth.users;
create trigger vestor_validate_signup before insert on auth.users
for each row execute function private.validate_vestor_signup();

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  email text not null,
  display_name text not null check (char_length(display_name) between 1 and 80),
  created_at timestamptz not null default now()
);
alter table public.profiles enable row level security;
revoke all on public.profiles from anon;
grant select on public.profiles to authenticated;

create or replace function private.create_vestor_profile()
returns trigger language plpgsql security definer
set search_path = public, pg_catalog
as $$
begin
  insert into public.profiles (id,email,display_name,created_at)
  values (
    new.id, lower(new.email),
    left(coalesce(nullif(trim(new.raw_user_meta_data ->> 'display_name'),''),
      split_part(new.email,'@',1)),80),
    new.created_at
  ) on conflict (id) do nothing;
  insert into public.user_roles(user_id,role) values(new.id,'user')
  on conflict (user_id) do nothing;
  return new;
end $$;
drop trigger if exists vestor_create_profile on auth.users;
create trigger vestor_create_profile after insert on auth.users
for each row execute function private.create_vestor_profile();

drop policy if exists "Users see their profile; owner sees all" on public.profiles;
create policy "Users see their profile; owner sees all"
on public.profiles for select to authenticated
using (id = auth.uid() or private.has_role('owner'));

create table if not exists public.portfolio_positions (
  user_id uuid not null references auth.users(id) on delete cascade,
  client_id text not null check (char_length(client_id) between 1 and 160),
  payload jsonb not null check (jsonb_typeof(payload) = 'object'),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  primary key (user_id, client_id)
);
alter table public.portfolio_positions enable row level security;
revoke all on public.portfolio_positions from anon;
grant select, insert, update, delete on public.portfolio_positions to authenticated;
drop policy if exists "Portfolio is private to its owner" on public.portfolio_positions;
create policy "Portfolio is private to its owner"
on public.portfolio_positions for all to authenticated
using (user_id = auth.uid()) with check (user_id = auth.uid());

create table if not exists public.security_events (
  id bigint generated always as identity primary key,
  user_id uuid references auth.users(id) on delete set null,
  event_type text not null check (char_length(event_type) between 1 and 80),
  details jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);
alter table public.security_events enable row level security;
revoke all on public.security_events from anon, authenticated;

create or replace function public.log_security_event(kind text, event_details jsonb default '{}'::jsonb)
returns void language plpgsql security definer
set search_path = public, auth, pg_catalog
as $$
begin
  if auth.uid() is null then return; end if;
  if kind not in ('sign_in','sign_out','portfolio_migrated','portfolio_sync_failed') then
    raise exception 'Unsupported security event';
  end if;
  insert into public.security_events(user_id,event_type,details)
  values(auth.uid(), kind, coalesce(event_details,'{}'::jsonb));
end $$;
revoke all on function public.log_security_event(text,jsonb) from public, anon;
grant execute on function public.log_security_event(text,jsonb) to authenticated;

-- Helpful indexes for RLS and owner administration.
create index if not exists profiles_created_at_idx on public.profiles(created_at);
create index if not exists portfolio_positions_updated_idx
on public.portfolio_positions(user_id, updated_at desc);
