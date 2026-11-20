-- =========================================================================
-- KAT'S SPECIAL PRACTICE TURF - SUPABASE GATEKEEPER SCHEMA & RPC FUNCTIONS
-- =========================================================================
-- Instructions:
-- 1. Create a free project at https://supabase.com
-- 2. In your Supabase dashboard, click "SQL Editor" on the left sidebar
-- 3. Click "New query", paste this entire script, and click "Run"
-- 4. Copy your "Project URL" and "anon public key" from Project Settings -> API
-- =========================================================================

-- 1. Create Turf Accounts Table
create table if not exists public.turf_accounts (
    id uuid primary key default gen_random_uuid(),
    username text unique not null,
    password_hash text not null,
    role text not null default 'user' check (role in ('master', 'user')),
    status text not null default 'active' check (status in ('active', 'banned')),
    notes text default '',
    created_at timestamptz default now(),
    expires_at timestamptz,
    last_login_at timestamptz
);

-- Enable Row Level Security (RLS)
alter table public.turf_accounts enable row level security;

-- Block direct SELECT/INSERT/UPDATE/DELETE from public anon key
-- All actions MUST go through the security-definer RPC functions below.
drop policy if exists "Deny all public direct access" on public.turf_accounts;
create policy "Deny all public direct access" on public.turf_accounts
    for all to public using (false);

-- =========================================================================
-- 2. Insert Default Master Account ('kat')
-- Default password: KatMaster2026! (change this in the Master Console anytime)
-- Hash generated via SHA-256('kats_turf_salt_2026:KatMaster2026!:kats_turf_salt_2026')
-- =========================================================================
insert into public.turf_accounts (username, password_hash, role, status, notes)
values (
    'kat',
    'b5f1638b00f8fc7c915a3dd072409d921919865cb0ed204acb55abccdd01de8d',
    'master',
    'active',
    'Master Administrator Account'
)
on conflict (username) do update set
    role = 'master',
    status = 'active';

-- =========================================================================
-- 3. RPC: Login Function
-- Validates credentials, checks active/banned status & expiration.
-- Returns safe user record (no password hashes).
-- =========================================================================
create or replace function public.turf_login(
    p_username text,
    p_password_hash text
)
returns json
language plpgsql
security definer
as $$
declare
    v_account record;
begin
    -- Case-insensitive username lookup
    select * into v_account
    from public.turf_accounts
    where lower(username) = lower(trim(p_username))
      and password_hash = p_password_hash;

    if not found then
        return json_build_object(
            'success', false,
            'error', 'Invalid username or password'
        );
    end if;

    if v_account.status = 'banned' then
        return json_build_object(
            'success', false,
            'error', 'This account has been revoked by Master Kat.'
        );
    end if;

    if v_account.expires_at is not null and v_account.expires_at < now() then
        return json_build_object(
            'success', false,
            'error', 'Access pass has expired. Contact Kat for renewal.'
        );
    end if;

    -- Update last login timestamp
    update public.turf_accounts
    set last_login_at = now()
    where id = v_account.id;

    return json_build_object(
        'success', true,
        'user', json_build_object(
            'id', v_account.id,
            'username', v_account.username,
            'role', v_account.role,
            'status', v_account.status,
            'notes', v_account.notes,
            'created_at', v_account.created_at,
            'expires_at', v_account.expires_at,
            'last_login_at', now()
        )
    );
end;
$$;

-- =========================================================================
-- 4. RPC: Admin List Users
-- Only succeeds if caller provides valid master credentials.
-- =========================================================================
create or replace function public.turf_admin_list_users(
    p_admin_username text,
    p_admin_password_hash text
)
returns json
language plpgsql
security definer
as $$
declare
    v_is_master boolean;
    v_users json;
begin
    select exists (
        select 1 from public.turf_accounts
        where lower(username) = lower(trim(p_admin_username))
          and password_hash = p_admin_password_hash
          and role = 'master'
          and status = 'active'
    ) into v_is_master;

    if not v_is_master then
        return json_build_object(
            'success', false,
            'error', 'Unauthorized: Master credentials required.'
        );
    end if;

    select json_agg(
        json_build_object(
            'id', id,
            'username', username,
            'role', role,
            'status', status,
            'notes', notes,
            'created_at', created_at,
            'expires_at', expires_at,
            'last_login_at', last_login_at
        ) order by created_at desc
    ) into v_users
    from public.turf_accounts;

    return json_build_object(
        'success', true,
        'users', coalesce(v_users, '[]'::json)
    );
end;
$$;

-- =========================================================================
-- 5. RPC: Admin Create User
-- Creates a new dynamic login (user or secondary master).
-- =========================================================================
create or replace function public.turf_admin_create_user(
    p_admin_username text,
    p_admin_password_hash text,
    p_new_username text,
    p_new_password_hash text,
    p_role text default 'user',
    p_expires_at timestamptz default null,
    p_notes text default ''
)
returns json
language plpgsql
security definer
as $$
declare
    v_is_master boolean;
    v_new_id uuid;
    v_clean_username text;
begin
    -- Verify master caller
    select exists (
        select 1 from public.turf_accounts
        where lower(username) = lower(trim(p_admin_username))
          and password_hash = p_admin_password_hash
          and role = 'master'
          and status = 'active'
    ) into v_is_master;

    if not v_is_master then
        return json_build_object(
            'success', false,
            'error', 'Unauthorized: Master credentials required.'
        );
    end if;

    v_clean_username := lower(trim(p_new_username));

    if length(v_clean_username) < 3 then
        return json_build_object(
            'success', false,
            'error', 'Username must be at least 3 characters.'
        );
    end if;

    -- Check if username already exists
    if exists (select 1 from public.turf_accounts where lower(username) = v_clean_username) then
        return json_build_object(
            'success', false,
            'error', 'Username already exists.'
        );
    end if;

    insert into public.turf_accounts (
        username,
        password_hash,
        role,
        status,
        expires_at,
        notes
    ) values (
        v_clean_username,
        p_new_password_hash,
        coalesce(p_role, 'user'),
        'active',
        p_expires_at,
        coalesce(p_notes, '')
    ) returning id into v_new_id;

    return json_build_object(
        'success', true,
        'user_id', v_new_id,
        'username', v_clean_username
    );
end;
$$;

-- =========================================================================
-- 6. RPC: Admin Toggle Status (Ban / Unban / Revoke)
-- =========================================================================
create or replace function public.turf_admin_toggle_status(
    p_admin_username text,
    p_admin_password_hash text,
    p_user_id uuid,
    p_new_status text
)
returns json
language plpgsql
security definer
as $$
declare
    v_is_master boolean;
    v_target_role text;
begin
    select exists (
        select 1 from public.turf_accounts
        where lower(username) = lower(trim(p_admin_username))
          and password_hash = p_admin_password_hash
          and role = 'master'
          and status = 'active'
    ) into v_is_master;

    if not v_is_master then
        return json_build_object('success', false, 'error', 'Unauthorized: Master credentials required.');
    end if;

    -- Prevent banning self/master if sole master
    select role into v_target_role from public.turf_accounts where id = p_user_id;
    if v_target_role = 'master' and p_new_status = 'banned' then
        return json_build_object('success', false, 'error', 'Cannot ban a Master account.');
    end if;

    update public.turf_accounts
    set status = p_new_status
    where id = p_user_id;

    return json_build_object('success', true, 'status', p_new_status);
end;
$$;

-- =========================================================================
-- 7. RPC: Admin Reset Password
-- =========================================================================
create or replace function public.turf_admin_reset_password(
    p_admin_username text,
    p_admin_password_hash text,
    p_user_id uuid,
    p_new_password_hash text
)
returns json
language plpgsql
security definer
as $$
declare
    v_is_master boolean;
begin
    select exists (
        select 1 from public.turf_accounts
        where lower(username) = lower(trim(p_admin_username))
          and password_hash = p_admin_password_hash
          and role = 'master'
          and status = 'active'
    ) into v_is_master;

    if not v_is_master then
        return json_build_object('success', false, 'error', 'Unauthorized: Master credentials required.');
    end if;

    update public.turf_accounts
    set password_hash = p_new_password_hash
    where id = p_user_id;

    return json_build_object('success', true);
end;
$$;

-- =========================================================================
-- 8. RPC: Admin Delete User
-- =========================================================================
create or replace function public.turf_admin_delete_user(
    p_admin_username text,
    p_admin_password_hash text,
    p_user_id uuid
)
returns json
language plpgsql
security definer
as $$
declare
    v_is_master boolean;
    v_target_role text;
begin
    select exists (
        select 1 from public.turf_accounts
        where lower(username) = lower(trim(p_admin_username))
          and password_hash = p_admin_password_hash
          and role = 'master'
          and status = 'active'
    ) into v_is_master;

    if not v_is_master then
        return json_build_object('success', false, 'error', 'Unauthorized: Master credentials required.');
    end if;

    select role into v_target_role from public.turf_accounts where id = p_user_id;
    if v_target_role = 'master' then
        return json_build_object('success', false, 'error', 'Cannot delete a Master account.');
    end if;

    delete from public.turf_accounts where id = p_user_id;

    return json_build_object('success', true);
end;
$$;
