-- COSMIC CHAT: Supabase foundation (run once in Supabase SQL Editor)
-- Includes profiles, conversations, members, messages, receipts, and private media storage.
-- RLS is enabled on every public table. Do not disable it.

create extension if not exists pgcrypto;

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  username text not null unique check (username ~ '^[a-z][a-z0-9_]{2,19}$'),
  display_name text not null default 'Cosmic User' check (char_length(display_name) between 1 and 80),
  avatar_url text,
  bio text not null default '' check (char_length(bio) <= 300),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create or replace function public.set_updated_at()
returns trigger language plpgsql as $$
begin new.updated_at = now(); return new; end;
$$;

drop trigger if exists profiles_set_updated_at on public.profiles;
create trigger profiles_set_updated_at before update on public.profiles
for each row execute function public.set_updated_at();

create or replace function public.handle_new_cosmic_user()
returns trigger
language plpgsql
security definer
set search_path = public, auth
as $$
declare
  requested_username text;
  safe_username text;
  requested_name text;
begin
  requested_username := lower(coalesce(new.raw_user_meta_data->>'username', ''));
  requested_name := left(coalesce(nullif(trim(new.raw_user_meta_data->>'full_name'), ''), split_part(new.email, '@', 1), 'Cosmic User'), 80);
  if requested_username !~ '^[a-z][a-z0-9_]{2,19}$' then
    safe_username := 'user_' || substr(replace(new.id::text, '-', ''), 1, 12);
  else
    safe_username := requested_username;
  end if;
  insert into public.profiles (id, username, display_name)
  values (new.id, safe_username, requested_name)
  on conflict (id) do nothing;
  return new;
end;
$$;

drop trigger if exists on_auth_user_created_cosmic on auth.users;
create trigger on_auth_user_created_cosmic
after insert on auth.users
for each row execute function public.handle_new_cosmic_user();

create table if not exists public.conversations (
  id uuid primary key default gen_random_uuid(),
  kind text not null default 'direct' check (kind in ('direct','group','community')),
  title text check (title is null or char_length(title) between 1 and 100),
  created_by uuid references auth.users(id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.conversation_members (
  conversation_id uuid not null references public.conversations(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  role text not null default 'member' check (role in ('owner','admin','moderator','member')),
  joined_at timestamptz not null default now(),
  last_read_at timestamptz,
  primary key (conversation_id, user_id)
);
create index if not exists conversation_members_user_idx on public.conversation_members(user_id, joined_at desc);

create table if not exists public.messages (
  id uuid primary key default gen_random_uuid(),
  conversation_id uuid not null references public.conversations(id) on delete cascade,
  sender_id uuid references auth.users(id) on delete set null,
  body text not null default '' check (char_length(body) <= 10000),
  message_type text not null default 'text' check (message_type in ('text','image','video','document','audio','system')),
  attachment_path text,
  reply_to uuid references public.messages(id) on delete set null,
  created_at timestamptz not null default now(),
  edited_at timestamptz,
  deleted_at timestamptz,
  constraint messages_body_or_attachment check (length(trim(body)) > 0 or attachment_path is not null or message_type = 'system')
);
create index if not exists messages_conversation_created_idx on public.messages(conversation_id, created_at desc);

create table if not exists public.message_receipts (
  message_id uuid not null references public.messages(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  delivered_at timestamptz,
  read_at timestamptz,
  primary key (message_id, user_id)
);

-- Helper used by RLS policies. SECURITY DEFINER avoids recursive RLS evaluation.
create or replace function public.is_conversation_member(target_conversation uuid)
returns boolean
language sql stable security definer
set search_path = public
as $$
  select exists (
    select 1 from public.conversation_members cm
    where cm.conversation_id = target_conversation and cm.user_id = auth.uid()
  );
$$;

create or replace function public.is_conversation_creator(target_conversation uuid)
returns boolean
language sql stable security definer
set search_path = public
as $$
  select exists (
    select 1 from public.conversations c
    where c.id = target_conversation and c.created_by = auth.uid()
  );
$$;
revoke all on function public.is_conversation_member(uuid) from public;
revoke all on function public.is_conversation_creator(uuid) from public;
grant execute on function public.is_conversation_member(uuid) to authenticated;
grant execute on function public.is_conversation_creator(uuid) to authenticated;

alter table public.profiles enable row level security;
alter table public.conversations enable row level security;
alter table public.conversation_members enable row level security;
alter table public.messages enable row level security;
alter table public.message_receipts enable row level security;

-- Profiles are discoverable to signed-in users; each user may edit only their own profile.
drop policy if exists "profiles readable by authenticated" on public.profiles;
create policy "profiles readable by authenticated" on public.profiles
for select to authenticated using (true);
drop policy if exists "profile owner updates own profile" on public.profiles;
create policy "profile owner updates own profile" on public.profiles
for update to authenticated using (id = auth.uid()) with check (id = auth.uid());

-- Conversation records and membership lists are visible only to members.
drop policy if exists "members read conversations" on public.conversations;
create policy "members read conversations" on public.conversations
for select to authenticated using (public.is_conversation_member(id));
drop policy if exists "creator creates conversation" on public.conversations;
create policy "creator creates conversation" on public.conversations
for insert to authenticated with check (created_by = auth.uid());
drop policy if exists "conversation owner updates conversation" on public.conversations;
create policy "conversation owner updates conversation" on public.conversations
for update to authenticated using (created_by = auth.uid()) with check (created_by = auth.uid());

drop policy if exists "members read memberships" on public.conversation_members;
create policy "members read memberships" on public.conversation_members
for select to authenticated using (public.is_conversation_member(conversation_id));
-- Membership creation is intentionally restricted to the creator of a newly created conversation.
drop policy if exists "creator adds initial members" on public.conversation_members;
create policy "creator adds initial members" on public.conversation_members
for insert to authenticated with check (public.is_conversation_creator(conversation_id));
drop policy if exists "users update own read position" on public.conversation_members;
create policy "users update own read position" on public.conversation_members
for update to authenticated using (user_id = auth.uid()) with check (user_id = auth.uid());

-- Messages: only members can read; sender must be the authenticated user and a member.
drop policy if exists "members read messages" on public.messages;
create policy "members read messages" on public.messages
for select to authenticated using (public.is_conversation_member(conversation_id));
drop policy if exists "members send own messages" on public.messages;
create policy "members send own messages" on public.messages
for insert to authenticated with check (sender_id = auth.uid() and public.is_conversation_member(conversation_id));
drop policy if exists "sender edits own messages" on public.messages;
create policy "sender edits own messages" on public.messages
for update to authenticated using (sender_id = auth.uid() and public.is_conversation_member(conversation_id))
with check (sender_id = auth.uid() and public.is_conversation_member(conversation_id));
drop policy if exists "sender deletes own messages" on public.messages;
create policy "sender deletes own messages" on public.messages
for delete to authenticated using (sender_id = auth.uid() and public.is_conversation_member(conversation_id));

-- A user may manage only their own receipt row, and only for a conversation they belong to.
drop policy if exists "members read receipts" on public.message_receipts;
create policy "members read receipts" on public.message_receipts
for select to authenticated using (exists (
  select 1 from public.messages m
  where m.id = message_id and public.is_conversation_member(m.conversation_id)
));
drop policy if exists "users insert own receipts" on public.message_receipts;
create policy "users insert own receipts" on public.message_receipts
for insert to authenticated with check (user_id = auth.uid() and exists (
  select 1 from public.messages m where m.id = message_id and public.is_conversation_member(m.conversation_id)
));
drop policy if exists "users update own receipts" on public.message_receipts;
create policy "users update own receipts" on public.message_receipts
for update to authenticated using (user_id = auth.uid()) with check (user_id = auth.uid());

-- Private storage bucket. Object path convention: <conversation-uuid>/<uploader-uuid>/<filename>
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('cosmic-chat-media', 'cosmic-chat-media', false, 52428800,
  array['image/jpeg','image/png','image/webp','image/gif','video/mp4','video/webm','application/pdf','text/plain'])
on conflict (id) do update set public = false, file_size_limit = excluded.file_size_limit,
  allowed_mime_types = excluded.allowed_mime_types;

drop policy if exists "conversation members read media" on storage.objects;
create policy "conversation members read media" on storage.objects
for select to authenticated using (
  bucket_id = 'cosmic-chat-media'
  and public.is_conversation_member(split_part(name, '/', 1)::uuid)
);
drop policy if exists "members upload own media" on storage.objects;
create policy "members upload own media" on storage.objects
for insert to authenticated with check (
  bucket_id = 'cosmic-chat-media'
  and split_part(name, '/', 2) = auth.uid()::text
  and public.is_conversation_member(split_part(name, '/', 1)::uuid)
);
drop policy if exists "owners delete own uploaded media" on storage.objects;
create policy "owners delete own uploaded media" on storage.objects
for delete to authenticated using (
  bucket_id = 'cosmic-chat-media'
  and split_part(name, '/', 2) = auth.uid()::text
  and public.is_conversation_member(split_part(name, '/', 1)::uuid)
);

-- Realtime: add only the durable message table. Presence/typing should use ephemeral channels.
do $$
begin
  if not exists (
    select 1 from pg_publication_tables
    where pubname = 'supabase_realtime' and schemaname = 'public' and tablename = 'messages'
  ) then
    alter publication supabase_realtime add table public.messages;
  end if;
end $$;

-- Important: this foundation intentionally does not grant arbitrary membership changes.
-- Next integration step will add a server-validated create-DM/group RPC and wire message UI.