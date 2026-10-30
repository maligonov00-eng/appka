-- FAMILY initial schema. Run in Supabase SQL editor or with Supabase CLI.
create extension if not exists pgcrypto;

create table public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  display_name text not null default '',
  nickname text unique,
  avatar_url text,
  status text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create table public.families (
  id uuid primary key default gen_random_uuid(),
  name text not null default 'Моя семья',
  created_by uuid not null references auth.users(id),
  created_at timestamptz not null default now()
);
create table public.family_members (
  family_id uuid not null references public.families(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  role text not null default 'member' check (role in ('owner','admin','member')),
  joined_at timestamptz not null default now(),
  primary key (family_id,user_id)
);
create table public.conversations (
  id uuid primary key default gen_random_uuid(),
  family_id uuid not null references public.families(id) on delete cascade,
  title text,
  kind text not null default 'direct' check (kind in ('direct','group')),
  avatar_url text,
  created_by uuid not null references auth.users(id),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create table public.conversation_members (
  conversation_id uuid not null references public.conversations(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  joined_at timestamptz not null default now(),
  last_read_at timestamptz,
  muted boolean not null default false,
  primary key (conversation_id,user_id)
);
create table public.messages (
  id uuid primary key default gen_random_uuid(),
  conversation_id uuid not null references public.conversations(id) on delete cascade,
  sender_id uuid not null references auth.users(id),
  body text not null default '',
  reply_to uuid references public.messages(id) on delete set null,
  edited_at timestamptz,
  deleted_at timestamptz,
  created_at timestamptz not null default now(),
  constraint message_body_or_attachment check (length(body) <= 10000)
);
create table public.message_reactions (
  message_id uuid not null references public.messages(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  emoji text not null check (length(emoji) <= 16),
  created_at timestamptz not null default now(),
  primary key (message_id,user_id,emoji)
);
create table public.attachments (
  id uuid primary key default gen_random_uuid(),
  message_id uuid not null references public.messages(id) on delete cascade,
  bucket text not null default 'family-media',
  object_path text not null unique,
  mime_type text not null,
  size_bytes bigint not null check (size_bytes >= 0),
  width integer,
  height integer,
  duration_seconds numeric(8,2),
  created_at timestamptz not null default now()
);
create table public.read_receipts (
  message_id uuid not null references public.messages(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  read_at timestamptz not null default now(),
  primary key(message_id,user_id)
);
create table public.invitations (
  id uuid primary key default gen_random_uuid(),
  family_id uuid not null references public.families(id) on delete cascade,
  created_by uuid not null references auth.users(id),
  token_hash text not null unique,
  email text,
  role text not null default 'member' check (role in ('admin','member')),
  expires_at timestamptz not null default now() + interval '7 days',
  accepted_by uuid references auth.users(id),
  accepted_at timestamptz,
  created_at timestamptz not null default now()
);
create table public.notifications (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  kind text not null,
  payload jsonb not null default '{}',
  read_at timestamptz,
  created_at timestamptz not null default now()
);

-- Invitation tokens are random, shown once to the inviter, and stored as SHA-256 hashes.
create or replace function public.create_family_invite(invite_family uuid, invite_email text default null)
returns text language plpgsql security definer set search_path=public,extensions
as $$
declare raw_token text; member_role text;
begin
  select role into member_role from public.family_members where family_id=invite_family and user_id=auth.uid();
  if coalesce(member_role,'') not in ('owner','admin') then raise exception 'Only family owners and admins can invite members'; end if;
  raw_token := encode(gen_random_bytes(24),'hex');
  insert into public.invitations(family_id,created_by,token_hash,email)
  values(invite_family,auth.uid(),encode(digest(raw_token,'sha256'),'hex'),nullif(lower(trim(invite_email)),''));
  return raw_token;
end;
$$;

create or replace function public.accept_family_invite(invite_token text)
returns uuid language plpgsql security definer set search_path=public,extensions
as $$
declare inv public.invitations%rowtype; auth_email text; solo_family uuid;
begin
  if auth.uid() is null then raise exception 'Sign in before accepting an invitation'; end if;
  select email into auth_email from auth.users where id=auth.uid();
  select * into inv from public.invitations
  where token_hash=encode(digest(invite_token,'sha256'),'hex')
    and accepted_at is null and expires_at>now()
  for update;
  if not found then raise exception 'Invitation is invalid, expired, or already used'; end if;
  if inv.email is not null and lower(inv.email)<>lower(coalesce(auth_email,'')) then raise exception 'This invitation was issued for another email address'; end if;
  insert into public.family_members(family_id,user_id,role) values(inv.family_id,auth.uid(),inv.role)
  on conflict(family_id,user_id) do nothing;
  insert into public.conversation_members(conversation_id,user_id)
  select c.id,auth.uid() from public.conversations c where c.family_id=inv.family_id and c.kind='group'
  on conflict(conversation_id,user_id) do nothing;
  update public.invitations set accepted_by=auth.uid(),accepted_at=now() where id=inv.id;
  select id into solo_family from public.families f where f.created_by=auth.uid()
    and not exists(select 1 from public.conversations c where c.family_id=f.id)
    and (select count(*) from public.family_members fm where fm.family_id=f.id)=1
  order by f.created_at limit 1;
  if solo_family is not null and solo_family<>inv.family_id then
    delete from public.families where id=solo_family;
  end if;
  return inv.family_id;
end;
$$;
create or replace function public.touch_conversation_updated_at()
returns trigger language plpgsql security definer set search_path=public
as $$ begin update public.conversations set updated_at=new.created_at where id=new.conversation_id; return new; end $$;
create trigger message_touches_conversation after insert on public.messages for each row execute procedure public.touch_conversation_updated_at();
revoke all on function public.create_family_invite(uuid,text) from public;
revoke all on function public.accept_family_invite(text) from public;
grant execute on function public.create_family_invite(uuid,text) to authenticated;
grant execute on function public.accept_family_invite(text) to authenticated;

create index conversations_family_updated_idx on public.conversations(family_id,updated_at desc);
create index conversation_members_user_idx on public.conversation_members(user_id,conversation_id);
create index messages_conversation_created_idx on public.messages(conversation_id,created_at desc);
create index messages_sender_idx on public.messages(sender_id);
create index attachments_message_idx on public.attachments(message_id);
create index notifications_user_created_idx on public.notifications(user_id,created_at desc);
create index invitations_family_idx on public.invitations(family_id,expires_at);

create or replace function public.is_family_member(target_family uuid)
returns boolean language sql stable security definer set search_path=public
as $$ select exists(select 1 from public.family_members where family_id=target_family and user_id=auth.uid()) $$;
create or replace function public.is_conversation_member(target_conversation uuid)
returns boolean language sql stable security definer set search_path=public
as $$ select exists(select 1 from public.conversation_members where conversation_id=target_conversation and user_id=auth.uid()) $$;
revoke all on function public.is_family_member(uuid) from public;
revoke all on function public.is_conversation_member(uuid) from public;
grant execute on function public.is_family_member(uuid) to authenticated;
grant execute on function public.is_conversation_member(uuid) to authenticated;

create or replace function public.handle_new_user()
returns trigger language plpgsql security definer set search_path=public
as $$
declare new_family uuid;
begin
  insert into public.profiles(id,display_name) values(new.id,coalesce(new.raw_user_meta_data->>'display_name',split_part(new.email,'@',1)));
  insert into public.families(name,created_by) values(coalesce(new.raw_user_meta_data->>'family_name','Моя семья'),new.id) returning id into new_family;
  insert into public.family_members(family_id,user_id,role) values(new_family,new.id,'owner');
  return new;
end;
$$;
create trigger on_auth_user_created after insert on auth.users for each row execute procedure public.handle_new_user();

alter table public.profiles enable row level security;
alter table public.families enable row level security;
alter table public.family_members enable row level security;
alter table public.conversations enable row level security;
alter table public.conversation_members enable row level security;
alter table public.messages enable row level security;
alter table public.message_reactions enable row level security;
alter table public.attachments enable row level security;
alter table public.read_receipts enable row level security;
alter table public.invitations enable row level security;
alter table public.notifications enable row level security;

create policy "profiles self or family" on public.profiles for select to authenticated using (id=auth.uid() or exists(select 1 from public.family_members mine join public.family_members theirs using(family_id) where mine.user_id=auth.uid() and theirs.user_id=profiles.id));
create policy "profile update self" on public.profiles for update to authenticated using (id=auth.uid()) with check (id=auth.uid());
create policy "family visible to members" on public.families for select to authenticated using (public.is_family_member(id));
create policy "family member list" on public.family_members for select to authenticated using (public.is_family_member(family_id));
create policy "conversation visible to members" on public.conversations for select to authenticated using (public.is_family_member(family_id) and public.is_conversation_member(id));
create policy "family members create conversations" on public.conversations for insert to authenticated with check (created_by=auth.uid() and public.is_family_member(family_id));
create policy "conversation members visible" on public.conversation_members for select to authenticated using (public.is_conversation_member(conversation_id));
create policy "family members add conversation members" on public.conversation_members for insert to authenticated with check (exists(select 1 from public.conversations c join public.family_members inviter on inviter.family_id=c.family_id join public.family_members invited on invited.family_id=c.family_id where c.id=conversation_id and inviter.user_id=auth.uid() and invited.user_id=conversation_members.user_id));
create policy "members can read messages" on public.messages for select to authenticated using (public.is_conversation_member(conversation_id));
create policy "members can send own messages" on public.messages for insert to authenticated with check (sender_id=auth.uid() and public.is_conversation_member(conversation_id));
create policy "authors can edit own messages" on public.messages for update to authenticated using (sender_id=auth.uid() and public.is_conversation_member(conversation_id)) with check (sender_id=auth.uid() and public.is_conversation_member(conversation_id));
create policy "authors can delete own messages" on public.messages for delete to authenticated using (sender_id=auth.uid() and public.is_conversation_member(conversation_id));
create policy "reactions visible to chat members" on public.message_reactions for select to authenticated using (exists(select 1 from public.messages m where m.id=message_id and public.is_conversation_member(m.conversation_id)));
create policy "members manage own reactions" on public.message_reactions for all to authenticated using (user_id=auth.uid() and exists(select 1 from public.messages m where m.id=message_id and public.is_conversation_member(m.conversation_id))) with check (user_id=auth.uid() and exists(select 1 from public.messages m where m.id=message_id and public.is_conversation_member(m.conversation_id)));
create policy "attachments visible to chat members" on public.attachments for select to authenticated using (exists(select 1 from public.messages m where m.id=message_id and public.is_conversation_member(m.conversation_id)));
create policy "chat members add attachments" on public.attachments for insert to authenticated with check (exists(select 1 from public.messages m where m.id=message_id and m.sender_id=auth.uid() and public.is_conversation_member(m.conversation_id)));
create policy "read receipts visible to chat members" on public.read_receipts for select to authenticated using (exists(select 1 from public.messages m where m.id=message_id and public.is_conversation_member(m.conversation_id)));
create policy "users manage own receipts" on public.read_receipts for all to authenticated using (user_id=auth.uid() and exists(select 1 from public.messages m where m.id=message_id and public.is_conversation_member(m.conversation_id))) with check (user_id=auth.uid() and exists(select 1 from public.messages m where m.id=message_id and public.is_conversation_member(m.conversation_id)));
create policy "family admins manage invites" on public.invitations for all to authenticated using (exists(select 1 from public.family_members fm where fm.family_id=invitations.family_id and fm.user_id=auth.uid() and fm.role in ('owner','admin'))) with check (created_by=auth.uid() and exists(select 1 from public.family_members fm where fm.family_id=invitations.family_id and fm.user_id=auth.uid() and fm.role in ('owner','admin')));
create policy "users see own notifications" on public.notifications for select to authenticated using (user_id=auth.uid());
create policy "users update own notifications" on public.notifications for update to authenticated using (user_id=auth.uid()) with check (user_id=auth.uid());

-- Enable database changes for Realtime message updates (safe to re-run).
do $$ begin
  if not exists(select 1 from pg_publication_tables where pubname='supabase_realtime' and schemaname='public' and tablename='messages') then
    alter publication supabase_realtime add table public.messages;
  end if;
end $$;

-- Storage bucket and object policies. Run once in a project with Storage enabled.
insert into storage.buckets(id,name,public,file_size_limit,allowed_mime_types)
values('family-media','family-media',false,52428800,array['image/jpeg','image/png','image/webp','image/heic','video/mp4','video/quicktime','audio/webm','audio/mp4','application/pdf'])
on conflict (id) do nothing;
create policy "family members read attachments" on storage.objects for select to authenticated using (bucket_id='family-media' and exists(select 1 from public.attachments a join public.messages m on m.id=a.message_id where a.object_path=name and public.is_conversation_member(m.conversation_id)));
create policy "signed-in users upload family media" on storage.objects for insert to authenticated with check (bucket_id='family-media' and (storage.foldername(name))[1]=auth.uid()::text);
create policy "uploaders remove own family media" on storage.objects for delete to authenticated using (bucket_id='family-media' and (storage.foldername(name))[1]=auth.uid()::text);
