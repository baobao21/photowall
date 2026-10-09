-- ============================================
-- photowall schema — safe to re-run in Supabase SQL Editor
-- ============================================

create table if not exists photos (
  id uuid primary key default gen_random_uuid(),
  storage_path text not null,
  caption text,
  op_name text,
  op_token text,
  uploader_ip_hash text not null,
  status text not null default 'pending'
    check (status in ('pending', 'live', 'archived', 'rejected')),
  created_at timestamptz not null default now()
);
-- for databases created from the older schema:
alter table photos add column if not exists op_name text;
alter table photos add column if not exists op_token text;

-- One permanent name per IP hash. Names are also unique (case-insensitive)
-- so nobody else can take or impersonate a name.
create table if not exists posters (
  ip_hash text primary key,
  name text not null,
  created_at timestamptz not null default now()
);
create unique index if not exists posters_name_lower_idx on posters (lower(name));

create table if not exists likes (
  id bigint generated always as identity primary key,
  photo_id uuid not null references photos(id) on delete cascade,
  liker_ip_hash text not null,
  created_at timestamptz not null default now(),
  unique (photo_id, liker_ip_hash)
);

create table if not exists comments (
  id bigint generated always as identity primary key,
  photo_id uuid not null references photos(id) on delete cascade,
  commenter_ip_hash text not null,
  body text not null check (char_length(body) between 1 and 500),
  author_name text,
  is_op boolean not null default false,
  parent_id bigint references comments(id) on delete cascade,
  created_at timestamptz not null default now()
);
alter table comments add column if not exists author_name text;
alter table comments add column if not exists is_op boolean not null default false;
alter table comments add column if not exists parent_id bigint references comments(id) on delete cascade;

create index if not exists likes_photo_idx on likes (photo_id);
create index if not exists comments_photo_idx on comments (photo_id);
create index if not exists comments_ip_idx on comments (commenter_ip_hash, created_at);
create index if not exists likes_ip_idx on likes (liker_ip_hash, created_at);

-- Single-row table: what's on the big screen right now.
-- ON DELETE SET NULL (was CASCADE, which deleted this row when its photo was deleted
-- and broke the display forever).
create table if not exists display_state (
  id int primary key default 1 check (id = 1),
  photo_id uuid references photos(id) on delete set null,
  started_at timestamptz,
  updated_at timestamptz not null default now()
);
alter table display_state drop constraint if exists display_state_photo_id_fkey;
alter table display_state
  add constraint display_state_photo_id_fkey
  foreign key (photo_id) references photos(id) on delete set null;
insert into display_state (id) values (1) on conflict (id) do nothing;

create table if not exists display_log (
  id bigint generated always as identity primary key,
  photo_id uuid not null references photos(id) on delete cascade,
  shown_at timestamptz not null default now()
);
create index if not exists display_log_time_idx on display_log (shown_at);

create or replace function purge_old_ip_hashes()
returns void language sql as $$
  delete from likes    where created_at < now() - interval '30 days';
  delete from comments where created_at < now() - interval '30 days';
$$;

-- Picks the next photo among status = 'live'. Favours newer uploads.
create or replace function pick_next_photo(excl_hours int)
returns setof photos language sql stable as $$
  select * from photos
  where status = 'live'
    and (excl_hours = 0 or id not in (
      select photo_id from display_log
      where shown_at > now() - (excl_hours || ' hours')::interval
    ))
  order by random() * (extract(epoch from now() - created_at) + 3600) asc
  limit 1
$$;

-- Photos stuck as 'pending' from the old flow? Uncomment to publish them:
-- update photos set status = 'live' where status = 'pending';

-- Setup: Storage -> New bucket -> "photos" -> PUBLIC bucket.
