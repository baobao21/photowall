-- ============================================
-- photowall schema — run this in Supabase SQL Editor
-- ============================================

create table if not exists photos (
  id uuid primary key default gen_random_uuid(),
  storage_path text not null,
  caption text,
  uploader_ip_hash text not null,      -- SHA-256(ip + salt), never the raw IP
  status text not null default 'pending'
    check (status in ('pending', 'live', 'archived', 'rejected')),
  created_at timestamptz not null default now()
);

create table if not exists likes (
  id bigint generated always as identity primary key,
  photo_id uuid not null references photos(id) on delete cascade,
  liker_ip_hash text not null,
  created_at timestamptz not null default now(),
  unique (photo_id, liker_ip_hash)     -- one like per IP per photo
);

create table if not exists comments (
  id bigint generated always as identity primary key,
  photo_id uuid not null references photos(id) on delete cascade,
  commenter_ip_hash text not null,
  body text not null check (char_length(body) between 1 and 500),
  created_at timestamptz not null default now()
);

create index if not exists likes_photo_idx on likes (photo_id);
create index if not exists comments_photo_idx on comments (photo_id);

-- Single-row table holding whatever photo is on the big screen right now
create table if not exists display_state (
  id int primary key default 1 check (id = 1),
  photo_id uuid references photos(id) on delete cascade,
  started_at timestamptz,
  updated_at timestamptz not null default now()
);
insert into display_state (id) values (1)
on conflict (id) do nothing;

-- History of what was shown, used to avoid repeats
create table if not exists display_log (
  id bigint generated always as identity primary key,
  photo_id uuid not null references photos(id) on delete cascade,
  shown_at timestamptz not null default now()
);
create index if not exists display_log_time_idx on display_log (shown_at);

-- Deletes IPs (hashes) older than 30 days — keep this or adjust as you like
create or replace function purge_old_ip_hashes()
returns void language sql as $$
  delete from likes      where created_at < now() - interval '30 days';
  delete from comments   where created_at < now() - interval '30 days';
$$;

-- Randomly picks the next photo. Favours newer uploads, and (when excl_hours > 0)
-- avoids photos shown within the last N hours.
create or replace function pick_next_photo(excl_hours int)
returns setof photos language sql stable as $$
  select * from photos
  where status = 'pending'
    and (excl_hours = 0 or id not in (
      select photo_id from display_log
      where shown_at > now() - (excl_hours || ' hours')::interval
    ))
  order by random() * (extract(epoch from now() - created_at) + 3600) asc
  limit 1
$$;

-- 0. Enable Storage: Storage -> New bucket -> name it "photos" -> PUBLIC bucket.
-- 1. Copy this file's contents into the Supabase SQL Editor and run it.
-- 2. Set SUPABASE_BUCKET=photos in your .env to match the bucket name.
