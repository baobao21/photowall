# THE WALL

One random photo on a big screen. It gets 10 minutes by default.
Every like adds **+5 minutes**, every comment adds **+10 minutes**.
When its time runs out, the next random photo takes the screen.

Built with: **Express (Render)** + **Supabase (Postgres + Storage)** + a vanilla JS frontend.

## 1. Supabase setup (5 min)

1. Create a project at [supabase.com](https://supabase.com).
2. **Storage** → *New bucket* → name it `photos`, make it **public**.
3. **SQL Editor** → paste the full contents of `db/schema.sql` → *Run*.

## 2. Local run

```bash
cp .env.example .env       # fill in your Supabase URL + service role key
npm install
npm run dev                # http://localhost:3000
```

## 3. Deploy to Render

1. Push this folder to a GitHub repo.
2. Render → *New* → *Web Service* → connect the repo. Render reads `render.yaml` automatically.
3. Add the environment variables (`SUPABASE_URL`, `SUPABASE_SERVICE_ROLE_KEY`, `IP_SALT`, `CRON_SECRET`).
   Generate secrets with: `openssl rand -hex 32`

### Free tier note

Free Render instances sleep after inactivity, which pauses the scheduler. Two options:

- **Easiest free fix:** create a job at [cron-job.org](https://cron-job.org) that POSTs
  to `https://your-app.onrender.com/api/tick` every minute with header `x-cron-secret: YOUR_CRON_SECRET`.
  The request wakes the instance and forces a scheduler check. (First request after sleep may be slow — cold start.)
- **Proper fix:** use the `starter` plan (always-on) and the built-in 30-second scheduler handles everything.

## How the algorithm works

- A `tick()` runs every 30 seconds.
- Remaining time is computed live: `base 10 min + 5 × likes + 10 × comments`, never stored — so engagement extends the display instantly for everyone.
- When time hits zero, `pick_next_photo()` randomly selects a `pending` photo, favouring newer uploads and avoiding anything shown in the last 24 hours (falls back to repeats if the queue is empty).
- The result goes into the single-row `display_state` table; the frontend polls `/api/current` every 4 seconds.

## Privacy & moderation (please read)

- **Raw IPs are never stored** — only salted SHA-256 hashes (dedupe likes, one like per IP per photo).
- Hashes are auto-purged after 30 days (`purge_old_ip_hashes()` — schedule it with pg_cron or run manually).
- Uploads of other people, illegal content, etc. — add a report button and moderate via
  `update photos set status='rejected' where id = '...'` (the picker only selects `pending`).
- Write a short privacy policy; IP-derived data may fall under GDPR/CCPA in your region.
- TODO: strip EXIF metadata from uploads (e.g. add `sharp`), and consider a profanity filter for comments.
