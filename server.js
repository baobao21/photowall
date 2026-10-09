require('dotenv').config();
const path = require('path');
const crypto = require('crypto');
const express = require('express');
const multer = require('multer');
const rateLimit = require('express-rate-limit');
const { createClient } = require('@supabase/supabase-js');

// ---------- config ----------
const app = express();
const PORT = process.env.PORT || 3000;

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);
const BUCKET = process.env.SUPABASE_BUCKET || 'photos';

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 8 * 1024 * 1024, files: 1 },
});

const BASE_MINUTES = 10;      // every photo gets 10 minutes
const LIKE_MINUTES = 5;       // +5 min per like
const COMMENT_MINUTES = 10;   // +10 min per comment
const REPEAT_EXCLUSION_HOURS = 24;

const ALLOWED_MIME = {
  'image/jpeg': 'jpg',
  'image/png': 'png',
  'image/webp': 'webp',
  'image/gif': 'gif',
};

// IPs are stored only as salted hashes — we can dedupe, but a leak can't identify anyone.
const IP_SALT = process.env.IP_SALT || crypto.randomBytes(32).toString('hex');
if (!process.env.IP_SALT) {
  console.warn('[warn] IP_SALT is not set — generated a random one for this session only. Set it in .env or likes will reset on restart.');
}

const clientIp = (req) =>
  (req.headers['x-forwarded-for']?.split(',')[0] || req.socket.remoteAddress || 'unknown').trim();
const hashIp = (ip) =>
  crypto.createHash('sha256').update(`${ip}:${IP_SALT}`).digest('hex');

// ---------- middleware ----------
app.set('trust proxy', 1); // Render sits behind a proxy
app.use(express.json({ limit: '20kb' }));
app.use(express.static(path.join(__dirname, 'photowall')));

const uploadLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, max: 10,
  standardHeaders: true, legacyHeaders: false,
  message: { error: 'Upload limit reached. Try again in a few minutes.' },
});
const commentLimiter = rateLimit({
  windowMs: 60 * 1000, max: 20,
  standardHeaders: true, legacyHeaders: false,
  message: { error: 'Slow down with the comments a little.' },
});
const likeLimiter = rateLimit({
  windowMs: 60 * 1000, max: 60,
  standardHeaders: true, legacyHeaders: false,
});

// ---------- display logic ----------
async function getEngagement(photoId) {
  const [l, c] = await Promise.all([
    supabase.from('likes').select('*', { count: 'exact', head: true }).eq('photo_id', photoId),
    supabase.from('comments').select('*', { count: 'exact', head: true }).eq('photo_id', photoId),
  ]);
  return { likes: l.count || 0, comments: c.count || 0 };
}

function remainingSeconds(startedAt, engagement) {
  const baseEnd = new Date(startedAt).getTime() + BASE_MINUTES * 60 * 1000;
  const bonus = (engagement.likes * LIKE_MINUTES + engagement.comments * COMMENT_MINUTES) * 60 * 1000;
  return Math.max(0, Math.round((baseEnd + bonus - Date.now()) / 1000));
}

async function getCurrentDisplay() {
  const { data: state } = await supabase
    .from('display_state').select('photo_id, started_at').eq('id', 1).single();
  if (!state?.photo_id) return null;

  const { data: photo } = await supabase
    .from('photos').select('id, caption, storage_path, created_at')
    .eq('id', state.photo_id).single();
  if (!photo) return null;

  const engagement = await getEngagement(photo.id);
  const { data: url } = supabase.storage.from(BUCKET).getPublicUrl(photo.storage_path);

  return {
    photo: {
      id: photo.id,
      caption: photo.caption,
      url: url.publicUrl,
      uploadedAt: photo.created_at,
    },
    engagement,
    remainingSeconds: remainingSeconds(state.started_at, engagement),
    startedAt: state.started_at,
  };
}

async function pickNextPhoto() {
  // Prefer unseen-in-24h photos; fall back to allowing repeats rather than a blank screen.
  const { data } = await supabase.rpc('pick_next_photo', { excl_hours: REPEAT_EXCLUSION_HOURS });
  if (data) return data;
  const { data: any } = await supabase.rpc('pick_next_photo', { excl_hours: 0 });
  return any || null;
}

// The heart of the app. Runs every 30s: if the current photo's time is up
// (base time + engagement bonus), crown a new random one.
async function tick() {
  try {
    const current = await getCurrentDisplay();
    if (current && current.remainingSeconds > 0) return;

    const next = await pickNextPhoto();
    if (!next) {
      console.log('[tick] queue is empty — nothing to show');
      return;
    }

    const now = new Date().toISOString();
    const { error } = await supabase.from('display_state')
      .update({ photo_id: next.id, started_at: now, updated_at: now })
      .eq('id', 1);
    if (error) throw error;

    await supabase.from('display_log').insert({ photo_id: next.id });
    console.log(`[tick] now showing photo ${next.id}`);
  } catch (err) {
    console.error('[tick] error:', err.message);
  }
}

// ---------- routes ----------
app.get('/api/health', (req, res) => res.json({ ok: true }));

app.get('/api/current', async (req, res) => {
  try {
    const current = await getCurrentDisplay();
    res.json(current || {
      photo: null,
      engagement: { likes: 0, comments: 0 },
      remainingSeconds: 0,
    });
  } catch (err) {
    console.error('[current]', err);
    res.status(500).json({ error: 'Could not load the current photo.' });
  }
});

app.post('/api/upload', uploadLimiter, upload.single('photo'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'No photo attached.' });

    const ext = ALLOWED_MIME[req.file.mimetype];
    if (!ext) {
      return res.status(400).json({ error: 'Only JPG, PNG, WebP or GIF images are allowed.' });
    }

    const caption = (req.body.caption || '').toString().slice(0, 280);
    const storagePath = `uploads/${Date.now()}-${crypto.randomBytes(6).toString('hex')}.${ext}`;

    const { error: upErr } = await supabase.storage
      .from(BUCKET)
      .upload(storagePath, req.file.buffer, { contentType: req.file.mimetype, upsert: false });
    if (upErr) throw upErr;

    const { data: photo, error: dbErr } = await supabase.from('photos')
      .insert({
        storage_path: storagePath,
        caption,
        uploader_ip_hash: hashIp(clientIp(req)),
        status: 'pending',
      })
      .select('id')
      .single();
    if (dbErr) throw dbErr;

    res.json({ ok: true, id: photo.id });
  } catch (err) {
    console.error('[upload]', err);
    res.status(500).json({ error: 'Upload failed. Please try again.' });
  }
});

app.post('/api/like', likeLimiter, async (req, res) => {
  const photoId = req.body?.photoId;
  if (!photoId) return res.status(400).json({ error: 'photoId is required.' });

  const { error } = await supabase.from('likes')
    .insert({ photo_id: photoId, liker_ip_hash: hashIp(clientIp(req)) });

  if (error) {
    if (error.code === '23505') {
      return res.status(409).json({ error: 'You already liked this photo.' });
    }
    console.error('[like]', error);
    return res.status(500).json({ error: 'Like failed.' });
  }
  res.json({ ok: true });
});

app.post('/api/comments', commentLimiter, async (req, res) => {
  const { photoId, body } = req.body || {};
  const text = (body || '').toString().trim().slice(0, 500);
  if (!photoId || !text) {
    return res.status(400).json({ error: 'photoId and a comment body are required.' });
  }

  const { error } = await supabase.from('comments')
    .insert({ photo_id: photoId, commenter_ip_hash: hashIp(clientIp(req)), body: text });

  if (error) {
    console.error('[comment]', error);
    return res.status(500).json({ error: 'Comment failed.' });
  }
  res.json({ ok: true });
});

app.get('/api/photos/:id/comments', async (req, res) => {
  const { data, error } = await supabase.from('comments')
    .select('id, body, created_at')
    .eq('photo_id', req.params.id)
    .order('created_at', { ascending: false })
    .limit(100);

  if (error) return res.status(500).json({ error: 'Could not load comments.' });
  res.json(data || []);
});

// Optional: external cron (e.g. cron-job.org every minute) can hit this to
// wake a sleeping free-tier instance and force a scheduler check.
app.post('/api/tick', (req, res) => {
  if (req.headers['x-cron-secret'] !== process.env.CRON_SECRET) {
    return res.status(401).json({ error: 'unauthorized' });
  }
  tick();
  res.json({ ok: true });
});

// ---------- go ----------
setInterval(tick, 30 * 1000);
app.listen(PORT, () => console.log(`photowall running on :${PORT}`));
