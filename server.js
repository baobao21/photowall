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

// ---------- anti-spam & moderation rules ----------
const COMMENTS_PER_PHOTO_PER_IP = 5;      // max comments one IP can leave on a single photo
const COMMENTS_PER_DAY_PER_IP = 40;       // global daily comment cap per IP
const COMMENT_COOLDOWN_SECONDS = 15;      // min seconds between comments from one IP
const LIKES_PER_DAY_PER_IP = 100;         // global daily like cap per IP
const VPN_CACHE_HOURS = 24;               // how long we remember an IP's VPN check

const ALLOWED_MIME = {
  'image/jpeg': 'jpg',
  'image/png': 'png',
  'image/webp': 'webp',
  'image/gif': 'gif',
};

// Fun anonymous name generator for uploaders who don't pick a name
const ADJ = ['Swift', 'Clever', 'Sleepy', 'Bold', 'Cosmic', 'Mellow', 'Hyper', 'Quiet', 'Lucky', 'Grumpy', 'Neon', 'Ancient', 'Sneaky', 'Turbo', 'Frosty', 'Golden'];
const NOUN = ['Fox', 'Otter', 'Raccoon', 'Panda', 'Falcon', 'Wolf', 'Lynx', 'Badger', 'Crane', 'Moose', 'Viper', 'Badger', 'Heron', 'Bison', 'Eagle', 'Sphinx'];
const generateName = () =>
  `${ADJ[crypto.randomInt(ADJ.length)]} ${NOUN[crypto.randomInt(NOUN.length)]} ${crypto.randomInt(1000, 9999)}`;

// IPs are stored only as salted hashes — we can dedupe, but a leak can't identify anyone.
const IP_SALT = process.env.IP_SALT || crypto.randomBytes(32).toString('hex');
if (!process.env.IP_SALT) {
  console.warn('[warn] IP_SALT is not set — generated a random one for this session only. Set it in .env or likes will reset on restart.');
}

const clientIp = (req) =>
  (req.headers['x-forwarded-for']?.split(',')[0] || req.socket.remoteAddress || 'unknown').trim();
const hashIp = (ip) =>
  crypto.createHash('sha256').update(`${ip}:${IP_SALT}`).digest('hex');

// --- Malicious link & spam blocker function ---
function containsMaliciousContent(text) {
  if (!text) return false;
  const urlRegex = /(https?:\/\/|www\.|[a-zA-Z0-9-]+\.(com|net|org|ru|xyz|top|cn|info|tk))/i;
  return urlRegex.test(text);
}

// ---------- VPN / proxy detection ----------
const vpnCache = new Map(); // ipHash -> { bad: boolean, at: number }

async function isBadIp(ip) {
  if (!process.env.VPNCHECK_API_KEY) return false;
  const key = hashIp(ip);
  const cached = vpnCache.get(key);
  if (cached && Date.now() - cached.at < VPN_CACHE_HOURS * 3600 * 1000) return cached.bad;

  let bad = false;
  try {
    const res = await fetch(
      `https://proxycheck.io/v2/${encodeURIComponent(ip)}?key=${process.env.VPNCHECK_API_KEY}&vpn=3&risk=2&asn=1`,
      { signal: AbortSignal.timeout(4000) }
    );
    const data = await res.json();
    const info = data?.[ip];
    bad = !!info && (
      info.proxy === 'yes' ||
      info.type === 'VPN' ||
      info.type === 'TOR' ||
      (parseInt(info.risk, 10) || 0) >= 80
    );
  } catch {
    bad = false;
  }
  vpnCache.set(key, { bad, at: Date.now() });
  if (bad) console.log(`[vpn-check] blocked ${ip} (vpn/proxy/tor)`);
  return bad;
}

// ---------- middleware ----------
app.set('trust proxy', 1);
app.use(express.json({ limit: '20kb' }));
app.use(express.static(path.join(__dirname, 'public')));

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
    .from('photos').select('id, caption, storage_path, op_name, created_at')
    .eq('id', state.photo_id).single();
  if (!photo) return null;

  const engagement = await getEngagement(photo.id);
  const { data: urlData } = supabase.storage.from(BUCKET).getPublicUrl(photo.storage_path);

  return {
    photo: {
      id: photo.id,
      caption: photo.caption,
      url: urlData.publicUrl,
      opName: photo.op_name,
      uploadedAt: photo.created_at,
    },
    engagement,
    remainingSeconds: remainingSeconds(state.started_at, engagement),
    startedAt: state.started_at,
  };
}

async function pickNextPhoto() {
  const get = async (hours) => {
    const { data } = await supabase.rpc('pick_next_photo', { excl_hours: hours });
    return Array.isArray(data) ? data[0] : data;
  };
  return (await get(REPEAT_EXCLUSION_HOURS)) || (await get(0));
}

async function tick() {
  try {
    const current = await getCurrentDisplay();
    if (current && current.remainingSeconds > 0) return;

    const next = await pickNextPhoto();
    if (!next || !next.id) {
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
    if (containsMaliciousContent(caption)) {
      return res.status(400).json({ error: 'Captions cannot contain links or promotional URLs.' });
    }

    const requestedName = (req.body.opName || '').toString().trim().slice(0, 20);
    const opName = requestedName || generateName();
    const opToken = crypto.randomUUID();

    const storagePath = `uploads/${Date.now()}-${crypto.randomBytes(6).toString('hex')}.${ext}`;
    const { error: upErr } = await supabase.storage
      .from(BUCKET)
      .upload(storagePath, req.file.buffer, { contentType: req.file.mimetype, upsert: false });
    if (upErr) throw upErr;

    const { data: photo, error: dbErr } = await supabase.from('photos')
      .insert({
        storage_path: storagePath,
        caption,
        op_name: opName,
        op_token: opToken,
        uploader_ip_hash: hashIp(clientIp(req)),
        status: 'pending',
      })
      .select('id')
      .single();
    if (dbErr) throw dbErr;

    res.json({ ok: true, id: photo.id, opName, opToken });
  } catch (err) {
    console.error('[upload]', err);
    res.status(500).json({ error: 'Upload failed. Please try again.' });
  }
});

app.post('/api/like', likeLimiter, async (req, res) => {
  const photoId = req.body?.photoId;
  if (!photoId) return res.status(400).json({ error: 'photoId is required.' });

  const ipHash = hashIp(clientIp(req));

  if (await isBadIp(clientIp(req))) {
    return res.status(403).json({ error: 'Likes are disabled on VPN/proxy connections.' });
  }

  const dayAgo = new Date(Date.now() - 24 * 3600 * 1000).toISOString();
  const { count: likesToday } = await supabase.from('likes')
    .select('*', { count: 'exact', head: true })
    .eq('liker_ip_hash', ipHash)
    .gte('created_at', dayAgo);
  if ((likesToday || 0) >= LIKES_PER_DAY_PER_IP) {
    return res.status(429).json({ error: 'Daily like limit reached. Come back tomorrow.' });
  }

  const { error } = await supabase.from('likes')
    .insert({ photo_id: photoId, liker_ip_hash: ipHash });

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
  const { photoId, body, opToken } = req.body || {};
  const text = (body || '').toString().trim().slice(0, 500);
  
  if (containsMaliciousContent(text)) {
    return res.status(400).json({ error: 'Comments cannot contain links or external URLs.' });
  }
  
  if (!photoId || !text) {
    return res.status(400).json({ error: 'photoId and a comment body are required.' });
  }

  const ip = clientIp(req);
  const ipHash = hashIp(ip);

  if (await isBadIp(ip)) {
    return res.status(403).json({ error: 'Comments are disabled on VPN/proxy connections.' });
  }

  const { data: lastComment } = await supabase.from('comments')
    .select('created_at').eq('commenter_ip_hash', ipHash)
    .order('created_at', { ascending: false })
    .limit(1).maybeSingle();
  if (lastComment && Date.now() - new Date(lastComment.created_at).getTime() < COMMENT_COOLDOWN_SECONDS * 1000) {
    return res.status(429).json({ error: `Please wait ${COMMENT_COOLDOWN_SECONDS} seconds between comments.` });
  }

  const { count: onPhoto } = await supabase.from('comments')
    .select('*', { count: 'exact', head: true })
    .eq('photo_id', photoId).eq('commenter_ip_hash', ipHash);
  if ((onPhoto || 0) >= COMMENTS_PER_PHOTO_PER_IP) {
    return res.status(429).json({ error: `Max ${COMMENTS_PER_PHOTO_PER_IP} comments per photo.` });
  }

  const dayAgo = new Date(Date.now() - 24 * 3600 * 1000).toISOString();
  const { count: today } = await supabase.from('comments')
    .select('*', { count: 'exact', head: true })
    .eq('commenter_ip_hash', ipHash)
    .gte('created_at', dayAgo);
  if ((today || 0) >= COMMENTS_PER_DAY_PER_IP) {
    return res.status(429).json({ error: 'Daily comment limit reached. Come back tomorrow.' });
  }

  let authorName = null;
  let isOp = false;
  if (opToken) {
    const { data: photo } = await supabase.from('photos')
      .select('op_token, op_name').eq('id', photoId).maybeSingle();
    if (photo?.op_token && photo.op_token === opToken) {
      isOp = true;
      authorName = photo.op_name;
    }
  }

  const { data: comment, error } = await supabase.from('comments')
    .insert({ photo_id: photoId, commenter_ip_hash: ipHash, body: text, author_name: authorName, is_op: isOp })
    .select('id, body, author_name, is_op, created_at')
    .single();

  if (error) {
    console.error('[comment]', error);
    return res.status(500).json({ error: 'Comment failed.' });
  }
  res.json(comment);
});

app.get('/api/photos/:id/comments', async (req, res) => {
  const { data, error } = await supabase.from('comments')
    .select('id, body, author_name, is_op, created_at')
    .eq('photo_id', req.params.id)
    .order('created_at', { ascending: false })
    .limit(100);

  if (error) return res.status(500).json({ error: 'Could not load comments.' });
  res.json(data || []);
});

app.post('/api/tick', (req, res) => {
  if (req.headers['x-cron-secret'] !== process.env.CRON_SECRET) {
    return res.status(401).json({ error: 'unauthorized' });
  }
  tick();
  res.json({ ok: true });
});

// --- Admin Authentication & Moderation Routes ---
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'change-this-secure-password';
const adminSessions = new Set();

app.post('/api/admin/login', (req, res) => {
  const { password } = req.body || {};
  if (password === ADMIN_PASSWORD) {
    const token = crypto.randomBytes(32).toString('hex');
    adminSessions.add(token);
    return res.json({ ok: true, token });
  }
  res.status(401).json({ error: 'Invalid admin password.' });
});

const requireAdmin = (req, res, next) => {
  const token = req.headers['x-admin-token'];
  if (token && adminSessions.has(token)) {
    return next();
  }
  res.status(401).json({ error: 'Unauthorized.' });
};

app.get('/api/admin/photos', requireAdmin, async (req, res) => {
  const { data, error } = await supabase
    .from('photos')
    .select('*')
    .order('created_at', { ascending: false })
    .limit(50);
  if (error) return res.status(500).json({ error: 'Failed to fetch photos' });
  res.json(data);
});

app.post('/api/admin/moderate-photo', requireAdmin, async (req, res) => {
  const { photoId, status } = req.body;
  if (!['pending', 'live', 'archived', 'rejected'].includes(status)) {
    return res.status(400).json({ error: 'Invalid status.' });
  }
  const { error } = await supabase
    .from('photos')
    .update({ status })
    .eq('id', photoId);
  if (error) return res.status(500).json({ error: 'Moderation failed.' });
  res.json({ ok: true });
});

// Edit photo caption (Admin)
app.put('/api/admin/photos/:id', requireAdmin, async (req, res) => {
  const { caption } = req.body;
  const { error } = await supabase
    .from('photos')
    .update({ caption: (caption || '').toString().slice(0, 280) })
    .eq('id', req.params.id);
  if (error) return res.status(500).json({ error: 'Failed to update caption.' });
  res.json({ ok: true });
});

// Delete photo (Admin)
app.delete('/api/admin/photos/:id', requireAdmin, async (req, res) => {
  const { error } = await supabase
    .from('photos')
    .delete()
    .eq('id', req.params.id);
  if (error) return res.status(500).json({ error: 'Failed to delete photo.' });
  res.json({ ok: true });
});

app.delete('/api/admin/comments/:id', requireAdmin, async (req, res) => {
  const { error } = await supabase
    .from('comments')
    .delete()
    .eq('id', req.params.id);
  if (error) return res.status(500).json({ error: 'Failed to delete comment.' });
  res.json({ ok: true });
});

// ---------- go ----------
setInterval(tick, 30 * 1000);
app.listen(PORT, () => console.log(`photowall running on :${PORT}`));
