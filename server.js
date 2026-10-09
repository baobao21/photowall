require('dotenv').config();
const path = require('path');
const crypto = require('crypto');
const express = require('express');
const multer = require('multer');
const rateLimit = require('express-rate-limit');
const { createClient } = require('@supabase/supabase-js');

// ---------- config ----------
if (!process.env.SUPABASE_URL || !process.env.SUPABASE_SERVICE_ROLE_KEY) {
  console.error('[fatal] SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY must be set.');
  process.exit(1);
}
const app = express();
const PORT = process.env.PORT || 3000;
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY);
const BUCKET = process.env.SUPABASE_BUCKET || 'photos';
const REQUIRE_APPROVAL = process.env.REQUIRE_APPROVAL === 'true';

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 8 * 1024 * 1024, files: 1 },
});

const BASE_SECONDS = 15;
const LIKE_MINUTES = 5;
const COMMENT_MINUTES = 10;
const REPEAT_EXCLUSION_HOURS = 0;

const COMMENTS_PER_PHOTO_PER_IP = 5;
const COMMENTS_PER_DAY_PER_IP = 40;
const COMMENT_COOLDOWN_SECONDS = 15;
const LIKES_PER_DAY_PER_IP = 100;
const VPN_CACHE_HOURS = 24;

const ADJ = ['Swift', 'Clever', 'Sleepy', 'Bold', 'Cosmic', 'Mellow', 'Hyper', 'Quiet', 'Lucky', 'Grumpy', 'Neon', 'Ancient', 'Sneaky', 'Turbo', 'Frosty', 'Golden'];
const NOUN = ['Fox', 'Otter', 'Raccoon', 'Panda', 'Falcon', 'Wolf', 'Lynx', 'Badger', 'Crane', 'Moose', 'Viper', 'Cobra', 'Heron', 'Bison', 'Eagle', 'Sphinx'];
const generateName = () =>
  `${ADJ[crypto.randomInt(ADJ.length)]} ${NOUN[crypto.randomInt(NOUN.length)]} ${crypto.randomInt(1000, 9999)}`;

const IP_SALT = process.env.IP_SALT || crypto.randomBytes(32).toString('hex');
if (!process.env.IP_SALT) {
  console.warn('[warn] IP_SALT is not set — using a random one for this run. Likes will reset on restart.');
}
// Never trust the raw X-Forwarded-For header: the client can put anything in it, which lets
// someone get unlimited fake IPs. Express's req.ip only trusts the proxy hops we configure.
const clientIp = (req) => (req.ip || req.socket.remoteAddress || 'unknown').replace(/^::ffff:/, '');
const hashIp = (ip) => crypto.createHash('sha256').update(`${ip}:${IP_SALT}`).digest('hex');

// ---------- permanent poster names (one name per IP hash, forever) ----------
async function getPosterName(ipHash) {
  const { data } = await supabase.from('posters').select('name').eq('ip_hash', ipHash).maybeSingle();
  if (data?.name) return data.name;

  // Legacy: this IP posted before the posters table existed -> adopt the name from its first photo
  const { data: old } = await supabase.from('photos')
    .select('op_name').eq('uploader_ip_hash', ipHash).not('op_name', 'is', null)
    .order('created_at', { ascending: true }).limit(1).maybeSingle();
  if (old?.op_name) {
    const { error } = await supabase.from('posters').insert({ ip_hash: ipHash, name: old.op_name });
    if (!error) return old.op_name;
    const { data: again } = await supabase.from('posters').select('name').eq('ip_hash', ipHash).maybeSingle();
    return again?.name || null; // name taken by someone else -> treat as unbound
  }
  return null;
}

// Returns { name } (existing or newly bound) or { taken: true } if the requested name is in use.
async function claimPosterName(ipHash, requested) {
  const existing = await getPosterName(ipHash);
  if (existing) return { name: existing, existing: true };

  for (let attempt = 0; attempt < 6; attempt++) {
    const useRequested = attempt === 0 && requested;
    const candidate = useRequested ? requested : generateName();
    const { error } = await supabase.from('posters').insert({ ip_hash: ipHash, name: candidate });
    if (!error) return { name: candidate };
    if (error.code !== '23505') throw error;
    // unique violation: either a parallel request already bound this IP, or the name is taken
    const raced = await getPosterName(ipHash);
    if (raced) return { name: raced, existing: true };
    if (useRequested) return { taken: true };
  }
  throw new Error('Could not allocate a poster name');
}

// Detect real image type from file bytes (don't trust the client's mimetype)
function sniffImage(buf) {
  if (!buf || buf.length < 12) return null;
  if (buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff) return { mime: 'image/jpeg', ext: 'jpg' };
  if (buf.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]))) return { mime: 'image/png', ext: 'png' };
  const h6 = buf.subarray(0, 6).toString('latin1');
  if (h6 === 'GIF87a' || h6 === 'GIF89a') return { mime: 'image/gif', ext: 'gif' };
  if (buf.subarray(0, 4).toString('latin1') === 'RIFF' && buf.subarray(8, 12).toString('latin1') === 'WEBP') return { mime: 'image/webp', ext: 'webp' };
  return null;
}

function containsMaliciousContent(text) {
  if (!text) return false;
  return /(https?:\/\/|www\.|[a-zA-Z0-9-]+\.(com|net|org|ru|xyz|top|cn|info|tk)\b)/i.test(text);
}

// Express 4 doesn't catch async errors — without this, one rejected promise can crash the process.
const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch((err) => {
  console.error(`[${req.method} ${req.path}]`, err);
  if (!res.headersSent) res.status(500).json({ error: 'Server error.' });
});

// ---------- VPN / proxy detection ----------
const vpnCache = new Map();
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
    bad = !!info && (info.proxy === 'yes' || info.type === 'VPN' || info.type === 'TOR' || (parseInt(info.risk, 10) || 0) >= 80);
  } catch { bad = false; }
  vpnCache.set(key, { bad, at: Date.now() });
  return bad;
}

// ---------- middleware ----------
app.set('trust proxy', parseInt(process.env.TRUST_PROXY_HOPS || '2', 10));
app.use(express.json({ limit: '20kb' }));
app.use(express.static(path.join(__dirname, 'public')));
app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html')));

const limiterOpts = (windowMs, max, message) => ({
  windowMs, max, standardHeaders: true, legacyHeaders: false,
  keyGenerator: (req) => clientIp(req),
  validate: { keyGeneratorIpFallback: false, ip: false },
  ...(message ? { message: { error: message } } : {}),
});
const uploadLimiter = rateLimit(limiterOpts(15 * 60 * 1000, 10, 'Upload limit reached. Try again in a few minutes.'));
const commentLimiter = rateLimit(limiterOpts(60 * 1000, 20, 'Slow down with the comments a little.'));
const likeLimiter = rateLimit(limiterOpts(60 * 1000, 60, 'Too many likes, slow down.'));
const adminLoginLimiter = rateLimit(limiterOpts(15 * 60 * 1000, 10, 'Too many login attempts.'));

// ---------- display logic ----------
async function getEngagement(photoId, startedAt, uploaderIpHash) {
  const [totalLikes, totalComments, sessionLikesRes, sessionCommentsRes] = await Promise.all([
    supabase.from('likes').select('*', { count: 'exact', head: true }).eq('photo_id', photoId),
    supabase.from('comments').select('*', { count: 'exact', head: true }).eq('photo_id', photoId),
    supabase.from('likes').select('liker_ip_hash').eq('photo_id', photoId).gte('created_at', startedAt),
    supabase.from('comments').select('is_op, commenter_ip_hash, parent_id').eq('photo_id', photoId).gte('created_at', startedAt),
  ]);
  const sLikes = (sessionLikesRes.data || []).filter((l) => l.liker_ip_hash !== uploaderIpHash);
  // replies (parent_id set) never add display time, only new top-level comments do
  const sComments = (sessionCommentsRes.data || []).filter((c) => !c.parent_id && !c.is_op && c.commenter_ip_hash !== uploaderIpHash);
  return {
    display: { likes: totalLikes.count || 0, comments: totalComments.count || 0 },
    session: { likes: sLikes.length, comments: sComments.length },
  };
}

function timing(startedAt, s) {
  const bonus = (s.likes * LIKE_MINUTES + s.comments * COMMENT_MINUTES) * 60;
  const total = BASE_SECONDS + bonus;
  const end = new Date(startedAt).getTime() + total * 1000;
  return { total, remaining: Math.max(0, Math.round((end - Date.now()) / 1000)) };
}

async function getCurrentDisplay() {
  const { data: state } = await supabase.from('display_state').select('photo_id, started_at').eq('id', 1).maybeSingle();
  if (!state?.photo_id || !state.started_at) return null;

  const { data: photo } = await supabase.from('photos')
    .select('id, caption, storage_path, op_name, created_at, uploader_ip_hash, status')
    .eq('id', state.photo_id).maybeSingle();
  // photo deleted, rejected or archived by admin -> treat as nothing on screen so tick() picks a new one
  if (!photo || photo.status !== 'live') return null;

  const eng = await getEngagement(photo.id, state.started_at, photo.uploader_ip_hash);
  const { data: urlData } = supabase.storage.from(BUCKET).getPublicUrl(photo.storage_path);
  const t = timing(state.started_at, eng.session);

  return {
    photo: { id: photo.id, caption: photo.caption, url: urlData.publicUrl, opName: photo.op_name, uploadedAt: photo.created_at },
    engagement: eng.display,
    remainingSeconds: t.remaining,
    totalSeconds: t.total,
    startedAt: state.started_at,
  };
}

async function pickNextPhoto() {
  const get = async (hours) => {
    const { data, error } = await supabase.rpc('pick_next_photo', { excl_hours: hours });
    if (error) console.error('[pick_next_photo]', error.message);
    return Array.isArray(data) ? data[0] : data;
  };
  return (await get(REPEAT_EXCLUSION_HOURS)) || (await get(0));
}

let ticking = false;
async function tick(force = false) {
  if (ticking) return;
  ticking = true;
  try {
    const current = await getCurrentDisplay();
    if (!force && current && current.remainingSeconds > 0) return;

    let next = await pickNextPhoto();
    // when skipping, try not to re-pick the same photo
    for (let i = 0; force && current && next && next.id === current.photo.id && i < 4; i++) {
      next = await pickNextPhoto();
    }
    if (!next || !next.id) {
      if (current === null) {
        await supabase.from('display_state').update({ photo_id: null, started_at: null }).eq('id', 1);
      }
      return;
    }
    const now = new Date().toISOString();
    const { error } = await supabase.from('display_state')
      .update({ photo_id: next.id, started_at: now, updated_at: now }).eq('id', 1);
    if (error) throw error;
    await supabase.from('display_log').insert({ photo_id: next.id });
    console.log(`[tick] now showing photo ${next.id}`);
  } catch (err) {
    console.error('[tick] error:', err.message);
  } finally {
    ticking = false;
  }
}

// ---------- routes ----------
app.get('/api/health', (req, res) => res.json({ ok: true }));

app.get('/api/current', wrap(async (req, res) => {
  const current = await getCurrentDisplay();
  res.json(current || { photo: null, engagement: { likes: 0, comments: 0 }, remainingSeconds: 0, totalSeconds: 0 });
}));

const uploadSingle = (req, res, next) =>
  upload.single('photo')(req, res, (err) => {
    if (!err) return next();
    const msg = err.code === 'LIMIT_FILE_SIZE' ? 'File too big (max 8 MB).' : 'Upload error. Try a different file.';
    res.status(400).json({ error: msg });
  });

app.post('/api/upload', uploadLimiter, uploadSingle, wrap(async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No photo attached.' });

  const kind = sniffImage(req.file.buffer);
  if (!kind) return res.status(400).json({ error: 'Only JPG, PNG, WebP or GIF images are allowed.' });

  const caption = (req.body.caption || '').toString().slice(0, 280);
  if (containsMaliciousContent(caption)) {
    return res.status(400).json({ error: 'Captions cannot contain links or promotional URLs.' });
  }
  const requestedName = (req.body.opName || '').toString().trim().slice(0, 20);
  if (containsMaliciousContent(requestedName)) {
    return res.status(400).json({ error: 'Names cannot contain links.' });
  }
  if (await isBadIp(clientIp(req))) {
    return res.status(403).json({ error: 'Uploads are disabled on VPN/proxy connections.' });
  }
  // The name is bound to this IP permanently; whatever was typed is ignored if one already exists.
  const ipHash = hashIp(clientIp(req));
  let claim;
  try {
    claim = await claimPosterName(ipHash, requestedName);
  } catch (err) {
    console.error('[upload] poster name:', err);
    const missing = err.code === '42P01' || err.code === 'PGRST205' || /posters/.test(err.message || '');
    return res.status(500).json({
      error: missing
        ? 'Setup problem: the "posters" table is missing. Run schema.sql in the Supabase SQL editor.'
        : `Could not assign a poster name (${err.message || 'unknown error'}).`,
    });
  }
  if (claim.taken) {
    return res.status(409).json({ error: 'That name is already taken. Pick another, or leave it blank for a random one.' });
  }
  const opName = claim.name;
  const opToken = crypto.randomUUID();

  const storagePath = `uploads/${Date.now()}-${crypto.randomBytes(6).toString('hex')}.${kind.ext}`;
  const { error: upErr } = await supabase.storage.from(BUCKET)
    .upload(storagePath, req.file.buffer, { contentType: kind.mime, upsert: false });
  if (upErr) {
    console.error('[upload] storage:', upErr);
    return res.status(500).json({ error: 'Storage upload failed. Check that the "photos" bucket exists.' });
  }

  const status = REQUIRE_APPROVAL ? 'pending' : 'live';
  const { data: photo, error: dbErr } = await supabase.from('photos')
    .insert({ storage_path: storagePath, caption, op_name: opName, op_token: opToken, uploader_ip_hash: ipHash, status })
    .select('id').single();
  if (dbErr) {
    console.error('[upload] db:', dbErr);
    await supabase.storage.from(BUCKET).remove([storagePath]); // don't leave orphan files
    return res.status(500).json({ error: 'Upload failed. Please try again.' });
  }

  res.json({ ok: true, id: photo.id, opName, opToken, status });
  tick(); // show it right away if the screen is empty
}));

app.get('/api/my-name', wrap(async (req, res) => {
  const name = await getPosterName(hashIp(clientIp(req)));
  res.json({ name: name || null });
}));

app.post('/api/like', likeLimiter, wrap(async (req, res) => {
  const photoId = req.body?.photoId;
  if (!photoId) return res.status(400).json({ error: 'photoId is required.' });
  const ip = clientIp(req);
  const ipHash = hashIp(ip);

  if (await isBadIp(ip)) return res.status(403).json({ error: 'Likes are disabled on VPN/proxy connections.' });

  const dayAgo = new Date(Date.now() - 24 * 3600 * 1000).toISOString();
  const { count: likesToday } = await supabase.from('likes')
    .select('*', { count: 'exact', head: true }).eq('liker_ip_hash', ipHash).gte('created_at', dayAgo);
  if ((likesToday || 0) >= LIKES_PER_DAY_PER_IP) {
    return res.status(429).json({ error: 'Daily like limit reached. Come back tomorrow.' });
  }

  const { error } = await supabase.from('likes').insert({ photo_id: photoId, liker_ip_hash: ipHash });
  if (error) {
    if (error.code === '23505') return res.status(409).json({ error: 'You already liked this photo.' });
    console.error('[like]', error);
    return res.status(500).json({ error: 'Like failed.' });
  }
  res.json({ ok: true });
}));

app.post('/api/comments', commentLimiter, wrap(async (req, res) => {
  const { photoId, body, opToken, parentId } = req.body || {};
  const text = (body || '').toString().trim().slice(0, 500);
  if (!photoId || !text) return res.status(400).json({ error: 'photoId and a comment body are required.' });
  if (containsMaliciousContent(text)) return res.status(400).json({ error: 'Comments cannot contain links or external URLs.' });

  const ip = clientIp(req);
  const ipHash = hashIp(ip);
  if (await isBadIp(ip)) return res.status(403).json({ error: 'Comments are disabled on VPN/proxy connections.' });

  const { data: lastComment } = await supabase.from('comments')
    .select('created_at').eq('commenter_ip_hash', ipHash)
    .order('created_at', { ascending: false }).limit(1).maybeSingle();
  if (lastComment && Date.now() - new Date(lastComment.created_at).getTime() < COMMENT_COOLDOWN_SECONDS * 1000) {
    return res.status(429).json({ error: `Please wait ${COMMENT_COOLDOWN_SECONDS} seconds between comments.` });
  }

  const { count: onPhoto } = await supabase.from('comments')
    .select('*', { count: 'exact', head: true }).eq('photo_id', photoId).eq('commenter_ip_hash', ipHash);
  if ((onPhoto || 0) >= COMMENTS_PER_PHOTO_PER_IP) {
    return res.status(429).json({ error: `Max ${COMMENTS_PER_PHOTO_PER_IP} comments per photo.` });
  }

  const dayAgo = new Date(Date.now() - 24 * 3600 * 1000).toISOString();
  const { count: today } = await supabase.from('comments')
    .select('*', { count: 'exact', head: true }).eq('commenter_ip_hash', ipHash).gte('created_at', dayAgo);
  if ((today || 0) >= COMMENTS_PER_DAY_PER_IP) {
    return res.status(429).json({ error: 'Daily comment limit reached. Come back tomorrow.' });
  }

  // a reply must point at a top-level comment on the same photo
  let parent = null;
  if (parentId) {
    const { data: p } = await supabase.from('comments')
      .select('id, photo_id, parent_id').eq('id', parentId).maybeSingle();
    if (!p || p.photo_id !== photoId || p.parent_id) return res.status(400).json({ error: 'Invalid reply target.' });
    parent = p.id;
  }

  let authorName = null, isOp = false;
  if (opToken) {
    const { data: photo } = await supabase.from('photos').select('op_token, op_name').eq('id', photoId).maybeSingle();
    if (photo?.op_token && photo.op_token === opToken) { isOp = true; authorName = photo.op_name; }
  }

  const { data: comment, error } = await supabase.from('comments')
    .insert({ photo_id: photoId, commenter_ip_hash: ipHash, body: text, author_name: authorName, is_op: isOp, parent_id: parent })
    .select('id, body, author_name, is_op, created_at, parent_id').single();
  if (error) {
    console.error('[comment]', error);
    return res.status(500).json({ error: 'Comment failed.' });
  }
  res.json(comment);
}));

app.get('/api/photos/:id/comments', wrap(async (req, res) => {
  const { data, error } = await supabase.from('comments')
    .select('id, body, author_name, is_op, created_at, parent_id')
    .eq('photo_id', req.params.id).order('created_at', { ascending: true });
  if (error) return res.status(500).json({ error: 'Could not load comments.' });
  res.json(data || []);
}));

app.post('/api/tick', (req, res) => {
  // previously: if CRON_SECRET was unset, undefined === undefined let everyone in
  if (!process.env.CRON_SECRET || req.headers['x-cron-secret'] !== process.env.CRON_SECRET) {
    return res.status(401).json({ error: 'unauthorized' });
  }
  tick();
  res.json({ ok: true });
});

// ---------- admin ----------
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
if (!ADMIN_PASSWORD) console.warn('[warn] ADMIN_PASSWORD is not set — admin login is disabled.');
const sha = (s) => crypto.createHash('sha256').update(String(s)).digest();
const adminSessions = new Map(); // token -> expiry ms
const SESSION_MS = 12 * 3600 * 1000;

app.post('/api/admin/login', adminLoginLimiter, (req, res) => {
  if (!ADMIN_PASSWORD) return res.status(503).json({ error: 'Admin login is not configured (set ADMIN_PASSWORD).' });
  const { password } = req.body || {};
  if (typeof password === 'string' && crypto.timingSafeEqual(sha(password), sha(ADMIN_PASSWORD))) {
    const token = crypto.randomBytes(32).toString('hex');
    adminSessions.set(token, Date.now() + SESSION_MS);
    return res.json({ ok: true, token });
  }
  res.status(401).json({ error: 'Invalid admin password.' });
});

const requireAdmin = (req, res, next) => {
  const token = req.headers['x-admin-token'];
  const exp = token && adminSessions.get(token);
  if (exp && exp > Date.now()) return next();
  if (token) adminSessions.delete(token);
  res.status(401).json({ error: 'Unauthorized.' });
};

// Open this while logged in to confirm the server sees YOUR real public IP.
app.get('/api/admin/whoami', requireAdmin, (req, res) => {
  res.json({ detectedIp: clientIp(req), xForwardedFor: req.headers['x-forwarded-for'] || null, trustProxyHops: app.get('trust proxy') });
});

app.get('/api/admin/photos', requireAdmin, wrap(async (req, res) => {
  const { data, error } = await supabase.from('photos')
    .select('id, storage_path, caption, op_name, status, created_at')
    .order('created_at', { ascending: false }).limit(100);
  if (error) return res.status(500).json({ error: 'Failed to fetch photos' });
  res.json((data || []).map((p) => ({
    ...p,
    url: supabase.storage.from(BUCKET).getPublicUrl(p.storage_path).data.publicUrl,
  })));
}));

app.post('/api/admin/moderate-photo', requireAdmin, wrap(async (req, res) => {
  const { photoId, status } = req.body || {};
  if (!photoId || !['pending', 'live', 'archived', 'rejected'].includes(status)) {
    return res.status(400).json({ error: 'Invalid request.' });
  }
  const { error } = await supabase.from('photos').update({ status }).eq('id', photoId);
  if (error) return res.status(500).json({ error: 'Moderation failed.' });
  res.json({ ok: true });
  tick(); // if the on-screen photo was just rejected, replace it right away
}));

app.put('/api/admin/photos/:id', requireAdmin, wrap(async (req, res) => {
  const caption = ((req.body || {}).caption || '').toString().slice(0, 280);
  const { error } = await supabase.from('photos').update({ caption }).eq('id', req.params.id);
  if (error) return res.status(500).json({ error: 'Failed to update caption.' });
  res.json({ ok: true });
}));

app.delete('/api/admin/photos/:id', requireAdmin, wrap(async (req, res) => {
  const { data: photo } = await supabase.from('photos').select('storage_path').eq('id', req.params.id).maybeSingle();
  const { error } = await supabase.from('photos').delete().eq('id', req.params.id);
  if (error) return res.status(500).json({ error: 'Failed to delete photo.' });
  if (photo?.storage_path) await supabase.storage.from(BUCKET).remove([photo.storage_path]);
  res.json({ ok: true });
  tick();
}));

// Force skip. Old version set started_at = 1970, which made ALL likes count as
// "session" bonus time, so the photo got thousands of minutes and was never skipped.
app.post('/api/admin/skip', requireAdmin, wrap(async (req, res) => {
  await tick(true);
  res.json({ ok: true });
}));

app.delete('/api/admin/comments/:id', requireAdmin, wrap(async (req, res) => {
  const { error } = await supabase.from('comments').delete().eq('id', req.params.id);
  if (error) return res.status(500).json({ error: 'Failed to delete comment.' });
  res.json({ ok: true });
}));

// JSON error handler (so the frontend never gets an HTML error page)
app.use((err, req, res, next) => {
  console.error('[unhandled]', err);
  if (res.headersSent) return next(err);
  res.status(err.status || 500).json({ error: err.type === 'entity.too.large' ? 'Request too large.' : 'Server error.' });
});

// ---------- startup self-check: tells you exactly what's missing in Supabase ----------
async function checkSchema() {
  const checks = {
    photos: 'id, storage_path, caption, op_name, op_token, uploader_ip_hash, status, created_at',
    comments: 'id, photo_id, body, author_name, is_op, parent_id, commenter_ip_hash, created_at',
    likes: 'id, photo_id, liker_ip_hash, created_at',
    posters: 'ip_hash, name',
    display_state: 'id, photo_id, started_at',
    display_log: 'id, photo_id, shown_at',
  };
  for (const [table, cols] of Object.entries(checks)) {
    const { error } = await supabase.from(table).select(cols).limit(1);
    if (error) console.error(`[schema] PROBLEM with "${table}": ${error.message} -> re-run schema.sql in Supabase`);
  }
  const { error: bErr } = await supabase.storage.from(BUCKET).list('', { limit: 1 });
  if (bErr) console.error(`[schema] PROBLEM with storage bucket "${BUCKET}": ${bErr.message} -> create a PUBLIC bucket with that name`);
  const { error: rErr } = await supabase.rpc('pick_next_photo', { excl_hours: 0 });
  if (rErr) console.error(`[schema] PROBLEM with function pick_next_photo: ${rErr.message}`);
  console.log('[schema] check finished (no PROBLEM lines above = all good)');
}
checkSchema().catch((e) => console.error('[schema] check failed:', e.message));

// ---------- go ----------
tick();
setInterval(() => tick(), 5 * 1000);
app.listen(PORT, () => console.log(`photowall running on :${PORT}`));
