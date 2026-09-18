// Narezka API - minimal TikTok Login Kit + Content Posting API (Direct Post) app.
// Zero dependencies; requires Node 20+.
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// --- config (.env is optional; real env vars win) ---
try {
  for (const line of fs.readFileSync(path.join(__dirname, '.env'), 'utf8').split(/\r?\n/)) {
    const m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*)\s*$/);
    if (m && !line.trim().startsWith('#') && !(m[1] in process.env)) process.env[m[1]] = m[2];
  }
} catch {}
const CLIENT_KEY = process.env.TIKTOK_CLIENT_KEY || '';
const CLIENT_SECRET = process.env.TIKTOK_CLIENT_SECRET || '';
const PORT = Number(process.env.PORT || 3000);
const BASE_URL = (process.env.BASE_URL || `http://localhost:${PORT}`).replace(/\/$/, '');
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
const REDIRECT_URI = `${BASE_URL}/callback`;
const SCOPES = 'user.info.basic,video.publish,video.upload';
const MAX_VIDEO_BYTES = 64 * 1024 * 1024; // single-chunk upload limit used here
const UPLOAD_DIR = path.join(__dirname, 'uploads');
fs.mkdirSync(UPLOAD_DIR, { recursive: true });

const API = 'https://open.tiktokapis.com';
const sessions = new Map(); // sid -> { state, token, openId, user, videos: Map }

// --- helpers ---
const MIME = { '.html': 'text/html; charset=utf-8', '.png': 'image/png', '.txt': 'text/plain; charset=utf-8', '.css': 'text/css', '.js': 'text/javascript' };
const sign = (v) => crypto.createHmac('sha256', SESSION_SECRET).update(v).digest('hex').slice(0, 24);
function getSession(req, res) {
  const raw = Object.fromEntries((req.headers.cookie || '').split(/;\s*/).filter(Boolean).map((c) => c.split('=')));
  const [id, sig] = (raw.sid || '').split('.');
  let sid = id && sig === sign(id) ? id : null;
  if (!sid || !sessions.has(sid)) {
    sid = crypto.randomBytes(16).toString('hex');
    sessions.set(sid, { videos: new Map() });
    const secure = BASE_URL.startsWith('https') ? '; Secure' : '';
    res.setHeader('Set-Cookie', `sid=${sid}.${sign(sid)}; HttpOnly; SameSite=Lax; Path=/${secure}`);
  }
  return sessions.get(sid);
}
const json = (res, code, obj) => { res.writeHead(code, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(obj)); };
const readBody = (req) => new Promise((ok, fail) => { const b = []; req.on('data', (c) => b.push(c)); req.on('end', () => ok(Buffer.concat(b).toString())); req.on('error', fail); });
async function tiktok(pathname, token, body) {
  const r = await fetch(API + pathname, {
    method: body === undefined ? 'GET' : 'POST',
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json; charset=UTF-8' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  return r.json();
}
const need = (s, res) => (s.token ? true : (json(res, 401, { error: 'not_logged_in' }), false));

// --- routes ---
async function handle(req, res) {
  const url = new URL(req.url, BASE_URL);
  const s = getSession(req, res);

  if (url.pathname === '/login') {
    if (!CLIENT_KEY) { res.writeHead(500); return res.end('TIKTOK_CLIENT_KEY is not set'); }
    s.state = crypto.randomBytes(16).toString('hex');
    const q = new URLSearchParams({ client_key: CLIENT_KEY, scope: SCOPES, response_type: 'code', redirect_uri: REDIRECT_URI, state: s.state });
    res.writeHead(302, { Location: `https://www.tiktok.com/v2/auth/authorize/?${q}` });
    return res.end();
  }

  if (url.pathname === '/callback') {
    const code = url.searchParams.get('code');
    if (url.searchParams.get('error') || !code || url.searchParams.get('state') !== s.state) {
      res.writeHead(302, { Location: '/app.html?error=login_failed' }); return res.end();
    }
    const r = await fetch(`${API}/v2/oauth/token/`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ client_key: CLIENT_KEY, client_secret: CLIENT_SECRET, code, grant_type: 'authorization_code', redirect_uri: REDIRECT_URI }),
    });
    const t = await r.json();
    if (!t.access_token) { res.writeHead(302, { Location: '/app.html?error=token_failed' }); return res.end(); }
    s.token = t.access_token; s.openId = t.open_id;
    const u = await tiktok('/v2/user/info/?fields=open_id,avatar_url,display_name', s.token);
    s.user = u.data?.user || {};
    res.writeHead(302, { Location: '/app.html' }); return res.end();
  }

  if (url.pathname === '/logout') { s.token = s.user = s.openId = null; res.writeHead(302, { Location: '/app.html' }); return res.end(); }

  if (url.pathname === '/api/me') return json(res, 200, s.token ? { loggedIn: true, user: s.user } : { loggedIn: false });

  // Required by Direct Post UX: the creator's allowed options (privacy levels, interaction toggles, max duration).
  if (url.pathname === '/api/creator-info') {
    if (!need(s, res)) return;
    return json(res, 200, await tiktok('/v2/post/publish/creator_info/query/', s.token, {}));
  }

  // Raw video upload from the browser to this server (stored temporarily, deleted after publishing).
  if (url.pathname === '/api/upload' && req.method === 'POST') {
    if (!need(s, res)) return;
    const len = Number(req.headers['content-length'] || 0);
    if (!len || len > MAX_VIDEO_BYTES) return json(res, 413, { error: 'video_too_large_or_empty', max_mb: 64 });
    const id = crypto.randomBytes(8).toString('hex');
    const file = path.join(UPLOAD_DIR, id + '.mp4');
    await new Promise((ok, fail) => { const w = fs.createWriteStream(file); req.pipe(w); w.on('finish', ok); w.on('error', fail); });
    s.videos.set(id, { file, size: fs.statSync(file).size });
    return json(res, 200, { id, size: s.videos.get(id).size });
  }
  if (url.pathname.startsWith('/api/video/')) { // preview of the uploaded video
    const v = s.videos.get(url.pathname.split('/').pop());
    if (!v) { res.writeHead(404); return res.end(); }
    res.writeHead(200, { 'Content-Type': 'video/mp4', 'Content-Length': v.size });
    return fs.createReadStream(v.file).pipe(res);
  }

  if (url.pathname === '/api/publish' && req.method === 'POST') {
    if (!need(s, res)) return;
    const b = JSON.parse((await readBody(req)) || '{}');
    const v = s.videos.get(b.videoId);
    if (!v) return json(res, 400, { error: 'unknown_video' });
    if (!b.consent) return json(res, 400, { error: 'consent_required' });
    const post_info = {
      title: String(b.title || '').slice(0, 2200),
      privacy_level: b.privacy,
      disable_comment: !!b.disableComment,
      disable_duet: !!b.disableDuet,
      disable_stitch: !!b.disableStitch,
      brand_content_toggle: !!b.brandContent,
      brand_organic_toggle: !!b.brandOrganic,
    };
    const init = await tiktok('/v2/post/publish/video/init/', s.token, {
      post_info,
      source_info: { source: 'FILE_UPLOAD', video_size: v.size, chunk_size: v.size, total_chunk_count: 1 },
    });
    if (init.error?.code !== 'ok') return json(res, 400, init);
    const up = await fetch(init.data.upload_url, {
      method: 'PUT',
      headers: { 'Content-Type': 'video/mp4', 'Content-Length': String(v.size), 'Content-Range': `bytes 0-${v.size - 1}/${v.size}` },
      body: fs.readFileSync(v.file),
    });
    fs.rm(v.file, () => {}); s.videos.delete(b.videoId);
    return json(res, up.ok ? 200 : 502, { publish_id: init.data.publish_id, upload_status: up.status });
  }

  if (url.pathname === '/api/status') {
    if (!need(s, res)) return;
    return json(res, 200, await tiktok('/v2/post/publish/status/fetch/', s.token, { publish_id: url.searchParams.get('publish_id') }));
  }

  // static files
  const p = url.pathname === '/' ? '/index.html' : url.pathname;
  const root = path.join(__dirname, 'public');
  const file = path.join(root, path.normalize(p));
  if (!file.startsWith(root) || !fs.existsSync(file) || fs.statSync(file).isDirectory()) { res.writeHead(404); return res.end('Not found'); }
  res.writeHead(200, { 'Content-Type': MIME[path.extname(file)] || 'application/octet-stream' });
  fs.createReadStream(file).pipe(res);
}

http.createServer((req, res) => handle(req, res).catch((e) => { console.error(e); if (!res.headersSent) json(res, 500, { error: 'server_error' }); }))
  .listen(PORT, () => console.log(`Narezka API on ${BASE_URL} (redirect URI: ${REDIRECT_URI})`));
