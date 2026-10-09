/* Élan Editor — Node server for Railway. No dependencies.
   "/" shows the login page; after an admin login it serves the original editor page.
   The editor page is never a public file: it is only sent to a valid admin session. */
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const editor = require('./api/editor.js');
const sessions = require('./session.js');

const PUBLIC = path.join(__dirname, 'public');
const EDITOR_DIR = path.join(__dirname, 'editor');
const COOKIE = 'elan_sess';
const TYPES = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.svg': 'image/svg+xml', '.png': 'image/png', '.ico': 'image/x-icon' };
const DEFAULT_PLATFORM = 'https://elan-scents.vercel.app/';

function sha(s) { return "'sha256-" + crypto.createHash('sha256').update(s, 'utf8').digest('base64') + "'"; }

/* Build the editor page once: point it at the configured site and allow only its own inline code. */
function buildEditorPage() {
  const origin = (process.env.EDITOR_SITE_ORIGIN || '').replace(/\/+$/, '');
  let html = fs.readFileSync(path.join(EDITOR_DIR, 'elan-editor.html'), 'utf8');
  if (origin) html = html.split(DEFAULT_PLATFORM).join(origin + '/');
  html = html.replace('</body>', '<script src="/session-guard.js"></script></body>');
  const hashes = [];
  html.replace(/<script>([\s\S]*?)<\/script>/g, (_, code) => { hashes.push(sha(code)); return ''; });
  const handlers = [];
  html.replace(/\son[a-z]+="([^"]*)"/g, (_, code) => { handlers.push(sha(code.replace(/&quot;/g, '"').replace(/&#39;/g, "'"))); return ''; });
  const csp = [
    "default-src 'self'",
    "script-src 'self' " + hashes.join(' ') + (handlers.length ? " 'unsafe-hashes' " + handlers.join(' ') : ''),
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
    "font-src 'self' https://fonts.gstatic.com data:",
    "img-src 'self' data: blob: https:",
    "media-src 'self' blob: https:",
    "connect-src 'self'",
    "frame-src " + (origin || "'none'"),
    "frame-ancestors 'none'", "base-uri 'none'", "form-action 'self'", "object-src 'none'"
  ].join('; ');
  return { html, csp };
}
let EDITOR_PAGE = null;

function baseHeaders(res) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Cache-Control', 'no-store');
}
function loginCsp(res) {
  res.setHeader('Content-Security-Policy', "default-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'");
}

function send(res, status, body, type) { res.statusCode = status; if (type) res.setHeader('Content-Type', type); res.end(body); }
function wrap(res) {
  res.status = (c) => { res.statusCode = c; return res; };
  res.json = (b) => { if (!res.getHeader('Content-Type')) res.setHeader('Content-Type', 'application/json; charset=utf-8'); res.end(JSON.stringify(b)); return res; };
  return res;
}
function readBody(req) {
  return new Promise((resolve) => {
    let size = 0; const chunks = [];
    req.on('data', (c) => { size += c.length; if (size > 400000) { resolve(null); req.destroy(); } else chunks.push(c); });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', () => resolve(null));
  });
}
function secure(req) { return (req.headers['x-forwarded-proto'] || '') === 'https' || process.env.NODE_ENV === 'production'; }
function setCookie(req, res, value, clear) {
  const parts = [COOKIE + '=' + value, 'Path=/', 'HttpOnly', 'SameSite=Strict'];
  if (secure(req)) parts.push('Secure');
  if (clear) parts.push('Max-Age=0'); // a session cookie otherwise: gone when the browser closes
  res.setHeader('Set-Cookie', parts.join('; '));
}
/* Browsers always send Origin on cross-site POSTs; refuse any POST whose Origin is not this host. */
function sameOrigin(req) {
  const o = req.headers.origin;
  if (!o) return true;
  try { return new URL(o).host === (req.headers['x-forwarded-host'] || req.headers.host); } catch (_) { return false; }
}
function clientIp(req) { return String(req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim() || 'unknown'; }

async function handle(req, res) {
  baseHeaders(res); wrap(res);
  const url = new URL(req.url, 'http://localhost');
  let pathname;
  try { pathname = decodeURIComponent(url.pathname); } catch (_) { return send(res, 400, 'bad request', 'text/plain'); }

  if (pathname === '/health') return send(res, 200, 'ok', 'text/plain');
  const sid = sessions.parseCookie(req.headers.cookie, COOKIE);

  if (pathname === '/api/login') {
    if (req.method !== 'POST') return res.status(405).json({ ok: false, error: 'method_not_allowed' });
    if (!sameOrigin(req)) return res.status(403).json({ ok: false, error: 'forbidden' });
    const raw = await readBody(req); let body = null;
    try { body = JSON.parse(raw || ''); } catch (_) { /* invalid */ }
    if (!body || typeof body !== 'object') return res.status(400).json({ ok: false, error: 'invalid_request' });
    const r = await sessions.login(body.email, body.password, clientIp(req));
    if (r.error) return res.status(r.status).json({ ok: false, error: r.error });
    setCookie(req, res, r.id, false);
    return res.status(200).json({ ok: true });
  }
  if (pathname === '/api/logout') {
    if (req.method !== 'POST' || !sameOrigin(req)) return res.status(403).json({ ok: false, error: 'forbidden' });
    sessions.destroy(sid); setCookie(req, res, '', true);
    return res.status(200).json({ ok: true });
  }
  if (pathname === '/api/session') {
    const s = await sessions.get(sid);
    return s ? res.status(200).json({ ok: true }) : res.status(401).json({ ok: false, error: 'unauthorized' });
  }

  if (pathname === '/api/editor') {
    if (req.method === 'POST' && !sameOrigin(req)) return res.status(403).json({ ok: false, error: 'forbidden' });
    const s = await sessions.get(sid);
    if (!s) return res.status(401).json({ ok: false, error: 'unauthorized' });
    req.headers.authorization = 'Bearer ' + s.token; // the browser never holds the Supabase token
    req.query = Object.fromEntries(url.searchParams);
    if (req.method === 'POST') {
      const raw = await readBody(req);
      if (raw === null) return res.status(413).json({ ok: false, error: 'invalid_request' });
      req.body = raw;
    }
    return editor(req, res);
  }

  if (req.method !== 'GET' && req.method !== 'HEAD') return send(res, 405, 'method not allowed', 'text/plain');

  if (pathname === '/' || pathname === '/index.html') {
    const s = await sessions.get(sid);
    if (s) {
      EDITOR_PAGE = EDITOR_PAGE || buildEditorPage();
      res.setHeader('Content-Security-Policy', EDITOR_PAGE.csp);
      return send(res, 200, req.method === 'HEAD' ? '' : EDITOR_PAGE.html, TYPES['.html']);
    }
    pathname = '/login.html';
  }
  // Only login assets and the session guard are public; the editor page and bridge library are not.
  const PUBLIC_FILES = new Set(['/login.html', '/login.js', '/login.css', '/session-guard.js']);
  if (!PUBLIC_FILES.has(pathname)) return send(res, 404, 'not found', 'text/plain');
  if (pathname === '/session-guard.js' && !(await sessions.get(sid))) return send(res, 404, 'not found', 'text/plain');
  if (pathname !== '/session-guard.js') loginCsp(res);
  fs.readFile(path.join(PUBLIC, pathname), (err, data) => {
    if (err) return send(res, 404, 'not found', 'text/plain');
    send(res, 200, data, TYPES[path.extname(pathname)] || 'application/octet-stream');
  });
}

if (require.main === module) {
  const port = Number(process.env.PORT) || 3000;
  http.createServer((req, res) => { handle(req, res).catch(() => { if (!res.headersSent) send(res, 500, 'error', 'text/plain'); }); })
    .listen(port, '0.0.0.0', () => console.log('elan-editor listening on ' + port));
}

module.exports = { handle, buildEditorPage };
