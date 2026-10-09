const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const { handle } = require('../server.js');

const SB = 'https://sb.example.test';
function env() {
  process.env.SUPABASE_URL = SB; process.env.SUPABASE_ANON_KEY = 'anon'; process.env.SUPABASE_SERVICE_ROLE_KEY = 'service';
  process.env.EDITOR_SITE_ORIGIN = 'https://site.example.test';
}
function start() {
  return new Promise((resolve) => {
    const srv = http.createServer((req, res) => { handle(req, res).catch(() => { res.statusCode = 500; res.end('x'); }); });
    srv.listen(0, '127.0.0.1', () => resolve(srv));
  });
}
/* Fake Supabase; everything aimed at the local test server passes straight through. */
function fakeSupabase(role) {
  const real = global.fetch;
  global.fetch = async (url, opts) => {
    url = String(url);
    if (url.startsWith('http://127.0.0.1')) return real(url, opts);
    let r;
    if (url.startsWith(SB + '/auth/v1/token')) {
      const b = JSON.parse(opts.body);
      r = b.password === 'right' ? { status: 200, json: { access_token: 'tok', refresh_token: 'ref', expires_in: 3600 } } : { status: 400, json: {} };
    } else if (url.startsWith(SB + '/auth/v1/user')) r = { status: 200, json: { id: 'u1', email: 'owner@example.test' } };
    else if (url.startsWith(SB + '/rest/v1/profiles')) r = { status: 200, json: [{ id: 'u1', role }] };
    else r = { status: 500, json: {} };
    return { ok: r.status < 300, status: r.status, json: async () => r.json, text: async () => '' };
  };
  return () => { global.fetch = real; };
}
const url = (srv, p) => 'http://127.0.0.1:' + srv.address().port + p;
const post = (srv, p, body, headers) => fetch(url(srv, p), { method: 'POST', headers: Object.assign({ 'Content-Type': 'application/json' }, headers || {}), body: JSON.stringify(body) });
const cookieOf = (r) => (r.headers.get('set-cookie') || '').split(';')[0];

test('anonymous visitors get the login page, never the editor', async () => {
  env(); const srv = await start();
  try {
    const page = await fetch(url(srv, '/'));
    const html = await page.text();
    assert.equal(page.status, 200);
    assert.match(html, /دخول المالكة/);
    assert.doesNotMatch(html, /Élan Scents · محرر/);
    assert.equal(page.headers.get('cache-control'), 'no-store');
    for (const p of ['/editor/elan-editor.html', '/elan-editor.html', '/elan-host-bridge.js', '/session-guard.js', '/server.js', '/..%2Fserver.js', '/api/_auth.js', '/package.json']) {
      assert.equal((await fetch(url(srv, p))).status, 404, p);
    }
  } finally { srv.close(); }
});

test('the editor API and session check refuse anonymous callers', async () => {
  env(); const srv = await start();
  try {
    assert.equal((await fetch(url(srv, '/api/editor'))).status, 401);
    assert.equal((await post(srv, '/api/editor', { action: 'save' })).status, 401);
    assert.equal((await fetch(url(srv, '/api/session'))).status, 401);
  } finally { srv.close(); }
});

test('wrong password, and non-admin accounts, cannot log in', async () => {
  env(); const srv = await start();
  let restore = fakeSupabase('platform_admin');
  try {
    assert.equal((await post(srv, '/api/login', { email: 'a@b.c', password: 'wrong' })).status, 401);
    restore(); restore = fakeSupabase('customer');
    const r = await post(srv, '/api/login', { email: 'a@b.c', password: 'right' });
    assert.equal(r.status, 403);
    assert.equal(r.headers.get('set-cookie'), null);
  } finally { restore(); srv.close(); }
});

test('admin login gives a session cookie, the original editor page, and logout ends it', async () => {
  env(); const srv = await start(); const restore = fakeSupabase('platform_admin');
  try {
    const r = await post(srv, '/api/login', { email: 'owner@example.test', password: 'right' });
    assert.equal(r.status, 200);
    const setCookie = r.headers.get('set-cookie');
    assert.match(setCookie, /HttpOnly/); assert.match(setCookie, /SameSite=Strict/);
    assert.doesNotMatch(setCookie, /Max-Age|Expires/, 'must be a browser-session cookie (no remember me)');
    const cookie = cookieOf(r);

    const page = await fetch(url(srv, '/'), { headers: { cookie } });
    const html = await page.text();
    assert.match(html, /Élan Scents · محرر تجريبي جديد/);
    assert.match(html, /site\.example\.test/);
    assert.doesNotMatch(html, /elan-scents\.vercel\.app/);
    const csp = page.headers.get('content-security-policy');
    assert.match(csp, /frame-src https:\/\/site\.example\.test/);
    assert.match(csp, /frame-ancestors 'none'/);
    assert.doesNotMatch(csp, /unsafe-eval|script-src[^;]*'unsafe-inline'/);
    assert.equal((await fetch(url(srv, '/api/session'), { headers: { cookie } })).status, 200);
    assert.equal((await fetch(url(srv, '/session-guard.js'), { headers: { cookie } })).status, 200);

    assert.equal((await post(srv, '/api/logout', {}, { cookie })).status, 200);
    assert.equal((await fetch(url(srv, '/api/session'), { headers: { cookie } })).status, 401);
    assert.match(await (await fetch(url(srv, '/'), { headers: { cookie } })).text(), /دخول المالكة/);
  } finally { restore(); srv.close(); }
});

test('cross-site posts are refused', async () => {
  env(); const srv = await start(); const restore = fakeSupabase('platform_admin');
  try {
    const r = await post(srv, '/api/login', { email: 'a@b.c', password: 'right' }, { Origin: 'https://evil.example' });
    assert.equal(r.status, 403);
  } finally { restore(); srv.close(); }
});
