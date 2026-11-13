'use strict';
/* Tamweel Shares — zero-dependency Node server (Node >= 22.5) with SQLite storage.
   Money is stored as integer cents. Passwords use scrypt. Sessions are random tokens
   (stored hashed) in an HttpOnly cookie. */
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { DatabaseSync } = require('node:sqlite');

const PORT = Number(process.env.PORT) || 3000;
const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'data', 'tamweel.db');
const PROD = process.env.NODE_ENV === 'production';
const TRUST_PROXY = process.env.TRUST_PROXY === '1';
const SESSION_DAYS = 7;

fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
const db = new DatabaseSync(DB_PATH);
db.exec(`
PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY, name TEXT NOT NULL, email TEXT NOT NULL UNIQUE,
  pass_hash TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN('investor','owner')), created INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS sessions(
  token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, expires INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS projects(
  id INTEGER PRIMARY KEY, owner_id INTEGER NOT NULL REFERENCES users(id), title TEXT NOT NULL, category TEXT NOT NULL,
  description TEXT NOT NULL, share_price_cents INTEGER NOT NULL CHECK(share_price_cents>0),
  total_shares INTEGER NOT NULL CHECK(total_shares>0), created INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS investments(
  id INTEGER PRIMARY KEY, project_id INTEGER NOT NULL REFERENCES projects(id), user_id INTEGER NOT NULL REFERENCES users(id),
  shares INTEGER NOT NULL CHECK(shares>0), amount_cents INTEGER NOT NULL, created INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS payouts(
  id INTEGER PRIMARY KEY, project_id INTEGER NOT NULL REFERENCES projects(id), amount_cents INTEGER NOT NULL CHECK(amount_cents>0),
  note TEXT NOT NULL, created INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS wallet_tx(
  id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id),
  type TEXT NOT NULL CHECK(type IN('deposit','invest','income','withdraw')),
  amount_cents INTEGER NOT NULL, project_id INTEGER REFERENCES projects(id), note TEXT, created INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS idx_inv_project ON investments(project_id);
CREATE INDEX IF NOT EXISTS idx_inv_user ON investments(user_id);
CREATE INDEX IF NOT EXISTS idx_tx_user ON wallet_tx(user_id);
`);

/* ---------- helpers ---------- */
class HttpError extends Error { constructor(status, code) { super(code); this.status = status; this.code = code; } }
const bad = (code = 'bad_input') => new HttpError(400, code);
function tx(fn) {
  db.exec('BEGIN IMMEDIATE');
  try { const r = fn(); db.exec('COMMIT'); return r; }
  catch (e) { db.exec('ROLLBACK'); throw e; }
}
const now = () => Date.now();
const sha = s => crypto.createHash('sha256').update(s).digest('hex');
const dollars = c => c / 100;

function hashPassword(pw) {
  const salt = crypto.randomBytes(16);
  const key = crypto.scryptSync(pw, salt, 64, { N: 16384, r: 8, p: 1 });
  return `scrypt$${salt.toString('hex')}$${key.toString('hex')}`;
}
function verifyPassword(pw, stored) {
  const [alg, saltHex, keyHex] = String(stored).split('$');
  if (alg !== 'scrypt') return false;
  const key = crypto.scryptSync(pw, Buffer.from(saltHex, 'hex'), 64, { N: 16384, r: 8, p: 1 });
  const exp = Buffer.from(keyHex, 'hex');
  return exp.length === key.length && crypto.timingSafeEqual(exp, key);
}
const DUMMY_HASH = hashPassword('dummy-password-for-timing');

/* input validation */
function str(v, min, max) {
  if (typeof v !== 'string') throw bad();
  const s = v.trim();
  if (s.length < min || s.length > max) throw bad();
  return s;
}
function cents(v, { min = 0.01, max = 10_000_000 } = {}) {
  const n = typeof v === 'string' ? Number(v) : v;
  if (typeof n !== 'number' || !Number.isFinite(n) || n < min || n > max) throw bad();
  return Math.round(n * 100);
}
function int(v, min, max) {
  const n = typeof v === 'string' ? Number(v) : v;
  if (!Number.isInteger(n) || n < min || n > max) throw bad();
  return n;
}
const CATS = ['agri', 'food', 'energy', 'real', 'tech', 'retail', 'other'];
const EMAIL_RE = /^[^\s@]{1,64}@[^\s@]{1,255}\.[^\s@]{2,}$/;

/* rate limiting (in memory) */
const hits = new Map();
function limit(key, max, windowMs) {
  const t = now(); let h = hits.get(key);
  if (!h || h.reset < t) { h = { n: 0, reset: t + windowMs }; hits.set(key, h); }
  if (++h.n > max) throw new HttpError(429, 'rate_limited');
}
setInterval(() => { const t = now(); for (const [k, v] of hits) if (v.reset < t) hits.delete(k); }, 60_000).unref();

/* sessions */
function cookieFlags(req) {
  const secure = PROD || req.headers['x-forwarded-proto'] === 'https';
  return `Path=/; HttpOnly; SameSite=Lax${secure ? '; Secure' : ''}`;
}
function startSession(req, res, userId) {
  const token = crypto.randomBytes(32).toString('hex');
  const exp = now() + SESSION_DAYS * 864e5;
  db.prepare('DELETE FROM sessions WHERE expires<?').run(now());
  db.prepare('INSERT INTO sessions(token_hash,user_id,expires) VALUES(?,?,?)').run(sha(token), userId, exp);
  res.setHeader('Set-Cookie', `tw_sid=${token}; Max-Age=${SESSION_DAYS * 86400}; ${cookieFlags(req)}`);
}
function getCookie(req, name) {
  for (const part of (req.headers.cookie || '').split(';')) {
    const i = part.indexOf('=');
    if (i > 0 && part.slice(0, i).trim() === name) return part.slice(i + 1).trim();
  }
  return null;
}
function currentUser(req) {
  const tok = getCookie(req, 'tw_sid');
  if (!tok || !/^[0-9a-f]{64}$/.test(tok)) return null;
  return db.prepare(`SELECT u.id,u.name,u.email,u.role FROM sessions s JOIN users u ON u.id=s.user_id
    WHERE s.token_hash=? AND s.expires>?`).get(sha(tok), now()) || null;
}
function requireUser(req, role) {
  const u = currentUser(req);
  if (!u) throw new HttpError(401, 'unauth');
  if (role && u.role !== role) throw new HttpError(403, 'forbidden');
  return u;
}
const balanceCents = uid => db.prepare('SELECT COALESCE(SUM(amount_cents),0) b FROM wallet_tx WHERE user_id=?').get(uid).b;

/* ---------- domain logic ---------- */
const PROJECT_SELECT = `SELECT p.id,p.title,p.category,p.description,p.share_price_cents,p.total_shares,p.created,p.owner_id,
  u.name owner_name, COALESCE((SELECT SUM(shares) FROM investments WHERE project_id=p.id),0) sold
  FROM projects p JOIN users u ON u.id=p.owner_id`;
const projectOut = p => ({
  id: p.id, title: p.title, category: p.category, description: p.description, owner: p.owner_name,
  sharePrice: dollars(p.share_price_cents), totalShares: p.total_shares, sold: p.sold,
  goal: dollars(p.share_price_cents * p.total_shares), raised: dollars(p.share_price_cents * p.sold), created: p.created
});

function signup(b) {
  const name = str(b.name, 2, 80), email = str(b.email, 3, 320).toLowerCase();
  const password = str(b.password, 8, 200);
  if (!EMAIL_RE.test(email)) throw bad();
  if (!['investor', 'owner'].includes(b.role)) throw bad();
  if (db.prepare('SELECT 1 FROM users WHERE email=?').get(email)) throw bad('email_used');
  const r = db.prepare('INSERT INTO users(name,email,pass_hash,role,created) VALUES(?,?,?,?,?)')
    .run(name, email, hashPassword(password), b.role, now());
  return Number(r.lastInsertRowid);
}
function createProject(owner, b) {
  const title = str(b.title, 3, 120), description = str(b.description, 10, 3000);
  if (!CATS.includes(b.category)) throw bad();
  const price = cents(b.sharePrice, { min: 1, max: 1_000_000 });
  const goal = cents(b.goal, { min: 100, max: 100_000_000 });
  const total = Math.floor(goal / price);
  if (total < 1 || total > 1_000_000) throw bad();
  const r = db.prepare('INSERT INTO projects(owner_id,title,category,description,share_price_cents,total_shares,created) VALUES(?,?,?,?,?,?,?)')
    .run(owner.id, title, b.category, description, price, total, now());
  return Number(r.lastInsertRowid);
}
function buyShares(user, projectId, shares) {
  return tx(() => {
    const p = db.prepare(PROJECT_SELECT + ' WHERE p.id=?').get(projectId);
    if (!p) throw new HttpError(404, 'not_found');
    if (shares > p.total_shares - p.sold) throw bad('not_enough_shares');
    const cost = shares * p.share_price_cents;
    if (balanceCents(user.id) < cost) throw bad('no_funds');
    const t = now();
    db.prepare('INSERT INTO investments(project_id,user_id,shares,amount_cents,created) VALUES(?,?,?,?,?)').run(p.id, user.id, shares, cost, t);
    db.prepare('INSERT INTO wallet_tx(user_id,type,amount_cents,project_id,note,created) VALUES(?,?,?,?,?,?)').run(user.id, 'invest', -cost, p.id, null, t);
    return balanceCents(user.id);
  });
}
function distributePayout(owner, projectId, amountCents, note) {
  return tx(() => {
    const p = db.prepare(PROJECT_SELECT + ' WHERE p.id=?').get(projectId);
    if (!p || p.owner_id !== owner.id) throw new HttpError(404, 'not_found');
    const holders = db.prepare('SELECT user_id, SUM(shares) sh FROM investments WHERE project_id=? GROUP BY user_id ORDER BY sh DESC, user_id').all(p.id);
    if (!holders.length) throw bad('no_investors');
    const t = now();
    db.prepare('INSERT INTO payouts(project_id,amount_cents,note,created) VALUES(?,?,?,?)').run(p.id, amountCents, note, t);
    let given = 0;
    holders.forEach(h => { h.c = Math.floor(amountCents * h.sh / p.sold); given += h.c; });
    holders[0].c += amountCents - given; // rounding remainder goes to the largest holder
    const ins = db.prepare('INSERT INTO wallet_tx(user_id,type,amount_cents,project_id,note,created) VALUES(?,?,?,?,?,?)');
    for (const h of holders) if (h.c > 0) ins.run(h.user_id, 'income', h.c, p.id, note, t);
    return holders.length;
  });
}
function withdraw(user, amountCents, dest) {
  return tx(() => {
    if (balanceCents(user.id) < amountCents) throw bad('no_funds');
    db.prepare('INSERT INTO wallet_tx(user_id,type,amount_cents,project_id,note,created) VALUES(?,?,?,?,?,?)')
      .run(user.id, 'withdraw', -amountCents, null, dest, now());
    return balanceCents(user.id);
  });
}
function deposit(user, amountCents) {
  db.prepare('INSERT INTO wallet_tx(user_id,type,amount_cents,project_id,note,created) VALUES(?,?,?,?,?,?)')
    .run(user.id, 'deposit', amountCents, null, null, now());
  return balanceCents(user.id);
}

function investorDashboard(u) {
  const holdings = db.prepare(`SELECT p.id,p.title,p.share_price_cents sp,p.total_shares ts,SUM(i.shares) sh
    FROM investments i JOIN projects p ON p.id=i.project_id WHERE i.user_id=? GROUP BY p.id ORDER BY p.id`).all(u.id);
  const inc = Object.fromEntries(db.prepare(`SELECT project_id pid,SUM(amount_cents) c FROM wallet_tx
    WHERE user_id=? AND type='income' GROUP BY project_id`).all(u.id).map(r => [r.pid, r.c]));
  const history = db.prepare(`SELECT t.id,t.type,t.amount_cents,t.note,t.created,p.title project FROM wallet_tx t
    LEFT JOIN projects p ON p.id=t.project_id WHERE t.user_id=? ORDER BY t.id DESC LIMIT 200`).all(u.id);
  return {
    balance: dollars(balanceCents(u.id)),
    holdings: holdings.map(h => ({ id: h.id, title: h.title, shares: h.sh, totalShares: h.ts,
      invested: dollars(h.sh * h.sp), income: dollars(inc[h.id] || 0) })),
    totalIncome: dollars(Object.values(inc).reduce((a, b) => a + b, 0)),
    history: history.map(h => ({ id: h.id, type: h.type, amount: dollars(h.amount_cents), note: h.note, project: h.project, date: h.created }))
  };
}
function ownerDashboard(u) {
  const projects = db.prepare(PROJECT_SELECT + ' WHERE p.owner_id=? ORDER BY p.id DESC').all(u.id);
  return projects.map(p => ({
    ...projectOut(p),
    investors: db.prepare(`SELECT u.name,SUM(i.shares) shares FROM investments i JOIN users u ON u.id=i.user_id
      WHERE i.project_id=? GROUP BY u.id ORDER BY shares DESC`).all(p.id)
      .map(r => ({ name: r.name, shares: r.shares, amount: dollars(r.shares * p.share_price_cents) })),
    payouts: db.prepare('SELECT amount_cents,note,created FROM payouts WHERE project_id=? ORDER BY id DESC').all(p.id)
      .map(r => ({ amount: dollars(r.amount_cents), note: r.note, date: r.created }))
  }));
}

/* ---------- routing ---------- */
const routes = [];
const route = (method, re, fn) => routes.push({ method, re, fn });

route('POST', /^\/api\/signup$/, (req, res, ctx) => {
  limit('auth:' + ctx.ip, 10, 15 * 60_000);
  const id = signup(ctx.body); startSession(req, res, id);
  return { ok: true };
});
route('POST', /^\/api\/login$/, (req, res, ctx) => {
  limit('auth:' + ctx.ip, 10, 15 * 60_000);
  const email = str(ctx.body.email, 3, 320).toLowerCase(), password = str(ctx.body.password, 1, 200);
  const u = db.prepare('SELECT id,pass_hash FROM users WHERE email=?').get(email);
  const ok = verifyPassword(password, u ? u.pass_hash : DUMMY_HASH) && u; // constant-ish time either way
  if (!ok) throw new HttpError(401, 'bad_login');
  startSession(req, res, u.id);
  return { ok: true };
});
route('POST', /^\/api\/logout$/, (req, res) => {
  const tok = getCookie(req, 'tw_sid');
  if (tok) db.prepare('DELETE FROM sessions WHERE token_hash=?').run(sha(tok));
  res.setHeader('Set-Cookie', `tw_sid=; Max-Age=0; ${cookieFlags(req)}`);
  return { ok: true };
});
route('GET', /^\/api\/me$/, req => {
  const u = currentUser(req);
  if (!u) return { user: null };
  return { user: { id: u.id, name: u.name, email: u.email, role: u.role, balance: u.role === 'investor' ? dollars(balanceCents(u.id)) : undefined } };
});
route('GET', /^\/api\/projects$/, () => db.prepare(PROJECT_SELECT + ' ORDER BY p.id DESC').all().map(projectOut));
route('GET', /^\/api\/projects\/(\d+)$/, (req, res, ctx) => {
  const p = db.prepare(PROJECT_SELECT + ' WHERE p.id=?').get(Number(ctx.m[1]));
  if (!p) throw new HttpError(404, 'not_found');
  return projectOut(p);
});
route('POST', /^\/api\/projects$/, (req, res, ctx) => {
  const u = requireUser(req, 'owner'); return { id: createProject(u, ctx.body) };
});
route('POST', /^\/api\/projects\/(\d+)\/buy$/, (req, res, ctx) => {
  const u = requireUser(req, 'investor');
  return { balance: dollars(buyShares(u, Number(ctx.m[1]), int(ctx.body.shares, 1, 1_000_000)) ) };
});
route('POST', /^\/api\/projects\/(\d+)\/payout$/, (req, res, ctx) => {
  const u = requireUser(req, 'owner');
  const note = ctx.body.note ? str(ctx.body.note, 0, 120) : '';
  return { investors: distributePayout(u, Number(ctx.m[1]), cents(ctx.body.amount), note) };
});
route('GET', /^\/api\/investor\/dashboard$/, req => investorDashboard(requireUser(req, 'investor')));
route('GET', /^\/api\/owner\/dashboard$/, req => ownerDashboard(requireUser(req, 'owner')));
route('POST', /^\/api\/wallet\/deposit$/, (req, res, ctx) => {
  const u = requireUser(req, 'investor'); // DEMO: no payment gateway — replace with a real provider before going live
  if (PROD && process.env.ALLOW_DEMO_DEPOSIT !== '1') throw new HttpError(403, 'forbidden');
  return { balance: dollars(deposit(u, cents(ctx.body.amount, { max: 100_000 }))) };
});
route('POST', /^\/api\/wallet\/withdraw$/, (req, res, ctx) => {
  const u = requireUser(req, 'investor');
  limit('wd:' + u.id, 10, 60 * 60_000);
  return { balance: dollars(withdraw(u, cents(ctx.body.amount), str(ctx.body.destination, 4, 100))) };
});

const INDEX = path.join(__dirname, 'public', 'index.html');
function securityHeaders(res) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'same-origin');
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Content-Security-Policy',
    "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'");
  if (PROD) res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
}
function readBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0; const chunks = [];
    req.on('data', c => { size += c.length; if (size > 10_000) { reject(new HttpError(413, 'too_large')); req.destroy(); } else chunks.push(c); });
    req.on('end', () => {
      if (!chunks.length) return resolve({});
      try { const b = JSON.parse(Buffer.concat(chunks).toString('utf8')); resolve(b && typeof b === 'object' && !Array.isArray(b) ? b : {}); }
      catch { reject(bad()); }
    });
    req.on('error', reject);
  });
}
function send(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Content-Length': Buffer.byteLength(body) });
  res.end(body);
}

const server = http.createServer(async (req, res) => {
  securityHeaders(res);
  try {
    const url = new URL(req.url, 'http://x');
    const ip = (TRUST_PROXY && String(req.headers['x-forwarded-for'] || '').split(',')[0].trim()) || req.socket.remoteAddress || '?';
    if (url.pathname.startsWith('/api/')) {
      const r = routes.find(r => r.method === req.method && r.re.test(url.pathname));
      if (!r) throw new HttpError(404, 'not_found');
      let body = {};
      if (req.method !== 'GET') {
        // JSON-only mutations: cross-site forms can't send this content type, and the cookie is SameSite=Lax
        if (!/^application\/json/i.test(req.headers['content-type'] || '') && Number(req.headers['content-length'] || 0) > 0) throw bad();
        body = await readBody(req);
      }
      return send(res, 200, r.fn(req, res, { body, ip, m: url.pathname.match(r.re) }));
    }
    if (req.method === 'GET' && (url.pathname === '/' || url.pathname === '/index.html')) {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      return fs.createReadStream(INDEX).pipe(res);
    }
    throw new HttpError(404, 'not_found');
  } catch (e) {
    if (e instanceof HttpError) return send(res, e.status, { error: e.code });
    console.error(e);
    send(res, 500, { error: 'server' });
  }
});

/* ---------- optional demo seed (local use only: SEED_DEMO=1) ---------- */
function seedDemo() {
  if (db.prepare('SELECT COUNT(*) c FROM users').get().c) return;
  const pw = process.env.DEMO_PASSWORD || 'demo12345';
  const owner = { id: signup({ name: 'صاحب مشروع تجريبي', email: 'owner@demo.com', password: pw, role: 'owner' }) };
  const inv = { id: signup({ name: 'مستثمر تجريبي', email: 'investor@demo.com', password: pw, role: 'investor' }) };
  createProject(owner, { title: 'مزرعة الوادي الأخضر للزيتون', category: 'agri', goal: 50000, sharePrice: 100,
    description: 'توسعة مزرعة الزيتون العائلية بمعصرة جديدة و٢٠٠٠ شجرة إضافية. يأتي الدخل من بيع زيت الزيتون الفاخر.' });
  createProject(owner, { title: 'محمصة قهوة المدينة', category: 'food', goal: 30000, sharePrice: 50,
    description: 'محمصة قهوة تزوّد ٣٠ مقهى في الحي. تُستخدم الأموال لشراء آلة تحميص ثانية وخط تغليف.' });
  createProject(owner, { title: 'ألواح شمسية لمدرسة النور', category: 'energy', goal: 80000, sharePrice: 200,
    description: 'تركيب ألواح شمسية على السطح وبيع فائض الكهرباء للشبكة. يُوزَّع الدخل من مبيعات الطاقة الشهرية.' });
  deposit(inv, 25000_00); buyShares(inv, 1, 120); buyShares(inv, 2, 80);
  distributePayout(owner, 1, 1200_00, 'مبيعات الزيت للربع الثالث');
  console.log('Seeded demo accounts: owner@demo.com / investor@demo.com');
}
if (process.env.SEED_DEMO === '1') seedDemo();

server.listen(PORT, () => console.log(`Tamweel Shares running on http://localhost:${PORT}`));
