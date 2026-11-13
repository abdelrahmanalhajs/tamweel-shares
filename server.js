'use strict';
/* Tamweel Shares — zero-dependency Node server (Node >= 22.5) with SQLite storage.
   Money is stored as integer cents. Passwords use scrypt. Sessions are random tokens
   (stored hashed) in an HttpOnly cookie. */
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { DatabaseSync } = require('node:sqlite');
const Analysis = require('./analysis.js');

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
  pass_hash TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN('investor','owner','admin')),
  totp_secret TEXT, totp_enabled INTEGER NOT NULL DEFAULT 0, risk_tolerance TEXT, experience TEXT,
  phone TEXT, national_id TEXT, company_name TEXT,
  kyc_status TEXT NOT NULL DEFAULT 'none' CHECK(kyc_status IN('none','pending','approved','rejected')), kyc_note TEXT,
  created INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS sessions(
  token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, expires INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS projects(
  id INTEGER PRIMARY KEY, owner_id INTEGER NOT NULL REFERENCES users(id), title TEXT NOT NULL, category TEXT NOT NULL,
  description TEXT NOT NULL, share_price_cents INTEGER NOT NULL CHECK(share_price_cents>0),
  total_shares INTEGER NOT NULL CHECK(total_shares>0), created INTEGER NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN('pending','approved','rejected')),
  risk TEXT NOT NULL DEFAULT 'unrated' CHECK(risk IN('unrated','low','medium','high')),
  location TEXT, founded_year INTEGER, branches INTEGER, employees INTEGER,
  monthly_sales_cents INTEGER, monthly_profit_cents INTEGER, duration_months INTEGER, expected_return REAL,
  min_shares INTEGER NOT NULL DEFAULT 1, use_of_funds TEXT, profit_terms TEXT, exit_terms TEXT,
  verification_note TEXT, admin_note TEXT);
CREATE TABLE IF NOT EXISTS documents(
  id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id), project_id INTEGER REFERENCES projects(id),
  kind TEXT NOT NULL, filename TEXT NOT NULL, path TEXT NOT NULL, mime TEXT NOT NULL, size INTEGER NOT NULL, created INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS investments(
  id INTEGER PRIMARY KEY, project_id INTEGER NOT NULL REFERENCES projects(id), user_id INTEGER NOT NULL REFERENCES users(id),
  shares INTEGER NOT NULL CHECK(shares>0), amount_cents INTEGER NOT NULL, created INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS payouts(
  id INTEGER PRIMARY KEY, project_id INTEGER NOT NULL REFERENCES projects(id), amount_cents INTEGER NOT NULL CHECK(amount_cents>0),
  note TEXT NOT NULL, created INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS wallet_tx(
  id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id),
  type TEXT NOT NULL CHECK(type IN('deposit','invest','income','withdraw','refund','sale','purchase')),
  amount_cents INTEGER NOT NULL, project_id INTEGER REFERENCES projects(id), note TEXT, created INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS withdrawals(
  id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id), tx_id INTEGER NOT NULL REFERENCES wallet_tx(id),
  amount_cents INTEGER NOT NULL, destination TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN('pending','paid','rejected')), created INTEGER NOT NULL, processed INTEGER);
CREATE TABLE IF NOT EXISTS audit(
  id INTEGER PRIMARY KEY, actor_id INTEGER, action TEXT NOT NULL, entity TEXT NOT NULL, entity_id INTEGER, detail TEXT, created INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS financials(
  project_id INTEGER NOT NULL REFERENCES projects(id), month TEXT NOT NULL,
  revenue INTEGER NOT NULL DEFAULT 0, cogs INTEGER NOT NULL DEFAULT 0, direct_exp INTEGER NOT NULL DEFAULT 0, indirect_exp INTEGER NOT NULL DEFAULT 0,
  payroll INTEGER NOT NULL DEFAULT 0, rent INTEGER NOT NULL DEFAULT 0, utilities INTEGER NOT NULL DEFAULT 0, commissions INTEGER NOT NULL DEFAULT 0,
  marketing INTEGER NOT NULL DEFAULT 0, other_exp INTEGER NOT NULL DEFAULT 0, debt_payments INTEGER NOT NULL DEFAULT 0, liabilities INTEGER NOT NULL DEFAULT 0,
  verified INTEGER NOT NULL DEFAULT 0, updated INTEGER NOT NULL, PRIMARY KEY(project_id, month));
CREATE TABLE IF NOT EXISTS contracts(
  id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id), project_id INTEGER NOT NULL REFERENCES projects(id),
  kind TEXT NOT NULL, shares INTEGER NOT NULL, amount_cents INTEGER NOT NULL, terms TEXT NOT NULL, signer TEXT NOT NULL,
  signed_ip TEXT, hash TEXT NOT NULL, created INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS reports(
  id INTEGER PRIMARY KEY, project_id INTEGER NOT NULL REFERENCES projects(id), month TEXT NOT NULL, summary TEXT NOT NULL,
  sales_cents INTEGER, expenses_cents INTEGER, challenges TEXT, next_plan TEXT, created INTEGER NOT NULL, UNIQUE(project_id, month));
CREATE TABLE IF NOT EXISTS notifications(
  id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id), type TEXT NOT NULL, project_id INTEGER, data TEXT,
  read INTEGER NOT NULL DEFAULT 0, created INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS idx_notif_user ON notifications(user_id, read);
CREATE TABLE IF NOT EXISTS posts(
  id INTEGER PRIMARY KEY, project_id INTEGER NOT NULL REFERENCES projects(id), user_id INTEGER NOT NULL REFERENCES users(id),
  kind TEXT NOT NULL CHECK(kind IN('question','answer','update')), parent_id INTEGER, body TEXT NOT NULL, created INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS polls(
  id INTEGER PRIMARY KEY, project_id INTEGER NOT NULL REFERENCES projects(id), question TEXT NOT NULL, options TEXT NOT NULL,
  closes INTEGER NOT NULL, created INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS votes(
  poll_id INTEGER NOT NULL REFERENCES polls(id), user_id INTEGER NOT NULL REFERENCES users(id), option_idx INTEGER NOT NULL, weight INTEGER NOT NULL,
  PRIMARY KEY(poll_id, user_id));
CREATE TABLE IF NOT EXISTS follows(
  user_id INTEGER NOT NULL REFERENCES users(id), project_id INTEGER NOT NULL REFERENCES projects(id), PRIMARY KEY(user_id, project_id));
CREATE TABLE IF NOT EXISTS exits(
  id INTEGER PRIMARY KEY, project_id INTEGER NOT NULL REFERENCES projects(id), seller_id INTEGER NOT NULL REFERENCES users(id),
  shares INTEGER NOT NULL CHECK(shares>0), price_cents INTEGER NOT NULL CHECK(price_cents>0),
  status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN('pending','open','sold','cancelled','rejected')),
  buyer_id INTEGER, created INTEGER NOT NULL, closed INTEGER);
CREATE TABLE IF NOT EXISTS complaints(
  id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id), project_id INTEGER, subject TEXT NOT NULL, body TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'open' CHECK(status IN('open','resolved')), reply TEXT, created INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS idx_inv_project ON investments(project_id);
CREATE INDEX IF NOT EXISTS idx_inv_user ON investments(user_id);
CREATE INDEX IF NOT EXISTS idx_tx_user ON wallet_tx(user_id);
CREATE INDEX IF NOT EXISTS idx_doc_project ON documents(project_id);
`);
const UPLOAD_DIR = path.join(path.dirname(DB_PATH), 'uploads');
fs.mkdirSync(UPLOAD_DIR, { recursive: true });

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
function audit(actorId, action, entity, entityId, detail) {
  db.prepare('INSERT INTO audit(actor_id,action,entity,entity_id,detail,created) VALUES(?,?,?,?,?,?)')
    .run(actorId ?? null, action, entity, entityId ?? null, detail ? JSON.stringify(detail) : null, now());
}
function notify(userId, type, projectId, data) {
  db.prepare('INSERT INTO notifications(user_id,type,project_id,data,created) VALUES(?,?,?,?,?)').run(userId, type, projectId ?? null, data ? JSON.stringify(data) : null, now());
}
const holdersOf = pid => db.prepare('SELECT DISTINCT user_id FROM investments WHERE project_id=?').all(pid).map(r => r.user_id);
const followersOf = pid => db.prepare('SELECT user_id FROM follows WHERE project_id=?').all(pid).map(r => r.user_id);
const audienceOf = pid => [...new Set([...holdersOf(pid), ...followersOf(pid)])];
const PROJECT_SELECT = `SELECT p.*, u.name owner_name, u.company_name owner_company,
  COALESCE((SELECT SUM(shares) FROM investments WHERE project_id=p.id),0) sold
  FROM projects p JOIN users u ON u.id=p.owner_id`;
const docOut = d => ({ id: d.id, kind: d.kind, filename: d.filename, size: d.size, created: d.created });
const docsOf = pid => db.prepare('SELECT * FROM documents WHERE project_id=? ORDER BY id').all(pid).map(docOut);
const orNull = v => (v === null || v === undefined ? null : v);
function projectOut(p, { private: priv = false } = {}) {
  const o = {
    id: p.id, title: p.title, category: p.category, description: p.description, owner: p.owner_company || p.owner_name, ownerId: p.owner_id,
    sharePrice: dollars(p.share_price_cents), totalShares: p.total_shares, sold: p.sold,
    goal: dollars(p.share_price_cents * p.total_shares), raised: dollars(p.share_price_cents * p.sold), created: p.created,
    status: p.status, risk: p.risk, location: p.location, foundedYear: p.founded_year, branches: p.branches, employees: p.employees,
    monthlySales: p.monthly_sales_cents == null ? null : dollars(p.monthly_sales_cents),
    monthlyProfit: p.monthly_profit_cents == null ? null : dollars(p.monthly_profit_cents),
    durationMonths: p.duration_months, expectedReturn: p.expected_return, minShares: p.min_shares,
    useOfFunds: p.use_of_funds, profitTerms: p.profit_terms, exitTerms: p.exit_terms, verificationNote: p.verification_note,
    verifiedDocs: db.prepare('SELECT DISTINCT kind FROM documents WHERE project_id=?').all(p.id).map(r => r.kind)
  };
  if (priv) { o.adminNote = p.admin_note; o.documents = docsOf(p.id); }
  return o;
}

function signup(b) {
  const name = str(b.name, 2, 80), email = str(b.email, 3, 320).toLowerCase();
  const password = str(b.password, 8, 200);
  const phone = b.phone ? str(b.phone, 6, 20) : null;
  if (phone && !/^\+?[0-9 ()-]{6,20}$/.test(phone)) throw bad();
  if (!EMAIL_RE.test(email)) throw bad();
  if (!['investor', 'owner'].includes(b.role)) throw bad();
  const company = b.role === 'owner' && b.company ? str(b.company, 2, 120) : null;
  if (db.prepare('SELECT 1 FROM users WHERE email=?').get(email)) throw bad('email_used');
  const r = db.prepare('INSERT INTO users(name,email,pass_hash,role,phone,company_name,created) VALUES(?,?,?,?,?,?,?)')
    .run(name, email, hashPassword(password), b.role, phone, company, now());
  return Number(r.lastInsertRowid);
}
const optInt = (v, min, max) => (v === undefined || v === null || v === '' ? null : int(v, min, max));
const optText = (v, max) => (v === undefined || v === null || v === '' ? null : str(v, 1, max));
const optCents = v => (v === undefined || v === null || v === '' ? null : cents(v, { min: 0, max: 1e9 }));
function createProject(owner, b, status = 'pending') {
  const title = str(b.title, 3, 120), description = str(b.description, 10, 3000);
  if (!CATS.includes(b.category)) throw bad();
  const price = cents(b.sharePrice, { min: 1, max: 1_000_000 });
  const goal = cents(b.goal, { min: 100, max: 100_000_000 });
  const total = Math.floor(goal / price);
  if (total < 1 || total > 1_000_000) throw bad();
  const minShares = b.minShares ? int(b.minShares, 1, total) : 1;
  const er = b.expectedReturn === undefined || b.expectedReturn === null || b.expectedReturn === '' ? null : Number(b.expectedReturn);
  if (er !== null && (!Number.isFinite(er) || er < -100 || er > 500)) throw bad();
  const r = db.prepare(`INSERT INTO projects(owner_id,title,category,description,share_price_cents,total_shares,created,status,
    location,founded_year,branches,employees,monthly_sales_cents,monthly_profit_cents,duration_months,expected_return,min_shares,
    use_of_funds,profit_terms,exit_terms) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
    .run(owner.id, title, b.category, description, price, total, now(), status,
      optText(b.location, 120), optInt(b.foundedYear, 1900, 2100), optInt(b.branches, 0, 10000), optInt(b.employees, 0, 1e6),
      optCents(b.monthlySales), optCents(b.monthlyProfit), optInt(b.durationMonths, 1, 600), er, minShares,
      optText(b.useOfFunds, 2000), optText(b.profitTerms, 2000), optText(b.exitTerms, 2000));
  const id = Number(r.lastInsertRowid);
  audit(owner.id, 'project.submitted', 'project', id, { title });
  return id;
}
function requireKyc(u) {
  const k = db.prepare('SELECT kyc_status FROM users WHERE id=?').get(u.id).kyc_status;
  if (k !== 'approved') throw new HttpError(403, 'kyc_required');
}
function makeContract(user, p, kind, shares, amountCents, sign, ip) {
  const signer = sign && typeof sign.signature === 'string' ? sign.signature.trim() : '';
  if (!sign || sign.accept !== true || signer.length < 3 || signer.length > 100) throw bad('contract_required');
  const terms = JSON.stringify({ project: p.title, category: p.category, shares, sharePrice: dollars(p.share_price_cents), amount: dollars(amountCents),
    durationMonths: p.duration_months, profitTerms: p.profit_terms, exitTerms: p.exit_terms, risk: p.risk, useOfFunds: p.use_of_funds,
    acknowledgements: ['no_guaranteed_profit', 'capital_at_risk', 'illiquid_until_exit'] });
  const created = now();
  const hash = sha(terms + '|' + user.id + '|' + signer + '|' + created);
  const r = db.prepare('INSERT INTO contracts(user_id,project_id,kind,shares,amount_cents,terms,signer,signed_ip,hash,created) VALUES(?,?,?,?,?,?,?,?,?,?)')
    .run(user.id, p.id, kind, shares, amountCents, terms, signer, ip || null, hash, created);
  return Number(r.lastInsertRowid);
}
function buyShares(user, projectId, shares, sign, ip) {
  requireKyc(user);
  return tx(() => {
    const p = db.prepare(PROJECT_SELECT + ' WHERE p.id=?').get(projectId);
    if (!p || p.status !== 'approved') throw new HttpError(404, 'not_found');
    const left = p.total_shares - p.sold;
    if (shares > left) throw bad('not_enough_shares');
    if (shares < Math.min(p.min_shares, left)) throw bad('below_minimum');
    const cost = shares * p.share_price_cents;
    if (balanceCents(user.id) < cost) throw bad('no_funds');
    const t = now();
    const cid = makeContract(user, p, 'primary', shares, cost, sign, ip);
    db.prepare('INSERT INTO investments(project_id,user_id,shares,amount_cents,created) VALUES(?,?,?,?,?)').run(p.id, user.id, shares, cost, t);
    db.prepare('INSERT INTO wallet_tx(user_id,type,amount_cents,project_id,note,created) VALUES(?,?,?,?,?,?)').run(user.id, 'invest', -cost, p.id, null, t);
    audit(user.id, 'investment.created', 'project', p.id, { shares, amount: dollars(cost), contract: cid });
    if (shares >= left) { notify(p.owner_id, 'fully_funded', p.id, {}); audienceOf(p.id).forEach(u => notify(u, 'fully_funded', p.id, {})); }
    else if ((p.sold + shares) / p.total_shares >= 0.9 && p.sold / p.total_shares < 0.9) followersOf(p.id).forEach(u => notify(u, 'almost_funded', p.id, {}));
    return balanceCents(user.id);
  });
}
function distributePayout(owner, projectId, amountCents, note) {
  return tx(() => {
    const p = db.prepare(PROJECT_SELECT + ' WHERE p.id=?').get(projectId);
    if (!p || p.owner_id !== owner.id || p.status !== 'approved') throw new HttpError(404, 'not_found');
    const holders = db.prepare('SELECT user_id, SUM(shares) sh FROM investments WHERE project_id=? GROUP BY user_id ORDER BY sh DESC, user_id').all(p.id);
    if (!holders.length) throw bad('no_investors');
    const t = now();
    db.prepare('INSERT INTO payouts(project_id,amount_cents,note,created) VALUES(?,?,?,?)').run(p.id, amountCents, note, t);
    let given = 0;
    holders.forEach(h => { h.c = Math.floor(amountCents * h.sh / p.sold); given += h.c; });
    holders[0].c += amountCents - given; // rounding remainder goes to the largest holder
    const ins = db.prepare('INSERT INTO wallet_tx(user_id,type,amount_cents,project_id,note,created) VALUES(?,?,?,?,?,?)');
    for (const h of holders) if (h.c > 0) ins.run(h.user_id, 'income', h.c, p.id, note, t);
    audit(owner.id, 'payout.distributed', 'project', p.id, { amount: dollars(amountCents), investors: holders.length });
    for (const h of holders) if (h.c > 0) notify(h.user_id, 'payout', p.id, { amount: dollars(h.c) });
    return holders.length;
  });
}
function withdraw(user, amountCents, dest) {
  requireKyc(user);
  return tx(() => {
    if (balanceCents(user.id) < amountCents) throw bad('no_funds');
    const t = now();
    const r = db.prepare('INSERT INTO wallet_tx(user_id,type,amount_cents,project_id,note,created) VALUES(?,?,?,?,?,?)')
      .run(user.id, 'withdraw', -amountCents, null, dest, t);
    const w = db.prepare('INSERT INTO withdrawals(user_id,tx_id,amount_cents,destination,created) VALUES(?,?,?,?,?)')
      .run(user.id, Number(r.lastInsertRowid), amountCents, dest, t);
    audit(user.id, 'withdrawal.requested', 'withdrawal', Number(w.lastInsertRowid), { amount: dollars(amountCents) });
    return balanceCents(user.id);
  });
}
function deposit(user, amountCents) {
  db.prepare('INSERT INTO wallet_tx(user_id,type,amount_cents,project_id,note,created) VALUES(?,?,?,?,?,?)')
    .run(user.id, 'deposit', amountCents, null, null, now());
  audit(user.id, 'wallet.deposit', 'user', user.id, { amount: dollars(amountCents) });
  return balanceCents(user.id);
}

/* ---------- financial statements & analysis ---------- */
const MONTH_RE = /^\d{4}-(0[1-9]|1[0-2])$/;
const FIN_MAP = { revenue: 'revenue', cogs: 'cogs', direct: 'direct_exp', indirect: 'indirect_exp', payroll: 'payroll', rent: 'rent',
  utilities: 'utilities', commissions: 'commissions', marketing: 'marketing', other: 'other_exp', debtPayments: 'debt_payments', liabilities: 'liabilities' };
function finRows(pid) {
  return db.prepare('SELECT * FROM financials WHERE project_id=? ORDER BY month').all(pid).map(r => {
    const o = { month: r.month, verified: !!r.verified };
    for (const [k, col] of Object.entries(FIN_MAP)) o[k] = dollars(r[col]);
    return o;
  });
}
function saveFinancials(owner, pid, rows) {
  const p = db.prepare('SELECT owner_id FROM projects WHERE id=?').get(pid);
  if (!p || p.owner_id !== owner.id) throw new HttpError(404, 'not_found');
  if (!Array.isArray(rows) || !rows.length || rows.length > 36) throw bad();
  tx(() => {
    for (const r of rows) {
      if (!r || typeof r.month !== 'string' || !MONTH_RE.test(r.month)) throw bad();
      const vals = Object.keys(FIN_MAP).map(k => (r[k] === undefined || r[k] === '' || r[k] === null ? 0 : cents(r[k], { min: 0, max: 1e9 })));
      db.prepare(`INSERT INTO financials(project_id,month,${Object.values(FIN_MAP).join(',')},verified,updated) VALUES(?,?,${vals.map(() => '?').join(',')},0,?)
        ON CONFLICT(project_id,month) DO UPDATE SET ${Object.values(FIN_MAP).map(c => c + '=excluded.' + c).join(',')}, verified=0, updated=excluded.updated`)
        .run(pid, r.month, ...vals, now());
    }
    if (db.prepare('SELECT COUNT(*) c FROM financials WHERE project_id=?').get(pid).c > 60) throw bad('too_many_files');
    audit(owner.id, 'financials.saved', 'project', pid, { months: rows.map(r => r.month) });
  });
}
function analysisFor(pid) {
  const p = db.prepare('SELECT * FROM projects WHERE id=?').get(pid);
  const docKinds = db.prepare('SELECT COUNT(DISTINCT kind) c FROM documents WHERE project_id=?').get(pid).c;
  const rows = finRows(pid);
  const a = Analysis.analyze(rows, { declaredSales: p.monthly_sales_cents == null ? 0 : dollars(p.monthly_sales_cents),
    declaredProfit: p.monthly_profit_cents == null ? 0 : dollars(p.monthly_profit_cents), foundedYear: p.founded_year, docKinds });
  return { ...a, rows };
}
function verifyFinancials(admin, pid, months, verified) {
  if (!Array.isArray(months) || !months.length || months.some(m => !MONTH_RE.test(m))) throw bad();
  const v = verified ? 1 : 0;
  for (const m of months) db.prepare('UPDATE financials SET verified=? WHERE project_id=? AND month=?').run(v, pid, m);
  audit(admin.id, v ? 'financials.verified' : 'financials.unverified', 'project', pid, { months });
}
/* Optional AI document reader: only active when ANTHROPIC_API_KEY is set. Output is a SUGGESTION the owner must review. */
const AI_ON = !!process.env.ANTHROPIC_API_KEY;
async function extractFromDocument(user, docId) {
  if (!AI_ON) throw new HttpError(501, 'ai_not_configured');
  const d = db.prepare('SELECT * FROM documents WHERE id=?').get(docId);
  if (!d || !d.project_id) throw new HttpError(404, 'not_found');
  const p = db.prepare('SELECT owner_id FROM projects WHERE id=?').get(d.project_id);
  if (user.role !== 'admin' && p.owner_id !== user.id) throw new HttpError(404, 'not_found');
  const b64 = fs.readFileSync(path.join(UPLOAD_DIR, path.basename(d.path))).toString('base64');
  const block = d.mime === 'application/pdf'
    ? { type: 'document', source: { type: 'base64', media_type: d.mime, data: b64 } }
    : { type: 'image', source: { type: 'base64', media_type: d.mime, data: b64 } };
  const r = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: { 'x-api-key': process.env.ANTHROPIC_API_KEY, 'anthropic-version': '2023-06-01', 'content-type': 'application/json' },
    body: JSON.stringify({ model: process.env.AI_MODEL || 'claude-sonnet-5-5', max_tokens: 600, messages: [{ role: 'user', content: [block,
      { type: 'text', text: 'Extract monthly business figures from this document. Reply with ONLY a JSON object with these numeric keys (use 0 if absent) and "month" as YYYY-MM if identifiable: month, revenue, cogs, direct, indirect, payroll, rent, utilities, commissions, marketing, other, debtPayments, liabilities. Do not invent numbers.' }] }] })
  });
  if (!r.ok) throw new HttpError(502, 'ai_failed');
  const j = await r.json();
  const text = (j.content || []).map(c => c.text || '').join('');
  const m = text.match(/\{[\s\S]*\}/); if (!m) throw new HttpError(502, 'ai_failed');
  let o; try { o = JSON.parse(m[0]); } catch { throw new HttpError(502, 'ai_failed'); }
  const out = { month: typeof o.month === 'string' && MONTH_RE.test(o.month) ? o.month : null };
  for (const k of Object.keys(FIN_MAP)) out[k] = Number.isFinite(+o[k]) && +o[k] >= 0 && +o[k] < 1e9 ? +o[k] : 0;
  audit(user.id, 'document.ai_extracted', 'document', docId, null);
  return out;
}

/* documents: stored on disk, never served publicly */
const DOC_KINDS = ['kyc_id', 'commercial_register', 'tax_card', 'license', 'financials', 'bank_statement', 'invoice', 'contract', 'ownership', 'payroll', 'other'];
function sniffMime(buf) {
  if (buf.length > 4 && buf.slice(0, 4).toString('latin1') === '%PDF') return ['application/pdf', 'pdf'];
  if (buf.length > 8 && buf.slice(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]))) return ['image/png', 'png'];
  if (buf.length > 3 && buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff) return ['image/jpeg', 'jpg'];
  return null;
}
function saveDocument(user, b) {
  const kind = DOC_KINDS.includes(b.kind) ? b.kind : (() => { throw bad(); })();
  const filename = str(b.filename, 1, 150).replace(/[^\p{L}\p{N}._ ()-]/gu, '_');
  if (typeof b.data !== 'string' || !/^[A-Za-z0-9+/=]+$/.test(b.data)) throw bad();
  const buf = Buffer.from(b.data, 'base64');
  if (buf.length < 16 || buf.length > 2 * 1024 * 1024) throw bad('file_too_large');
  const m = sniffMime(buf); if (!m) throw bad('bad_file_type');
  let pid = null;
  if (b.projectId !== undefined && b.projectId !== null) {
    pid = int(b.projectId, 1, 1e9);
    const p = db.prepare('SELECT owner_id FROM projects WHERE id=?').get(pid);
    if (!p || p.owner_id !== user.id) throw new HttpError(404, 'not_found');
    if (db.prepare('SELECT COUNT(*) c FROM documents WHERE project_id=?').get(pid).c >= 30) throw bad('too_many_files');
  } else {
    if (kind !== 'kyc_id') throw bad();
    if (db.prepare('SELECT COUNT(*) c FROM documents WHERE user_id=? AND project_id IS NULL').get(user.id).c >= 5) throw bad('too_many_files');
  }
  const file = crypto.randomBytes(16).toString('hex') + '.' + m[1];
  fs.writeFileSync(path.join(UPLOAD_DIR, file), buf, { mode: 0o600 });
  const r = db.prepare('INSERT INTO documents(user_id,project_id,kind,filename,path,mime,size,created) VALUES(?,?,?,?,?,?,?,?)')
    .run(user.id, pid, kind, filename, file, m[0], buf.length, now());
  audit(user.id, 'document.uploaded', pid ? 'project' : 'user', pid || user.id, { kind, filename });
  return Number(r.lastInsertRowid);
}
function submitKyc(u, b) {
  const fullName = str(b.fullName, 3, 100), nationalId = str(b.nationalId, 6, 20), phone = str(b.phone, 6, 20);
  if (!/^[0-9A-Za-z-]{6,20}$/.test(nationalId) || !/^\+?[0-9 ()-]{6,20}$/.test(phone)) throw bad();
  if (!db.prepare("SELECT 1 FROM documents WHERE user_id=? AND project_id IS NULL AND kind='kyc_id'").get(u.id)) throw bad('need_document');
  const cur = db.prepare('SELECT kyc_status FROM users WHERE id=?').get(u.id).kyc_status;
  if (cur === 'approved' || cur === 'pending') throw bad('kyc_locked');
  db.prepare("UPDATE users SET name=?, national_id=?, phone=?, kyc_status='pending', kyc_note=NULL WHERE id=?").run(fullName, nationalId, phone, u.id);
  audit(u.id, 'kyc.submitted', 'user', u.id, null);
}

function investorDashboard(u) {
  const holdings = db.prepare(`SELECT p.id,p.title,p.share_price_cents sp,p.total_shares ts,SUM(i.shares) sh
    FROM investments i JOIN projects p ON p.id=i.project_id WHERE i.user_id=? GROUP BY p.id ORDER BY p.id`).all(u.id);
  const inc = Object.fromEntries(db.prepare(`SELECT project_id pid,SUM(amount_cents) c FROM wallet_tx
    WHERE user_id=? AND type='income' GROUP BY project_id`).all(u.id).map(r => [r.pid, r.c]));
  const history = db.prepare(`SELECT t.id,t.type,t.amount_cents,t.note,t.created,p.title project FROM wallet_tx t
    LEFT JOIN projects p ON p.id=t.project_id WHERE t.user_id=? ORDER BY t.id DESC LIMIT 200`).all(u.id);
  const pending = db.prepare("SELECT COALESCE(SUM(amount_cents),0) c FROM withdrawals WHERE user_id=? AND status='pending'").get(u.id).c;
  return {
    balance: dollars(balanceCents(u.id)), pendingWithdrawals: dollars(pending),
    holdings: holdings.map(h => ({ id: h.id, title: h.title, shares: h.sh, totalShares: h.ts,
      invested: dollars(h.sh * h.sp), income: dollars(inc[h.id] || 0) })),
    totalIncome: dollars(Object.values(inc).reduce((a, b) => a + b, 0)),
    history: history.map(h => ({ id: h.id, type: h.type, amount: dollars(h.amount_cents), note: h.note, project: h.project, date: h.created }))
  };
}
function ownerDashboard(u) {
  const projects = db.prepare(PROJECT_SELECT + ' WHERE p.owner_id=? ORDER BY p.id DESC').all(u.id);
  return projects.map(p => ({
    ...projectOut(p, { private: true }),
    investors: db.prepare(`SELECT u.name,SUM(i.shares) shares FROM investments i JOIN users u ON u.id=i.user_id
      WHERE i.project_id=? GROUP BY u.id ORDER BY shares DESC`).all(p.id)
      .map(r => ({ name: r.name, shares: r.shares, amount: dollars(r.shares * p.share_price_cents) })),
    payouts: db.prepare('SELECT amount_cents,note,created FROM payouts WHERE project_id=? ORDER BY id DESC').all(p.id)
      .map(r => ({ amount: dollars(r.amount_cents), note: r.note, date: r.created }))
  }));
}

/* ---------- admin ---------- */
function adminOverview() {
  const c = (sql, ...a) => db.prepare(sql).get(...a).c;
  const raised = db.prepare('SELECT COALESCE(SUM(amount_cents),0) c, COUNT(*) n FROM investments').get();
  return {
    investors: c("SELECT COUNT(*) c FROM users WHERE role='investor'"), owners: c("SELECT COUNT(*) c FROM users WHERE role='owner'"),
    kycPending: c("SELECT COUNT(*) c FROM users WHERE kyc_status='pending'"),
    projectsPending: c("SELECT COUNT(*) c FROM projects WHERE status='pending'"),
    projectsApproved: c("SELECT COUNT(*) c FROM projects WHERE status='approved'"),
    projectsRejected: c("SELECT COUNT(*) c FROM projects WHERE status='rejected'"),
    totalRaised: dollars(raised.c), avgInvestment: raised.n ? dollars(Math.round(raised.c / raised.n)) : 0,
    totalPaidOut: dollars(c("SELECT COALESCE(SUM(amount_cents),0) c FROM wallet_tx WHERE type='income'")),
    withdrawalsPending: c("SELECT COUNT(*) c FROM withdrawals WHERE status='pending'"),
    walletLiability: dollars(c('SELECT COALESCE(SUM(amount_cents),0) c FROM wallet_tx'))
  };
}
function adminKycQueue() {
  return db.prepare("SELECT id,name,email,phone,national_id,kyc_status,created FROM users WHERE kyc_status='pending' ORDER BY id").all()
    .map(u => ({ ...u, documents: db.prepare("SELECT * FROM documents WHERE user_id=? AND project_id IS NULL").all(u.id).map(docOut) }));
}
function adminDecideKyc(admin, uid, b) {
  const d = b.decision; if (!['approved', 'rejected'].includes(d)) throw bad();
  const note = b.note ? str(b.note, 0, 500) : null;
  const u = db.prepare("SELECT id FROM users WHERE id=? AND kyc_status='pending'").get(uid);
  if (!u) throw new HttpError(404, 'not_found');
  db.prepare('UPDATE users SET kyc_status=?, kyc_note=? WHERE id=?').run(d, note, uid);
  audit(admin.id, 'kyc.' + d, 'user', uid, { note });
  notify(uid, 'kyc_' + d, null, { note });
}
function adminProjects() {
  return db.prepare(PROJECT_SELECT + ' ORDER BY p.id DESC').all().map(p => ({ ...projectOut(p, { private: true }), ownerName: p.owner_name, ownerEmail: db.prepare('SELECT email FROM users WHERE id=?').get(p.owner_id).email,
    analysis: (() => { const a = analysisFor(p.id); return { n: a.n, rating: a.rating, flags: a.flags, rows: a.rows }; })() }));
}
function adminReview(admin, pid, b) {
  const d = b.decision; if (!['approved', 'rejected'].includes(d)) throw bad();
  const risk = b.risk && ['low', 'medium', 'high'].includes(b.risk) ? b.risk : 'unrated';
  if (d === 'approved' && risk === 'unrated') throw bad('risk_required');
  const vn = b.verificationNote ? str(b.verificationNote, 0, 2000) : null, an = b.adminNote ? str(b.adminNote, 0, 2000) : null;
  const old = db.prepare('SELECT status,risk FROM projects WHERE id=?').get(pid);
  if (!old) throw new HttpError(404, 'not_found');
  db.prepare('UPDATE projects SET status=?, risk=?, verification_note=?, admin_note=? WHERE id=?').run(d, risk, vn, an, pid);
  audit(admin.id, 'project.' + d, 'project', pid, { old, risk });
  const pr = db.prepare('SELECT owner_id FROM projects WHERE id=?').get(pid);
  notify(pr.owner_id, 'project_' + d, pid, { note: an });
  if (d === 'approved' && old.status !== 'approved') db.prepare("SELECT id FROM users WHERE role='investor' AND kyc_status='approved'").all().forEach(u => notify(u.id, 'new_project', pid, {}));
  if (d === 'approved' && old.status === 'approved' && old.risk !== risk) audienceOf(pid).forEach(u => notify(u, 'risk_changed', pid, { risk }));
}
function adminWithdrawals() {
  return db.prepare(`SELECT w.id,w.amount_cents,w.destination,w.status,w.created,w.processed,u.name,u.email FROM withdrawals w
    JOIN users u ON u.id=w.user_id ORDER BY (w.status='pending') DESC, w.id DESC LIMIT 200`).all()
    .map(w => ({ id: w.id, amount: dollars(w.amount_cents), destination: w.destination, status: w.status, created: w.created, name: w.name, email: w.email }));
}
function adminDecideWithdrawal(admin, id, decision) {
  if (!['paid', 'rejected'].includes(decision)) throw bad();
  tx(() => {
    const w = db.prepare("SELECT * FROM withdrawals WHERE id=? AND status='pending'").get(id);
    if (!w) throw new HttpError(404, 'not_found');
    db.prepare('UPDATE withdrawals SET status=?, processed=? WHERE id=?').run(decision, now(), id);
    if (decision === 'rejected')
      db.prepare('INSERT INTO wallet_tx(user_id,type,amount_cents,project_id,note,created) VALUES(?,?,?,?,?,?)')
        .run(w.user_id, 'refund', w.amount_cents, null, 'withdrawal #' + id, now());
    audit(admin.id, 'withdrawal.' + decision, 'withdrawal', id, { amount: dollars(w.amount_cents) });
    notify(w.user_id, 'withdrawal_' + decision, null, { amount: dollars(w.amount_cents) });
  });
}
function adminUsers() {
  return db.prepare("SELECT id,name,email,role,phone,kyc_status,created FROM users ORDER BY id DESC LIMIT 500").all();
}
function adminTransactions() {
  return db.prepare(`SELECT t.id,t.type,t.amount_cents,t.note,t.created,u.name,p.title project FROM wallet_tx t
    JOIN users u ON u.id=t.user_id LEFT JOIN projects p ON p.id=t.project_id ORDER BY t.id DESC LIMIT 300`).all()
    .map(t => ({ id: t.id, type: t.type, amount: dollars(t.amount_cents), note: t.note, date: t.created, user: t.name, project: t.project }));
}
function adminAudit() {
  return db.prepare(`SELECT a.id,a.action,a.entity,a.entity_id,a.detail,a.created,u.name actor FROM audit a
    LEFT JOIN users u ON u.id=a.actor_id ORDER BY a.id DESC LIMIT 300`).all();
}

/* ---------- reports, community, polls, follows ---------- */
function ownProject(user, pid) {
  const p = db.prepare('SELECT * FROM projects WHERE id=?').get(pid);
  if (!p || p.owner_id !== user.id) throw new HttpError(404, 'not_found');
  return p;
}
function canSee(user, p) { return p.status === 'approved' || (user && (user.role === 'admin' || user.id === p.owner_id)); }
function createReport(owner, pid, b) {
  const p = ownProject(owner, pid); if (p.status !== 'approved') throw new HttpError(403, 'forbidden');
  if (typeof b.month !== 'string' || !MONTH_RE.test(b.month)) throw bad();
  const sales = b.sales === undefined || b.sales === '' ? null : cents(b.sales, { min: 0, max: 1e9 });
  const exp = b.expenses === undefined || b.expenses === '' ? null : cents(b.expenses, { min: 0, max: 1e9 });
  db.prepare(`INSERT INTO reports(project_id,month,summary,sales_cents,expenses_cents,challenges,next_plan,created) VALUES(?,?,?,?,?,?,?,?)
    ON CONFLICT(project_id,month) DO UPDATE SET summary=excluded.summary,sales_cents=excluded.sales_cents,expenses_cents=excluded.expenses_cents,
    challenges=excluded.challenges,next_plan=excluded.next_plan,created=excluded.created`)
    .run(pid, b.month, str(b.summary, 10, 3000), sales, exp, b.challenges ? str(b.challenges, 1, 2000) : null, b.nextPlan ? str(b.nextPlan, 1, 2000) : null, now());
  audit(owner.id, 'report.published', 'project', pid, { month: b.month });
  audienceOf(pid).forEach(u => notify(u, 'report', pid, { month: b.month }));
}
function reportsFor(user, pid) {
  const p = db.prepare('SELECT * FROM projects WHERE id=?').get(pid);
  if (!p || !canSee(user, p)) throw new HttpError(404, 'not_found');
  const holder = user && db.prepare('SELECT 1 FROM investments WHERE project_id=? AND user_id=?').get(pid, user.id);
  if (!(holder || (user && (user.role === 'admin' || user.id === p.owner_id)))) throw new HttpError(403, 'holders_only');
  return db.prepare('SELECT * FROM reports WHERE project_id=? ORDER BY month DESC').all(pid).map(r => ({ month: r.month, summary: r.summary,
    sales: r.sales_cents == null ? null : dollars(r.sales_cents), expenses: r.expenses_cents == null ? null : dollars(r.expenses_cents),
    challenges: r.challenges, nextPlan: r.next_plan, created: r.created }));
}
function postsFor(pid) {
  return db.prepare(`SELECT po.id,po.kind,po.parent_id,po.body,po.created,u.name,u.role FROM posts po JOIN users u ON u.id=po.user_id
    WHERE po.project_id=? ORDER BY po.id`).all(pid).map(r => ({ id: r.id, kind: r.kind, parentId: r.parent_id, body: r.body, created: r.created, author: r.role === 'owner' ? r.name : r.name.split(' ')[0], role: r.role }));
}
function createPost(user, pid, b) {
  const p = db.prepare('SELECT * FROM projects WHERE id=?').get(pid);
  if (!p || p.status !== 'approved') throw new HttpError(404, 'not_found');
  const body = str(b.body, 2, 1500); let kind, parent = null;
  if (user.id === p.owner_id) {
    if (b.parentId) { parent = int(b.parentId, 1, 1e9); const q = db.prepare("SELECT 1 FROM posts WHERE id=? AND project_id=? AND kind='question'").get(parent, pid); if (!q) throw bad(); kind = 'answer'; }
    else kind = 'update';
  } else if (user.role === 'investor') kind = 'question';
  else throw new HttpError(403, 'forbidden');
  const r = db.prepare('INSERT INTO posts(project_id,user_id,kind,parent_id,body,created) VALUES(?,?,?,?,?,?)').run(pid, user.id, kind, parent, body, now());
  if (kind === 'update') audienceOf(pid).forEach(u => notify(u, 'update', pid, {}));
  if (kind === 'question') notify(p.owner_id, 'question', pid, {});
  if (kind === 'answer') { const q = db.prepare('SELECT user_id FROM posts WHERE id=?').get(parent); notify(q.user_id, 'answer', pid, {}); }
  return Number(r.lastInsertRowid);
}
function createPoll(owner, pid, b) {
  const p = ownProject(owner, pid); if (p.status !== 'approved') throw new HttpError(403, 'forbidden');
  const question = str(b.question, 5, 300);
  if (!Array.isArray(b.options) || b.options.length < 2 || b.options.length > 6) throw bad();
  const options = b.options.map(o => str(o, 1, 100)); const days = int(b.days ?? 7, 1, 60);
  const r = db.prepare('INSERT INTO polls(project_id,question,options,closes,created) VALUES(?,?,?,?,?)').run(pid, question, JSON.stringify(options), now() + days * 864e5, now());
  holdersOf(pid).forEach(u => notify(u, 'poll', pid, {}));
  audit(owner.id, 'poll.created', 'project', pid, { question });
  return Number(r.lastInsertRowid);
}
function pollsFor(user, pid) {
  const p = db.prepare('SELECT * FROM projects WHERE id=?').get(pid);
  if (!p || !canSee(user, p)) throw new HttpError(404, 'not_found');
  return db.prepare('SELECT * FROM polls WHERE project_id=? ORDER BY id DESC').all(pid).map(pl => {
    const opts = JSON.parse(pl.options), tally = opts.map(() => 0);
    db.prepare('SELECT option_idx,SUM(weight) w FROM votes WHERE poll_id=? GROUP BY option_idx').all(pl.id).forEach(v => { tally[v.option_idx] = v.w; });
    const mine = user ? db.prepare('SELECT option_idx FROM votes WHERE poll_id=? AND user_id=?').get(pl.id, user.id) : null;
    return { id: pl.id, question: pl.question, options: opts, tally, closes: pl.closes, open: pl.closes > now(), myVote: mine ? mine.option_idx : null };
  });
}
function vote(user, pollId, optionIdx) {
  const pl = db.prepare('SELECT * FROM polls WHERE id=?').get(pollId);
  if (!pl || pl.closes < now()) throw new HttpError(404, 'not_found');
  const sh = db.prepare('SELECT COALESCE(SUM(shares),0) s FROM investments WHERE project_id=? AND user_id=?').get(pl.project_id, user.id).s;
  if (!sh) throw new HttpError(403, 'holders_only');
  const n = JSON.parse(pl.options).length; if (!Number.isInteger(optionIdx) || optionIdx < 0 || optionIdx >= n) throw bad();
  if (db.prepare('SELECT 1 FROM votes WHERE poll_id=? AND user_id=?').get(pollId, user.id)) throw bad('already_voted');
  db.prepare('INSERT INTO votes(poll_id,user_id,option_idx,weight) VALUES(?,?,?,?)').run(pollId, user.id, optionIdx, sh);
}
function ownerReputation(oid) {
  const u = db.prepare("SELECT id,name,company_name,kyc_status,created FROM users WHERE id=? AND role='owner'").get(oid);
  if (!u) throw new HttpError(404, 'not_found');
  const ps = db.prepare("SELECT id FROM projects WHERE owner_id=? AND status='approved'").all(oid);
  const raised = db.prepare("SELECT COALESCE(SUM(i.amount_cents),0) c FROM investments i JOIN projects p ON p.id=i.project_id WHERE p.owner_id=?").get(oid).c;
  const reports = db.prepare('SELECT COUNT(*) c FROM reports r JOIN projects p ON p.id=r.project_id WHERE p.owner_id=?').get(oid).c;
  const scores = ps.map(p => analysisFor(p.id).rating).filter(Boolean).map(r => r.score);
  return { name: u.company_name || u.name, memberSince: u.created, projects: ps.length, raised: dollars(raised), reports,
    avgScore: scores.length ? Math.round(scores.reduce((a, b) => a + b, 0) / scores.length) : null, payouts: db.prepare('SELECT COUNT(*) c FROM payouts pa JOIN projects p ON p.id=pa.project_id WHERE p.owner_id=?').get(oid).c };
}

/* ---------- exits / secondary market ---------- */
const heldShares = (uid, pid) => db.prepare('SELECT COALESCE(SUM(shares),0) s FROM investments WHERE user_id=? AND project_id=?').get(uid, pid).s;
const listedShares = (uid, pid) => db.prepare("SELECT COALESCE(SUM(shares),0) s FROM exits WHERE seller_id=? AND project_id=? AND status IN('pending','open')").get(uid, pid).s;
function createExit(user, b) {
  requireKyc(user);
  const pid = int(b.projectId, 1, 1e9), shares = int(b.shares, 1, 1e6), price = cents(b.pricePerShare, { min: 0.01, max: 1e6 });
  if (shares > heldShares(user.id, pid) - listedShares(user.id, pid)) throw bad('not_enough_shares');
  const r = db.prepare('INSERT INTO exits(project_id,seller_id,shares,price_cents,created) VALUES(?,?,?,?,?)').run(pid, user.id, shares, price, now());
  audit(user.id, 'exit.requested', 'project', pid, { shares, price: dollars(price) });
  return Number(r.lastInsertRowid);
}
function exitOut(e) { return { id: e.id, projectId: e.project_id, project: e.title, shares: e.shares, pricePerShare: dollars(e.price_cents), total: dollars(e.shares * e.price_cents),
  faceValue: dollars(e.share_price_cents), status: e.status, created: e.created }; }
const EXIT_SELECT = 'SELECT e.*, p.title, p.share_price_cents FROM exits e JOIN projects p ON p.id=e.project_id';
function buyExit(user, id, sign, ip) {
  requireKyc(user);
  return tx(() => {
    const e = db.prepare(EXIT_SELECT + " WHERE e.id=? AND e.status='open'").get(id);
    if (!e) throw new HttpError(404, 'not_found');
    if (e.seller_id === user.id) throw bad();
    const total = e.shares * e.price_cents;
    if (balanceCents(user.id) < total) throw bad('no_funds');
    if (heldShares(e.seller_id, e.project_id) < e.shares) throw bad('not_enough_shares');
    const p = db.prepare(PROJECT_SELECT + ' WHERE p.id=?').get(e.project_id);
    const cid = makeContract(user, p, 'secondary', e.shares, total, sign, ip);
    let left = e.shares;                                              // move shares from the seller's rows (oldest first)
    for (const row of db.prepare('SELECT * FROM investments WHERE project_id=? AND user_id=? ORDER BY id').all(e.project_id, e.seller_id)) {
      if (!left) break; const take = Math.min(left, row.shares); left -= take;
      if (take === row.shares) db.prepare('DELETE FROM investments WHERE id=?').run(row.id);
      else db.prepare('UPDATE investments SET shares=?, amount_cents=? WHERE id=?').run(row.shares - take, (row.shares - take) * p.share_price_cents, row.id);
    }
    const t = now();
    db.prepare('INSERT INTO investments(project_id,user_id,shares,amount_cents,created) VALUES(?,?,?,?,?)').run(e.project_id, user.id, e.shares, e.shares * p.share_price_cents, t);
    const w = db.prepare('INSERT INTO wallet_tx(user_id,type,amount_cents,project_id,note,created) VALUES(?,?,?,?,?,?)');
    w.run(user.id, 'purchase', -total, e.project_id, null, t); w.run(e.seller_id, 'sale', total, e.project_id, null, t);
    db.prepare("UPDATE exits SET status='sold', buyer_id=?, closed=? WHERE id=?").run(user.id, t, id);
    audit(user.id, 'exit.sold', 'project', e.project_id, { exit: id, shares: e.shares, total: dollars(total), contract: cid });
    notify(e.seller_id, 'exit_sold', e.project_id, { amount: dollars(total) });
    return balanceCents(user.id);
  });
}

/* ---------- 2FA (TOTP, RFC 6238) ---------- */
const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
function b32enc(buf) { let bits = '', out = ''; for (const b of buf) bits += b.toString(2).padStart(8, '0'); for (let i = 0; i < bits.length; i += 5) out += B32[parseInt(bits.slice(i, i + 5).padEnd(5, '0'), 2)]; return out; }
function b32dec(s) { let bits = ''; for (const c of s) bits += B32.indexOf(c).toString(2).padStart(5, '0'); const out = []; for (let i = 0; i + 8 <= bits.length; i += 8) out.push(parseInt(bits.slice(i, i + 8), 2)); return Buffer.from(out); }
function totpAt(secret, counter) {
  const b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(counter));
  const h = crypto.createHmac('sha1', b32dec(secret)).update(b).digest(); const o = h[h.length - 1] & 15;
  return String(((h.readUInt32BE(o) & 0x7fffffff) % 1_000_000)).padStart(6, '0');
}
function totpValid(secret, code) {
  if (!/^\d{6}$/.test(String(code || ''))) return false; const c = Math.floor(Date.now() / 30000);
  return [-1, 0, 1].some(d => { const x = Buffer.from(totpAt(secret, c + d)), y = Buffer.from(String(code)); return crypto.timingSafeEqual(x, y); });
}

/* ---------- optional AI assistant (needs ANTHROPIC_API_KEY) ---------- */
async function askAssistant(user, b) {
  if (!AI_ON) throw new HttpError(501, 'ai_not_configured');
  const question = str(b.question, 3, 500); let ctx = {};
  if (b.projectId) { const pid = int(b.projectId, 1, 1e9); const p = db.prepare(PROJECT_SELECT + ' WHERE p.id=?').get(pid);
    if (!p || p.status !== 'approved') throw new HttpError(404, 'not_found');
    const a = analysisFor(pid); ctx.project = projectOut(p); ctx.analysis = { metrics: a.metrics, flags: a.flags, rating: a.rating, valuation: a.valuation, months: a.n }; }
  if (user.role === 'investor') ctx.myPortfolio = investorDashboard(user).holdings;
  const r = await fetch('https://api.anthropic.com/v1/messages', { method: 'POST',
    headers: { 'x-api-key': process.env.ANTHROPIC_API_KEY, 'anthropic-version': '2023-06-01', 'content-type': 'application/json' },
    body: JSON.stringify({ model: process.env.AI_MODEL || 'claude-sonnet-5-5', max_tokens: 700,
      system: 'You are the assistant of Tamweel Shares, an investment crowdfunding platform. Answer ONLY from the JSON context provided; if it is not there, say you do not know. Never promise or imply guaranteed returns, never tell the user to buy or sell, and remind them that capital is at risk when relevant. Reply in the language of the question, concisely.',
      messages: [{ role: 'user', content: 'Context JSON:\n' + JSON.stringify(ctx) + '\n\nQuestion: ' + question }] }) });
  if (!r.ok) throw new HttpError(502, 'ai_failed');
  const j = await r.json(); return { answer: (j.content || []).map(c => c.text || '').join('').trim() };
}

/* ---------- routing ---------- */
const routes = [];
const HANDLED = Symbol('handled');
const route = (method, re, fn, opts = {}) => routes.push({ method, re, fn, limit: opts.limit || 10_000 });

route('POST', /^\/api\/signup$/, (req, res, ctx) => {
  limit('auth:' + ctx.ip, 10, 15 * 60_000);
  const id = signup(ctx.body); startSession(req, res, id);
  return { ok: true };
});
route('POST', /^\/api\/login$/, (req, res, ctx) => {
  limit('auth:' + ctx.ip, 10, 15 * 60_000);
  const email = str(ctx.body.email, 3, 320).toLowerCase(), password = str(ctx.body.password, 1, 200);
  const u = db.prepare('SELECT id,pass_hash,totp_secret,totp_enabled FROM users WHERE email=?').get(email);
  const ok = verifyPassword(password, u ? u.pass_hash : DUMMY_HASH) && u; // constant-ish time either way
  if (!ok) throw new HttpError(401, 'bad_login');
  if (u.totp_enabled) {
    if (!ctx.body.code) throw new HttpError(401, 'totp_required');
    if (!totpValid(u.totp_secret, ctx.body.code)) throw new HttpError(401, 'bad_code');
  }
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
  const full = db.prepare('SELECT phone,kyc_status,kyc_note,company_name,totp_enabled,risk_tolerance,experience FROM users WHERE id=?').get(u.id);
  return { user: { id: u.id, name: u.name, email: u.email, role: u.role, phone: full.phone, company: full.company_name,
    kyc: full.kyc_status, kycNote: full.kyc_note, totp: !!full.totp_enabled, riskTolerance: full.risk_tolerance, experience: full.experience,
    balance: u.role === 'investor' ? dollars(balanceCents(u.id)) : undefined } };
});
route('POST', /^\/api\/kyc$/, (req, res, ctx) => { const u = requireUser(req); if (u.role === 'admin') throw new HttpError(403, 'forbidden'); submitKyc(u, ctx.body); return { ok: true }; });
route('POST', /^\/api\/documents$/, (req, res, ctx) => {
  const u = requireUser(req); if (u.role === 'admin') throw new HttpError(403, 'forbidden');
  limit('doc:' + u.id, 40, 60 * 60_000);
  return { id: saveDocument(u, ctx.body) };
}, { limit: 3_200_000 });
route('GET', /^\/api\/documents\/(\d+)$/, (req, res, ctx) => {
  const u = requireUser(req);
  const d = db.prepare('SELECT * FROM documents WHERE id=?').get(Number(ctx.m[1]));
  if (!d || (d.user_id !== u.id && u.role !== 'admin')) throw new HttpError(404, 'not_found');
  const file = path.join(UPLOAD_DIR, path.basename(d.path));
  if (!fs.existsSync(file)) throw new HttpError(404, 'not_found');
  res.writeHead(200, { 'Content-Type': d.mime, 'Content-Length': d.size,
    'Content-Disposition': `attachment; filename*=UTF-8''${encodeURIComponent(d.filename)}` });
  fs.createReadStream(file).pipe(res);
  return HANDLED;
});
route('GET', /^\/api\/projects$/, () => db.prepare(PROJECT_SELECT + " WHERE p.status='approved' ORDER BY p.id DESC").all().map(p => projectOut(p)));
route('GET', /^\/api\/projects\/(\d+)$/, (req, res, ctx) => {
  const p = db.prepare(PROJECT_SELECT + ' WHERE p.id=?').get(Number(ctx.m[1]));
  const u = currentUser(req);
  if (!p || (p.status !== 'approved' && !(u && (u.role === 'admin' || u.id === p.owner_id)))) throw new HttpError(404, 'not_found');
  return projectOut(p, { private: !!(u && (u.role === 'admin' || u.id === p.owner_id)) });
});
route('POST', /^\/api\/projects$/, (req, res, ctx) => {
  const u = requireUser(req, 'owner'); return { id: createProject(u, ctx.body) };
});
route('POST', /^\/api\/projects\/(\d+)\/buy$/, (req, res, ctx) => {
  const u = requireUser(req, 'investor');
  return { balance: dollars(buyShares(u, Number(ctx.m[1]), int(ctx.body.shares, 1, 1_000_000), { accept: ctx.body.accept, signature: ctx.body.signature }, ctx.ip)) };
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
  requireKyc(u);
  return { balance: dollars(deposit(u, cents(ctx.body.amount, { max: 100_000 }))) };
});
route('POST', /^\/api\/wallet\/withdraw$/, (req, res, ctx) => {
  const u = requireUser(req, 'investor');
  limit('wd:' + u.id, 10, 60 * 60_000);
  return { balance: dollars(withdraw(u, cents(ctx.body.amount), str(ctx.body.destination, 4, 100))) };
});
route('GET', /^\/api\/config$/, () => ({ ai: AI_ON }));
route('GET', /^\/api\/projects\/(\d+)\/analysis$/, (req, res, ctx) => {
  const pid = Number(ctx.m[1]);
  const p = db.prepare('SELECT status,owner_id FROM projects WHERE id=?').get(pid);
  const u = currentUser(req);
  if (!p || (p.status !== 'approved' && !(u && (u.role === 'admin' || u.id === p.owner_id)))) throw new HttpError(404, 'not_found');
  return analysisFor(pid);
});
route('PUT', /^\/api\/projects\/(\d+)\/financials$/, (req, res, ctx) => { saveFinancials(requireUser(req, 'owner'), Number(ctx.m[1]), ctx.body.rows); return { ok: true }; }, { limit: 40_000 });
route('DELETE', /^\/api\/projects\/(\d+)\/financials\/(\d{4}-\d{2})$/, (req, res, ctx) => {
  const u = requireUser(req, 'owner'); const pid = Number(ctx.m[1]);
  const p = db.prepare('SELECT owner_id FROM projects WHERE id=?').get(pid);
  if (!p || p.owner_id !== u.id) throw new HttpError(404, 'not_found');
  db.prepare('DELETE FROM financials WHERE project_id=? AND month=?').run(pid, ctx.m[2]);
  audit(u.id, 'financials.deleted', 'project', pid, { month: ctx.m[2] }); return { ok: true };
});
route('POST', /^\/api\/documents\/(\d+)\/extract$/, async (req, res, ctx) => {
  const u = requireUser(req); limit('ai:' + u.id, 15, 60 * 60_000);
  return await extractFromDocument(u, Number(ctx.m[1]));
});
/* reports, community, polls, follows */
route('GET', /^\/api\/projects\/(\d+)\/reports$/, (req, res, ctx) => reportsFor(currentUser(req), Number(ctx.m[1])));
route('POST', /^\/api\/projects\/(\d+)\/reports$/, (req, res, ctx) => { createReport(requireUser(req, 'owner'), Number(ctx.m[1]), ctx.body); return { ok: true }; }, { limit: 12_000 });
route('GET', /^\/api\/projects\/(\d+)\/posts$/, (req, res, ctx) => {
  const p = db.prepare('SELECT * FROM projects WHERE id=?').get(Number(ctx.m[1])); if (!p || p.status !== 'approved') throw new HttpError(404, 'not_found');
  return postsFor(p.id);
});
route('POST', /^\/api\/projects\/(\d+)\/posts$/, (req, res, ctx) => { const u = requireUser(req); limit('post:' + u.id, 30, 60 * 60_000); return { id: createPost(u, Number(ctx.m[1]), ctx.body) }; }, { limit: 4_000 });
route('GET', /^\/api\/projects\/(\d+)\/polls$/, (req, res, ctx) => pollsFor(currentUser(req), Number(ctx.m[1])));
route('POST', /^\/api\/projects\/(\d+)\/polls$/, (req, res, ctx) => ({ id: createPoll(requireUser(req, 'owner'), Number(ctx.m[1]), ctx.body) }), { limit: 4_000 });
route('POST', /^\/api\/polls\/(\d+)\/vote$/, (req, res, ctx) => { vote(requireUser(req, 'investor'), Number(ctx.m[1]), ctx.body.option); return { ok: true }; });
route('GET', /^\/api\/follows$/, req => db.prepare('SELECT project_id FROM follows WHERE user_id=?').all(requireUser(req).id).map(r => r.project_id));
route('POST', /^\/api\/projects\/(\d+)\/follow$/, (req, res, ctx) => {
  const u = requireUser(req); const p = db.prepare("SELECT id FROM projects WHERE id=? AND status='approved'").get(Number(ctx.m[1])); if (!p) throw new HttpError(404, 'not_found');
  db.prepare('INSERT OR IGNORE INTO follows(user_id,project_id) VALUES(?,?)').run(u.id, p.id); return { ok: true };
});
route('DELETE', /^\/api\/projects\/(\d+)\/follow$/, (req, res, ctx) => { db.prepare('DELETE FROM follows WHERE user_id=? AND project_id=?').run(requireUser(req).id, Number(ctx.m[1])); return { ok: true }; });
route('GET', /^\/api\/owners\/(\d+)\/reputation$/, (req, res, ctx) => ownerReputation(Number(ctx.m[1])));
/* contracts */
route('GET', /^\/api\/contracts$/, req => db.prepare(`SELECT c.id,c.kind,c.shares,c.amount_cents,c.created,p.title,p.id pid FROM contracts c JOIN projects p ON p.id=c.project_id WHERE c.user_id=? ORDER BY c.id DESC`).all(requireUser(req).id)
  .map(c => ({ id: c.id, kind: c.kind, shares: c.shares, amount: dollars(c.amount_cents), created: c.created, project: c.title, projectId: c.pid })));
route('GET', /^\/api\/contracts\/(\d+)$/, (req, res, ctx) => {
  const u = requireUser(req); const c = db.prepare('SELECT c.*, u.name investor_name, u.email, p.owner_id, p.title FROM contracts c JOIN users u ON u.id=c.user_id JOIN projects p ON p.id=c.project_id WHERE c.id=?').get(Number(ctx.m[1]));
  if (!c || (c.user_id !== u.id && c.owner_id !== u.id && u.role !== 'admin')) throw new HttpError(404, 'not_found');
  return { id: c.id, kind: c.kind, investor: c.investor_name, signer: c.signer, shares: c.shares, amount: dollars(c.amount_cents), terms: JSON.parse(c.terms), hash: c.hash, created: c.created, project: c.title };
});
/* notifications */
route('GET', /^\/api\/notifications$/, req => { const u = requireUser(req);
  return db.prepare('SELECT n.id,n.type,n.project_id,n.data,n.read,n.created,p.title FROM notifications n LEFT JOIN projects p ON p.id=n.project_id WHERE n.user_id=? ORDER BY n.id DESC LIMIT 60').all(u.id)
    .map(n => ({ id: n.id, type: n.type, projectId: n.project_id, project: n.title, data: n.data ? JSON.parse(n.data) : {}, read: !!n.read, created: n.created })); });
route('POST', /^\/api\/notifications\/read$/, req => { db.prepare('UPDATE notifications SET read=1 WHERE user_id=?').run(requireUser(req).id); return { ok: true }; });
/* exits / secondary market */
route('GET', /^\/api\/exits$/, req => { requireUser(req); return db.prepare(EXIT_SELECT + " WHERE e.status='open' ORDER BY e.id DESC").all().map(exitOut); });
route('GET', /^\/api\/exits\/mine$/, req => db.prepare(EXIT_SELECT + ' WHERE e.seller_id=? ORDER BY e.id DESC').all(requireUser(req).id).map(exitOut));
route('POST', /^\/api\/exits$/, (req, res, ctx) => ({ id: createExit(requireUser(req, 'investor'), ctx.body) }));
route('DELETE', /^\/api\/exits\/(\d+)$/, (req, res, ctx) => {
  const r = db.prepare("UPDATE exits SET status='cancelled', closed=? WHERE id=? AND seller_id=? AND status IN('pending','open')").run(now(), Number(ctx.m[1]), requireUser(req).id);
  if (!r.changes) throw new HttpError(404, 'not_found'); return { ok: true };
});
route('POST', /^\/api\/exits\/(\d+)\/buy$/, (req, res, ctx) => ({ balance: dollars(buyExit(requireUser(req, 'investor'), Number(ctx.m[1]), { accept: ctx.body.accept, signature: ctx.body.signature }, ctx.ip)) }));
/* profile, 2FA, complaints, assistant */
route('PUT', /^\/api\/profile$/, (req, res, ctx) => {
  const u = requireUser(req); const rt = ctx.body.riskTolerance, ex = ctx.body.experience;
  if (rt !== undefined && !['low', 'medium', 'high'].includes(rt)) throw bad(); if (ex !== undefined && !['beginner', 'intermediate', 'expert'].includes(ex)) throw bad();
  db.prepare('UPDATE users SET risk_tolerance=COALESCE(?,risk_tolerance), experience=COALESCE(?,experience) WHERE id=?').run(rt ?? null, ex ?? null, u.id); return { ok: true };
});
route('POST', /^\/api\/2fa\/setup$/, req => {
  const u = requireUser(req); if (db.prepare('SELECT totp_enabled FROM users WHERE id=?').get(u.id).totp_enabled) throw bad('kyc_locked');
  const secret = b32enc(crypto.randomBytes(20)); db.prepare('UPDATE users SET totp_secret=? WHERE id=?').run(secret, u.id);
  return { secret, uri: `otpauth://totp/TamweelShares:${encodeURIComponent(u.email)}?secret=${secret}&issuer=TamweelShares` };
});
route('POST', /^\/api\/2fa\/enable$/, (req, res, ctx) => {
  const u = requireUser(req); const r = db.prepare('SELECT totp_secret FROM users WHERE id=?').get(u.id);
  if (!r.totp_secret || !totpValid(r.totp_secret, ctx.body.code)) throw bad('bad_code');
  db.prepare('UPDATE users SET totp_enabled=1 WHERE id=?').run(u.id); audit(u.id, '2fa.enabled', 'user', u.id, null); return { ok: true };
});
route('POST', /^\/api\/2fa\/disable$/, (req, res, ctx) => {
  const u = requireUser(req); limit('2fa:' + u.id, 10, 15 * 60_000); const r = db.prepare('SELECT pass_hash,totp_secret,totp_enabled FROM users WHERE id=?').get(u.id);
  if (!r.totp_enabled || !verifyPassword(String(ctx.body.password || ''), r.pass_hash) || !totpValid(r.totp_secret, ctx.body.code)) throw bad('bad_code');
  db.prepare('UPDATE users SET totp_enabled=0,totp_secret=NULL WHERE id=?').run(u.id); audit(u.id, '2fa.disabled', 'user', u.id, null); return { ok: true };
});
route('POST', /^\/api\/complaints$/, (req, res, ctx) => { const u = requireUser(req); limit('cmp:' + u.id, 10, 60 * 60_000);
  const r = db.prepare('INSERT INTO complaints(user_id,project_id,subject,body,created) VALUES(?,?,?,?,?)').run(u.id, ctx.body.projectId ? int(ctx.body.projectId, 1, 1e9) : null, str(ctx.body.subject, 3, 150), str(ctx.body.body, 10, 3000), now());
  audit(u.id, 'complaint.created', 'complaint', Number(r.lastInsertRowid), null); return { id: Number(r.lastInsertRowid) }; }, { limit: 6_000 });
route('GET', /^\/api\/complaints\/mine$/, req => db.prepare('SELECT id,subject,body,status,reply,created FROM complaints WHERE user_id=? ORDER BY id DESC').all(requireUser(req).id));
route('POST', /^\/api\/assistant$/, async (req, res, ctx) => { const u = requireUser(req); limit('ai:' + u.id, 20, 60 * 60_000); return await askAssistant(u, ctx.body); }, { limit: 3_000 });
/* admin */
route('GET', /^\/api\/admin\/exits$/, req => { requireUser(req, 'admin'); return db.prepare(EXIT_SELECT.replace('SELECT e.*,', 'SELECT e.*, (SELECT name FROM users WHERE id=e.seller_id) seller,') + " WHERE e.status IN('pending','open') ORDER BY e.id DESC").all().map(e => ({ ...exitOut(e), seller: e.seller })); });
route('POST', /^\/api\/admin\/exits\/(\d+)$/, (req, res, ctx) => {
  const a = requireUser(req, 'admin'); const d = ctx.body.decision; if (!['approved', 'rejected'].includes(d)) throw bad();
  const e = db.prepare("SELECT * FROM exits WHERE id=? AND status='pending'").get(Number(ctx.m[1])); if (!e) throw new HttpError(404, 'not_found');
  db.prepare('UPDATE exits SET status=? WHERE id=?').run(d === 'approved' ? 'open' : 'rejected', e.id); audit(a.id, 'exit.' + d, 'exit', e.id, null); notify(e.seller_id, 'exit_' + d, e.project_id, {}); return { ok: true };
});
route('GET', /^\/api\/admin\/complaints$/, req => { requireUser(req, 'admin'); return db.prepare('SELECT c.*,u.name FROM complaints c JOIN users u ON u.id=c.user_id ORDER BY (c.status=\'open\') DESC, c.id DESC LIMIT 200').all(); });
route('POST', /^\/api\/admin\/complaints\/(\d+)$/, (req, res, ctx) => {
  const a = requireUser(req, 'admin'); const c = db.prepare('SELECT * FROM complaints WHERE id=?').get(Number(ctx.m[1])); if (!c) throw new HttpError(404, 'not_found');
  db.prepare("UPDATE complaints SET status='resolved', reply=? WHERE id=?").run(str(ctx.body.reply, 1, 2000), c.id); audit(a.id, 'complaint.resolved', 'complaint', c.id, null); notify(c.user_id, 'complaint_resolved', null, {}); return { ok: true };
}, { limit: 4_000 });
route('POST', /^\/api\/admin\/projects\/(\d+)\/financials\/verify$/, (req, res, ctx) => { verifyFinancials(requireUser(req, 'admin'), Number(ctx.m[1]), ctx.body.months, !!ctx.body.verified); return { ok: true }; });
route('GET', /^\/api\/admin\/overview$/, req => { requireUser(req, 'admin'); return adminOverview(); });
route('GET', /^\/api\/admin\/users$/, req => { requireUser(req, 'admin'); return adminUsers(); });
route('GET', /^\/api\/admin\/kyc$/, req => { requireUser(req, 'admin'); return adminKycQueue(); });
route('POST', /^\/api\/admin\/kyc\/(\d+)$/, (req, res, ctx) => { adminDecideKyc(requireUser(req, 'admin'), Number(ctx.m[1]), ctx.body); return { ok: true }; });
route('GET', /^\/api\/admin\/projects$/, req => { requireUser(req, 'admin'); return adminProjects(); });
route('POST', /^\/api\/admin\/projects\/(\d+)\/review$/, (req, res, ctx) => { adminReview(requireUser(req, 'admin'), Number(ctx.m[1]), ctx.body); return { ok: true }; }, { limit: 12_000 });
route('GET', /^\/api\/admin\/withdrawals$/, req => { requireUser(req, 'admin'); return adminWithdrawals(); });
route('POST', /^\/api\/admin\/withdrawals\/(\d+)$/, (req, res, ctx) => { adminDecideWithdrawal(requireUser(req, 'admin'), Number(ctx.m[1]), ctx.body.decision); return { ok: true }; });
route('GET', /^\/api\/admin\/transactions$/, req => { requireUser(req, 'admin'); return adminTransactions(); });
route('GET', /^\/api\/admin\/audit$/, req => { requireUser(req, 'admin'); return adminAudit(); });

const INDEX = path.join(__dirname, 'index.html');
function securityHeaders(res) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'same-origin');
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Content-Security-Policy',
    "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'");
  if (PROD) res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
}
function readBody(req, maxBytes) {
  return new Promise((resolve, reject) => {
    let size = 0; const chunks = [];
    req.on('data', c => { size += c.length; if (size > maxBytes) { reject(new HttpError(413, 'too_large')); req.destroy(); } else chunks.push(c); });
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
        body = await readBody(req, r.limit);
      }
      const out = await r.fn(req, res, { body, ip, m: url.pathname.match(r.re) });
      if (out === HANDLED) return;
      return send(res, 200, out);
    }
    if (req.method === 'GET' && url.pathname === '/analysis.js') {
      res.writeHead(200, { 'Content-Type': 'application/javascript; charset=utf-8' });
      return fs.createReadStream(path.join(__dirname, 'analysis.js')).pipe(res);
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

/* ---------- admin bootstrap & optional demo seed ---------- */
function insertAdmin(name, email, password) {
  if (db.prepare('SELECT 1 FROM users WHERE email=?').get(email)) return;
  db.prepare("INSERT INTO users(name,email,pass_hash,role,kyc_status,created) VALUES(?,?,?,'admin','approved',?)")
    .run(name, email, hashPassword(password), now());
}
if (process.env.ADMIN_EMAIL && process.env.ADMIN_PASSWORD) {
  if (process.env.ADMIN_PASSWORD.length < 10) throw new Error('ADMIN_PASSWORD must be at least 10 characters');
  insertAdmin('Admin', process.env.ADMIN_EMAIL.toLowerCase(), process.env.ADMIN_PASSWORD);
}
function seedDemo() {
  if (db.prepare('SELECT COUNT(*) c FROM users').get().c) return;
  const pw = process.env.DEMO_PASSWORD || 'demo12345';
  insertAdmin('مدير المنصة', 'admin@demo.com', pw);
  const owner = { id: signup({ name: 'صاحب مشروع تجريبي', email: 'owner@demo.com', password: pw, role: 'owner', company: 'شركة الوادي للتجارة' }) };
  const inv = { id: signup({ name: 'مستثمر تجريبي', email: 'investor@demo.com', password: pw, role: 'investor' }) };
  db.prepare("UPDATE users SET kyc_status='approved' WHERE id=?").run(inv.id);
  const mk = (b, risk) => { const id = createProject(owner, b, 'approved'); db.prepare('UPDATE projects SET risk=? WHERE id=?').run(risk, id); return id; };
  mk({ title: 'مزرعة الوادي الأخضر للزيتون', category: 'agri', goal: 50000, sharePrice: 100, location: 'الفيوم', foundedYear: 2016, branches: 1, employees: 14,
    monthlySales: 18000, monthlyProfit: 5200, durationMonths: 24, expectedReturn: 18, minShares: 5,
    description: 'توسعة مزرعة الزيتون العائلية بمعصرة جديدة و٢٠٠٠ شجرة إضافية. يأتي الدخل من بيع زيت الزيتون الفاخر.',
    useOfFunds: 'معصرة حديثة ٦٠٪، شتلات وري ٣٠٪، تسويق ١٠٪', profitTerms: 'توزيع ربع سنوي بنسبة الأسهم من صافي الربح المعتمد', exitTerms: 'تخارج بعد ٢٤ شهرًا أو بيع الحصص لمستثمر آخر بموافقة المنصة' }, 'medium');
  mk({ title: 'محمصة قهوة المدينة', category: 'food', goal: 30000, sharePrice: 50, location: 'القاهرة', foundedYear: 2019, branches: 2, employees: 9,
    monthlySales: 24000, monthlyProfit: 6100, durationMonths: 18, expectedReturn: 22, minShares: 10,
    description: 'محمصة قهوة تزوّد ٣٠ مقهى في الحي. تُستخدم الأموال لشراء آلة تحميص ثانية وخط تغليف.',
    useOfFunds: 'آلة تحميص ٥٥٪، خط تغليف ٣٠٪، مخزون ١٥٪', profitTerms: 'توزيع شهري من صافي الربح', exitTerms: 'تخارج بعد ١٨ شهرًا' }, 'low');
  mk({ title: 'ألواح شمسية لمدرسة النور', category: 'energy', goal: 80000, sharePrice: 200, location: 'الجيزة', foundedYear: 2021, branches: 1, employees: 4,
    monthlySales: 9000, monthlyProfit: 4000, durationMonths: 36, expectedReturn: 14,
    description: 'تركيب ألواح شمسية على السطح وبيع فائض الكهرباء للشبكة. يُوزَّع الدخل من مبيعات الطاقة الشهرية.',
    useOfFunds: 'ألواح ومحولات ٨٥٪، تركيب ١٠٪، صيانة ٥٪', profitTerms: 'توزيع نصف سنوي', exitTerms: 'تخارج بعد ٣٦ شهرًا' }, 'high');
  createProject(owner, { title: 'مصنع تغليف جديد (قيد المراجعة)', category: 'other', goal: 60000, sharePrice: 100,
    description: 'طلب تمويل جديد في انتظار مراجعة الإدارة والمستندات.' });
  const sign = { accept: true, signature: 'مستثمر تجريبي' };
  deposit(inv, 25000_00); buyShares(inv, 1, 120, sign); buyShares(inv, 2, 80, sign);
  const seedRows = []; for (let m = 1; m <= 9; m++) seedRows.push({ month: '2026-0' + m, revenue: 17000 + m * 450 + (m % 3) * 300, cogs: 6200 + (m % 4) * 150, direct: 900, indirect: 700, payroll: 3900, rent: 1500, utilities: 450, commissions: 200, marketing: 600, other: 250, debtPayments: 400, liabilities: 14000 - m * 300 });
  saveFinancials(owner, 1, seedRows); verifyFinancials({ id: 0 }, 1, seedRows.slice(0, 5).map(r => r.month), true);
  createReport(owner, 1, { month: '2026-09', summary: 'ارتفعت المبيعات بفضل موسم الحصاد وتم تركيب المعصرة الجديدة.', sales: 21000, expenses: 15500, challenges: 'ارتفاع تكلفة العبوات', nextPlan: 'البدء في زراعة ٥٠٠ شجرة جديدة' });
  createPost(owner, 1, { body: 'تم الانتهاء من تركيب المعصرة وبدء التشغيل التجريبي.' });
  createPoll(owner, 1, { question: 'هل توافقون على إعادة استثمار ٢٠٪ من أرباح الربع القادم في التوسعة؟', options: ['نعم', 'لا'], days: 14 });
  distributePayout(owner, 1, 1200_00, 'مبيعات الزيت للربع الثالث');
  console.log('Seeded demo accounts: admin@demo.com / owner@demo.com / investor@demo.com');
}
if (process.env.SEED_DEMO === '1') seedDemo();

server.listen(PORT, () => console.log(`Tamweel Shares running on http://localhost:${PORT}`));
