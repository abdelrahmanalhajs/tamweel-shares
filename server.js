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
  pass_hash TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN('investor','owner','admin')),
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
  type TEXT NOT NULL CHECK(type IN('deposit','invest','income','withdraw','refund')),
  amount_cents INTEGER NOT NULL, project_id INTEGER REFERENCES projects(id), note TEXT, created INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS withdrawals(
  id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id), tx_id INTEGER NOT NULL REFERENCES wallet_tx(id),
  amount_cents INTEGER NOT NULL, destination TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN('pending','paid','rejected')), created INTEGER NOT NULL, processed INTEGER);
CREATE TABLE IF NOT EXISTS audit(
  id INTEGER PRIMARY KEY, actor_id INTEGER, action TEXT NOT NULL, entity TEXT NOT NULL, entity_id INTEGER, detail TEXT, created INTEGER NOT NULL);
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
const PROJECT_SELECT = `SELECT p.*, u.name owner_name, u.company_name owner_company,
  COALESCE((SELECT SUM(shares) FROM investments WHERE project_id=p.id),0) sold
  FROM projects p JOIN users u ON u.id=p.owner_id`;
const docOut = d => ({ id: d.id, kind: d.kind, filename: d.filename, size: d.size, created: d.created });
const docsOf = pid => db.prepare('SELECT * FROM documents WHERE project_id=? ORDER BY id').all(pid).map(docOut);
const orNull = v => (v === null || v === undefined ? null : v);
function projectOut(p, { private: priv = false } = {}) {
  const o = {
    id: p.id, title: p.title, category: p.category, description: p.description, owner: p.owner_company || p.owner_name,
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
function buyShares(user, projectId, shares) {
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
    db.prepare('INSERT INTO investments(project_id,user_id,shares,amount_cents,created) VALUES(?,?,?,?,?)').run(p.id, user.id, shares, cost, t);
    db.prepare('INSERT INTO wallet_tx(user_id,type,amount_cents,project_id,note,created) VALUES(?,?,?,?,?,?)').run(user.id, 'invest', -cost, p.id, null, t);
    audit(user.id, 'investment.created', 'project', p.id, { shares, amount: dollars(cost) });
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
}
function adminProjects() {
  return db.prepare(PROJECT_SELECT + ' ORDER BY p.id DESC').all().map(p => ({ ...projectOut(p, { private: true }), ownerName: p.owner_name, ownerEmail: db.prepare('SELECT email FROM users WHERE id=?').get(p.owner_id).email }));
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
  const full = db.prepare('SELECT phone,kyc_status,kyc_note,company_name FROM users WHERE id=?').get(u.id);
  return { user: { id: u.id, name: u.name, email: u.email, role: u.role, phone: full.phone, company: full.company_name,
    kyc: full.kyc_status, kycNote: full.kyc_note,
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
  return { balance: dollars(buyShares(u, Number(ctx.m[1]), int(ctx.body.shares, 1, 1_000_000))) };
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
/* admin */
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
      const out = r.fn(req, res, { body, ip, m: url.pathname.match(r.re) });
      if (out === HANDLED) return;
      return send(res, 200, out);
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
  deposit(inv, 25000_00); buyShares(inv, 1, 120); buyShares(inv, 2, 80);
  distributePayout(owner, 1, 1200_00, 'مبيعات الزيت للربع الثالث');
  console.log('Seeded demo accounts: admin@demo.com / owner@demo.com / investor@demo.com');
}
if (process.env.SEED_DEMO === '1') seedDemo();

server.listen(PORT, () => console.log(`Tamweel Shares running on http://localhost:${PORT}`));
