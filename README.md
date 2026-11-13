# Tamweel Shares (تمويل شيرز)

Investment crowdfunding platform: owners apply for funding, admins verify and rate projects, verified investors buy shares, sign contracts, follow performance and withdraw income. Arabic (default, RTL) + English. Node 22.5+ and built-in SQLite — **no npm dependencies**.

## Run locally
```bash
npm run dev   # seeds demo data. Logins (password demo12345): admin@demo.com, owner@demo.com, investor@demo.com
```
Production: `ADMIN_EMAIL=you@x.com ADMIN_PASSWORD='long-password' NODE_ENV=production npm start` (creates the first admin; DB starts empty).
Optional `ANTHROPIC_API_KEY` enables AI document reading and the investor assistant.

**GitHub Pages / static hosts:** no server, so `index.html` falls back to a browser-only demo (localStorage): marketplace, wallet, analysis, simulator, compare. Admin, KYC, uploads, contracts, community, polls, notifications, resale market and 2FA need the Node server.

## Phase 1 — core
Accounts (scrypt, HttpOnly sessions, rate limits), roles, KYC with document upload, funding applications, admin review/risk rating, search & filters, calculator, wallet with admin-approved withdrawals, audit log, admin reports.

## Phase 2 — analysis
Monthly financial statements (form / CSV / optional AI document reader) → **rule-based, explainable analyzer** (`analysis.js`): margins, break-even, growth, cash flow, debt, 0–100 rating with per-component reasons, suggested risk, anomaly & fraud-style flags (declared-vs-actual mismatch, expense spikes, identical/round figures, rising debt…), indicative valuation, admin month-by-month verification. **Expansion simulator** (cost, funding, break-even, payback, 3 scenarios).

## Phase 3 — investment management
Digital contracts (accepted with typed signature, timestamp, IP and SHA-256 fingerprint; document vault), monthly owner reports, in-app notifications, follow projects.

## Phase 4 — AI
Rule-based risk/fraud detection, project comparison (up to 4), indicative valuation, growth simulator; optional LLM document reader and assistant (answers only from platform data, no investment decisions, no guaranteed returns).

## Phase 5 — advanced
Exit / resale market (listing → admin approval → purchase with new contract and ownership transfer), investor polls weighted by shares, Q&A and updates, owner track record, recommendations by risk profile, investment academy, complaints centre, TOTP two-factor login.

## Not included (needs third parties / licences)
SMS OTP, qualified e-signature provider, real payment gateway, licensed escrow/custody, OCR for scanned bank statements beyond the optional LLM reader, platform-fee accounting. Selling shares to the public needs regulatory licensing (e.g. FRA in Egypt) before real money. The resale market in particular requires a licence.

## Deploy
`Dockerfile` + `render.yaml` (persistent disk at `/data` for DB and uploads).
