# Tamweel Shares (تمويل شيرز)

Investment crowdfunding platform: owners apply for funding, admins verify and rate projects, verified investors buy shares and withdraw their income. Arabic (default, RTL) + English. Node 22.5+ and built-in SQLite — **no npm dependencies**.

## Run locally
```bash
npm run dev   # seeds demo data. Logins (password demo12345): admin@demo.com, owner@demo.com, investor@demo.com
```
Production: `ADMIN_EMAIL=you@x.com ADMIN_PASSWORD='long-password' NODE_ENV=production npm start` (creates the first admin; database starts empty).

On a static host (GitHub Pages) there is no server, so the page falls back to a **browser-only demo mode** (localStorage). Admin, KYC and document upload exist only with the Node server.

## Implemented (Phase 1 of the spec)
- **Accounts & security:** scrypt passwords, hashed session tokens in HttpOnly/SameSite cookies, login rate limiting, JSON-only API, security headers, roles (investor / owner / admin).
- **KYC:** investors submit ID data + document; admin approves/rejects. Required before deposit, invest, withdraw.
- **Funding applications:** owners submit a detailed application (financials, terms, use of funds), upload documents (PDF/PNG/JPG ≤ 2 MB, type-checked, private); admin reviews, sets risk rating + verification note, approves/rejects. Only approved projects are public.
- **Marketplace:** search + filters (sector, risk, status), project details, risk disclosure, investment calculator (optimistic / realistic / conservative / worst case — assumptions only, never guaranteed).
- **Wallet:** income credited automatically; withdrawals are requests that an admin marks paid or rejects (rejection refunds the wallet).
- **Admin dashboard:** overview/report, KYC queue, applications, withdrawals, users, transactions, audit log (who did what, when).

## Not built yet (from the spec)
OTP/2FA, e-signed contracts, OCR/AI analysis & fraud detection, expansion simulator, monthly reports & notifications, fund-utilization tracking, investor community/voting, exit/secondary market, real payment & escrow integration. Selling shares to the public needs Egyptian regulatory licensing (e.g. FRA) and licensed escrow before real money.

## Deploy
`Dockerfile` + `render.yaml` included (persistent disk at `/data` for the database and uploaded documents).
