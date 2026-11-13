# Tamweel Shares (تمويل شيرز)

Crowdfunding with shares. Arabic (default, RTL) + English.
Node 22.5+ and SQLite (built in) — **no npm dependencies**.

On a static host (e.g. GitHub Pages) there is no server, so the same page runs in a **browser-only demo mode** (data in localStorage, banner shown). With the Node server it uses the real database.

## Run locally
```bash
npm run dev      # seeds demo accounts (owner@demo.com / investor@demo.com, password demo12345)
# open http://localhost:3000
```
Without `SEED_DEMO=1` the database starts empty (use this for production: `npm start`).

## What's inside
- Accounts: scrypt-hashed passwords, random session tokens (stored hashed) in an HttpOnly + SameSite cookie, login rate limiting, JSON-only mutations, security headers.
- SQLite database (`data/tamweel.db`, override with `DB_PATH`). Money is stored as integer cents; buying, payouts and withdrawals run in transactions.
- Investor wallet: income from payouts is credited to the wallet; investors buy shares from the wallet and can withdraw the balance.
- Owners: create projects, track funds/investors, distribute income by shares.

## Before real money
- `/api/wallet/deposit` is a **demo top-up** (disabled when `NODE_ENV=production` unless `ALLOW_DEMO_DEPOSIT=1`). Connect a payment provider for real deposits.
- Withdrawals are **recorded** only; paying them out to a bank needs a provider/manual process and an admin review step.
- Add email verification & password reset, HTTPS (set by your host), backups of the DB volume, and legal/licensing review for selling shares.

## Deploy
`Dockerfile` included; mount a persistent volume at `/data`.
