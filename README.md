# Money Hunter20 — Backend Starter

## Stack
- Node.js + Express
- PostgreSQL
- JWT session layer
- Telegram Mini App-ready architecture

## Setup
1. Install Node.js 20+ and PostgreSQL.
2. Create a PostgreSQL database.
3. Run `schema.sql` against that database.
4. Copy `.env.example` to `.env` and fill in real values.
5. Run:
   `npm install`
   `npm run dev`

Health check:
`GET /api/health`

## Next production modules
1. Server-side Telegram WebApp initData verification
2. Secure earning event verification
3. Referral attribution
4. Daily bonus endpoint with server-side date lock
5. Withdrawal request + admin approval
6. Admin authentication/roles
7. Rate limits, fraud detection and audit logs
8. Connect the existing Money Hunter20 frontend to `/api/me` and `/api/activity`

Never put database credentials or the Telegram bot token in frontend JavaScript.
