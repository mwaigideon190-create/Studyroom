# Study Room (live)

Node server + web pages. The server serves `public/index.html` (students and affiliates) and `public/admin.html` (admin). Both pages carry their own styling.

## Deploy (Render + Postgres)
1. New GitHub repo. Upload everything in this folder, keeping the `public` folder.
2. Make a free Postgres database (Neon or Supabase) and copy its connection string.
3. On Render: New > Blueprint (uses render.yaml), or New > Web Service. Use a paid instance, because free ones sleep and can miss the Saturday 6:00 AM payout.
4. Fill in every variable from `.env.example` in Render > Environment. Set BASE_URL to your Render address.
5. Open `https://YOUR-APP/` for students and `https://YOUR-APP/admin.html` for admin.

## Daraja checklist
- STK Push: needs your Paybill shortcode and Lipa Na M-Pesa passkey. The callback address is built from BASE_URL and CALLBACK_SECRET automatically.
- Payouts use B2C. Your Paybill must have B2C enabled with an initiator name and password from Safaricom. Put Safaricom's production certificate in MPESA_CERT (newlines written as \n).
- Fund the B2C account before Saturday, or payouts fail and are refunded to the affiliate balance.
- Test everything with MPESA_ENV=sandbox first.

## Money rules (in server.js)
- Payment of 150: affiliate with an approved code gets 35, main account gets 115. No code or unapproved code: main gets 150.
- Each M-Pesa receipt is credited once only.
- Payouts run Saturday 06:00 Nairobi time. A failed payout returns to the affiliate balance. A timed-out one is marked "review" for you to check on your M-Pesa statement.

## Free Render and Saturday payouts
Free Render instances sleep after 15 minutes without visits, so a timer inside the server can miss Saturday 06:00. This version handles that:
1. Set a free pinger (cron-job.org) to open `https://YOUR-APP/health` every 10 minutes. This keeps the server awake.
2. Add a second job on Saturday at 06:05 (Nairobi time) opening `https://YOUR-APP/api/cron/YOUR_CALLBACK_SECRET`. It wakes the server and pays if the payout has not run.
3. If the server was asleep anyway, the payout runs as soon as it wakes. Each Saturday slot is paid once only.
A paid Render instance is safer once real money is moving.
