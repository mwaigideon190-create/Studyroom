const express = require("express"), crypto = require("crypto"), { Pool } = require("pg");
const nodemailer = require("nodemailer"), cron = require("node-cron");
const E = process.env, app = express();
app.use(express.json({ limit: "50kb" })); app.set("trust proxy", 1);
app.use((req, res, n) => { res.set("X-Content-Type-Options", "nosniff"); n(); });

const PRICE = 150, AFF = 35, SECRET = E.TOKEN_SECRET, CB = E.CALLBACK_SECRET;
const pool = new Pool({ connectionString: E.DATABASE_URL, ssl: /localhost/.test(E.DATABASE_URL || "") ? false : { rejectUnauthorized: false } });
const q = (s, p) => pool.query(s, p).then(r => r.rows);
async function tx(fn) {
  const c = await pool.connect();
  try { await c.query("BEGIN"); const r = await fn(c); await c.query("COMMIT"); return r; }
  catch (e) { await c.query("ROLLBACK"); throw e; } finally { c.release(); }
}
const sha = s => crypto.createHash("sha256").update(String(s)).digest("hex");
const hmac = b => crypto.createHmac("sha256", SECRET).update(b).digest("base64url");
const sign = o => { const b = Buffer.from(JSON.stringify(o)).toString("base64url"); return b + "." + hmac(b); };
const read = t => { try { const [b, s] = t.split("."); if (!crypto.timingSafeEqual(Buffer.from(s), Buffer.from(hmac(b)))) return null; const o = JSON.parse(Buffer.from(b, "base64url")); return o.exp > Date.now() ? o : null; } catch { return null; } };
const hash = p => { const s = crypto.randomBytes(16).toString("hex"); return s + ":" + crypto.scryptSync(p, s, 64).toString("hex"); };
const verifyPw = (p, h) => { const [s, k] = h.split(":"); return crypto.timingSafeEqual(Buffer.from(k, "hex"), crypto.scryptSync(p, s, 64)); };
const same = (a, b) => crypto.timingSafeEqual(Buffer.from(sha(a)), Buffer.from(sha(b)));
const auth = role => (req, res, n) => { const t = read((req.headers.authorization || "").slice(7)); if (!t || t.role !== role) return res.status(401).json({ error: "Please log in." }); req.t = t; n(); };
const hits = new Map();
const limit = (req, res, n) => { const now = Date.now(), a = (hits.get(req.ip) || []).filter(t => now - t < 9e5); a.push(now); hits.set(req.ip, a); a.length > 40 ? res.status(429).json({ error: "Too many attempts. Try again later." }) : n(); };
const W = f => (req, res) => f(req, res).catch(e => { console.error(e); if (!res.headersSent) res.status(500).json({ error: "Server error. Try again." }); });
const phone = p => { p = String(p || "").replace(/[\s+]/g, ""); if (/^0[17]\d{8}$/.test(p)) p = "254" + p.slice(1); return /^254[17]\d{8}$/.test(p) ? p : null; };
const low = s => String(s || "").toLowerCase().trim();
function nextSat() { const d = new Date(); d.setUTCHours(3, 0, 0, 0); d.setUTCDate(d.getUTCDate() + (6 - d.getUTCDay() + 7) % 7); if (d <= Date.now()) d.setUTCDate(d.getUTCDate() + 7); return d.getTime(); }

// ---------- email codes ----------
const port = +E.SMTP_PORT || 465;
const mail = nodemailer.createTransport({ host: E.SMTP_HOST, port, secure: port === 465, auth: { user: E.SMTP_USER, pass: E.SMTP_PASS } });
async function sendOtp(email, kind) {
  const code = String(crypto.randomInt(1e5, 1e6)), min = kind === "login" ? 1 : 10;
  await q("INSERT INTO otps(email,code,kind,exp,tries)VALUES($1,$2,$3,$4,0)ON CONFLICT(email)DO UPDATE SET code=$2,kind=$3,exp=$4,tries=0", [email, sha(code), kind, Date.now() + min * 6e4]);
  await mail.sendMail({ from: E.SMTP_USER, to: email, subject: "Your Study Room code", text: `Your code is ${code}. It expires in ${min} minute${min > 1 ? "s" : ""}. If you did not ask for it, ignore this email.` });
}
async function checkOtp(email, code, kind) {
  const [o] = await q("SELECT * FROM otps WHERE email=$1", [email]);
  if (!o || o.kind !== kind || +o.exp < Date.now() || o.tries >= 5) return false;
  if (o.code !== sha(code)) { await q("UPDATE otps SET tries=tries+1 WHERE email=$1", [email]); return false; }
  await q("DELETE FROM otps WHERE email=$1", [email]); return true;
}

// ---------- affiliate codes (1STUI00001 ... 1STUI05000) ----------
async function approve(id) {
  const [u] = await q("SELECT approved FROM users WHERE id=$1", [id]);
  if (!u || u.approved) return false;
  try {
    const [{ n }] = await q("SELECT nextval('code_seq') n");
    await q("UPDATE users SET code='1STUI'||lpad($2::text,5,'0'),approved=true WHERE id=$1 AND approved=false", [id, n]);
    return true;
  } catch { return false; } // pool of 5000 used up
}
const setting = async k => ((await q("SELECT val FROM settings WHERE key=$1", [k]))[0] || {}).val;

// ---------- auth routes ----------
app.post("/api/signup", limit, W(async (req, res) => {
  const { role, password } = req.body, ph = phone(req.body.phone), em = low(req.body.email);
  if (!["stu", "aff"].includes(role) || !ph || !/^\S+@\S+\.\S+$/.test(em) || String(password || "").length < 6) return res.status(400).json({ error: "Please check your details." });
  const ref = role === "stu" ? String(req.body.ref || "").toUpperCase().trim() : null;
  const [ex] = await q("SELECT id,ver FROM users WHERE email=$1", [em]);
  if (ex && ex.ver) return res.status(400).json({ error: "That email is already registered." });
  if (ex) await q("UPDATE users SET phone=$2,pw=$3,role=$4,ref=$5 WHERE id=$1", [ex.id, ph, hash(password), role, ref]);
  else await q("INSERT INTO users(role,phone,email,pw,ref)VALUES($1,$2,$3,$4,$5)", [role, ph, em, hash(password), ref]);
  await sendOtp(em, "verify"); res.json({ ok: true });
}));
const tok = id => sign({ role: "user", id, exp: Date.now() + 6048e5 });
app.post("/api/verify", limit, W(async (req, res) => {
  const em = low(req.body.email);
  if (!await checkOtp(em, req.body.code, "verify")) return res.status(400).json({ error: "Wrong or expired code." });
  const [u] = await q("UPDATE users SET ver=true WHERE email=$1 RETURNING *", [em]);
  if (u.role === "aff" && !u.approved && await setting("auto") !== "off") await approve(u.id);
  res.json({ token: tok(u.id) });
}));
app.post("/api/login", limit, W(async (req, res) => {
  const em = low(req.body.email), [u] = await q("SELECT * FROM users WHERE email=$1 AND ver", [em]);
  if (!u || !verifyPw(String(req.body.password || ""), u.pw)) return res.status(401).json({ error: "Wrong email or password." });
  await sendOtp(em, "login"); res.json({ ok: true });
}));
app.post("/api/login/verify", limit, W(async (req, res) => {
  const em = low(req.body.email);
  if (!await checkOtp(em, req.body.code, "login")) return res.status(400).json({ error: "Wrong or expired code." });
  const [u] = await q("SELECT id FROM users WHERE email=$1", [em]); res.json({ token: tok(u.id) });
}));
app.get("/api/me", auth("user"), W(async (req, res) => {
  const [u] = await q("SELECT id,role,phone,email,paid,approved,code,bal FROM users WHERE id=$1", [req.t.id]);
  const refs = u.role === "aff" && u.approved ? await q("SELECT right(phone,3) p FROM users WHERE ref_by=$1 ORDER BY id", [u.id]) : [];
  res.json({ ...u, refs, next: nextSat() });
}));
app.get("/api/complaints", auth("user"), W(async (req, res) => res.json(await q("SELECT type,msg,status FROM complaints WHERE user_id=$1 ORDER BY id DESC", [req.t.id]))));
app.post("/api/complaints", auth("user"), W(async (req, res) => {
  const t = ["Complaint about account affiliation", "Complaint about affiliator account"].includes(req.body.type) ? req.body.type : null, m = String(req.body.msg || "").slice(0, 1000);
  if (!t || !m) return res.status(400).json({ error: "Please describe the problem." });
  await q("INSERT INTO complaints(user_id,type,msg)VALUES($1,$2,$3)", [req.t.id, t, m]); res.json({ ok: true });
}));

// ---------- Daraja ----------
const BASE = E.MPESA_ENV === "production" ? "https://api.safaricom.co.ke" : "https://sandbox.safaricom.co.ke";
async function dpost(path, body) {
  const t = await (await fetch(BASE + "/oauth/v1/generate?grant_type=client_credentials", { headers: { Authorization: "Basic " + Buffer.from(E.MPESA_KEY + ":" + E.MPESA_SECRET).toString("base64") } })).json();
  return (await fetch(BASE + path, { method: "POST", headers: { Authorization: "Bearer " + t.access_token, "Content-Type": "application/json" }, body: JSON.stringify(body) })).json();
}
app.post("/api/pay", auth("user"), W(async (req, res) => {
  const [u] = await q("SELECT * FROM users WHERE id=$1", [req.t.id]);
  if (u.role !== "stu" || u.paid) return res.status(400).json({ error: "Nothing to pay." });
  const ts = new Date().toISOString().replace(/\D/g, "").slice(0, 14), sc = E.MPESA_SHORTCODE;
  const d = await dpost("/mpesa/stkpush/v1/processrequest", { BusinessShortCode: sc, Password: Buffer.from(sc + E.MPESA_PASSKEY + ts).toString("base64"), Timestamp: ts, TransactionType: "CustomerPayBillOnline", Amount: PRICE, PartyA: u.phone, PartyB: sc, PhoneNumber: u.phone, CallBackURL: E.BASE_URL + "/api/mpesa/stk/" + CB, AccountReference: "StudyRoom", TransactionDesc: "Study Room access" });
  if (d.ResponseCode !== "0") return res.status(502).json({ error: "M-Pesa could not start the payment. Try again." });
  await q("INSERT INTO payments(user_id,checkout_id,amount)VALUES($1,$2,$3)", [u.id, d.CheckoutRequestID, PRICE]); res.json({ ok: true });
}));
app.post("/api/mpesa/stk/:s", W(async (req, res) => {
  res.json({ ResultCode: 0, ResultDesc: "OK" });
  if (req.params.s !== CB) return;
  const c = req.body && req.body.Body && req.body.Body.stkCallback; if (!c) return;
  const m = Object.fromEntries(((c.CallbackMetadata || {}).Item || []).map(i => [i.Name, i.Value]));
  if (c.ResultCode !== 0 || +m.Amount !== PRICE) return void await q("UPDATE payments SET status='failed' WHERE checkout_id=$1 AND status='pending'", [c.CheckoutRequestID]);
  await tx(async db => {
    const { rows: [p] } = await db.query("UPDATE payments SET status='paid',receipt=$2 WHERE checkout_id=$1 AND status='pending' RETURNING *", [c.CheckoutRequestID, m.MpesaReceiptNumber]);
    if (!p) return; // already processed: never credit twice
    const { rows: [u] } = await db.query("UPDATE users SET paid=true WHERE id=$1 RETURNING ref", [p.user_id]);
    const { rows: [a] } = u.ref ? await db.query("SELECT id,code FROM users WHERE role='aff' AND approved AND code=$1 FOR UPDATE", [u.ref]) : { rows: [] };
    if (a) {
      await db.query("UPDATE users SET bal=bal+$2 WHERE id=$1", [a.id, AFF]);
      await db.query("UPDATE users SET ref_by=$2 WHERE id=$1", [p.user_id, a.id]);
      await db.query("UPDATE accounts SET bal=bal+$1 WHERE name='general'", [PRICE - AFF]);
    } else await db.query("UPDATE accounts SET bal=bal+$1 WHERE name='general'", [PRICE]);
    await db.query("INSERT INTO ledger(note,amount)VALUES($1,$2)", [`${m.MpesaReceiptNumber}${a ? " via " + a.code : ""}`, PRICE]);
  });
}));

// ---------- Saturday 06:00 payouts (B2C) ----------
const cred = () => crypto.publicEncrypt({ key: (E.MPESA_CERT || "").replace(/\\n/g, "\n"), padding: crypto.constants.RSA_PKCS1_PADDING }, Buffer.from(E.MPESA_INITIATOR_PASS)).toString("base64");
async function refund(id) {
  await tx(async db => {
    const { rows: [p] } = await db.query("UPDATE payouts SET status='failed' WHERE id=$1 AND status='sending' RETURNING *", [id]);
    if (p) await db.query("UPDATE users SET bal=bal+$2 WHERE id=$1", [p.user_id, p.amount]);
  });
}
async function payout() {
  let n = 0;
  for (const u of await q("SELECT id,phone,bal FROM users WHERE role='aff' AND bal>=10")) {
    const amt = u.bal;
    const pid = await tx(async db => {
      if (!(await db.query("UPDATE users SET bal=bal-$2 WHERE id=$1 AND bal>=$2", [u.id, amt])).rowCount) return 0;
      return (await db.query("INSERT INTO payouts(user_id,phone,amount,status)VALUES($1,$2,$3,'sending')RETURNING id", [u.id, u.phone, amt])).rows[0].id;
    });
    if (!pid) continue;
    let d = {};
    try { d = await dpost("/mpesa/b2c/v1/paymentrequest", { InitiatorName: E.MPESA_INITIATOR, SecurityCredential: cred(), CommandID: "BusinessPayment", Amount: amt, PartyA: E.MPESA_B2C_SHORTCODE || E.MPESA_SHORTCODE, PartyB: u.phone, Remarks: "Affiliate payout", QueueTimeOutURL: E.BASE_URL + "/api/mpesa/b2c-timeout/" + CB, ResultURL: E.BASE_URL + "/api/mpesa/b2c/" + CB, Occasion: "Weekly" }); } catch (e) { console.error(e); }
    if (d.ResponseCode === "0") await q("UPDATE payouts SET orig=$2 WHERE id=$1", [pid, d.OriginatorConversationID]); else await refund(pid);
    n++;
  }
  return n;
}
app.post("/api/mpesa/b2c/:s", W(async (req, res) => {
  res.json({ ResultCode: 0, ResultDesc: "OK" });
  const r = req.body && req.body.Result; if (req.params.s !== CB || !r) return;
  const [p] = await q("SELECT id FROM payouts WHERE orig=$1", [r.OriginatorConversationID]); if (!p) return;
  if (r.ResultCode === 0) await q("UPDATE payouts SET status='paid',receipt=$2 WHERE id=$1 AND status='sending'", [p.id, r.TransactionID]); else await refund(p.id);
}));
app.post("/api/mpesa/b2c-timeout/:s", W(async (req, res) => {
  res.json({ ResultCode: 0, ResultDesc: "OK" });
  const r = req.body && req.body.Result; if (req.params.s !== CB || !r) return;
  await q("UPDATE payouts SET status='review' WHERE orig=$1 AND status='sending'", [r.OriginatorConversationID]); // admin checks M-Pesa statement
}));
app.get("/api/health", (req, res) => res.json({ ok: true }));
app.get("/api/cron/payout/:s", W(async (req, res) => { // for an outside scheduler; safe to call twice, balances are already zero after the first run
  if (req.params.s !== CB) return res.status(404).end();
  res.json({ sent: await payout() });
}));
// Most recent Saturday 06:00 Nairobi (= 03:00 UTC). runDue pays once per slot, even if the server was asleep at 06:00.
function lastSlot() { const d = new Date(); d.setUTCHours(3, 0, 0, 0); d.setUTCDate(d.getUTCDate() - (d.getUTCDay() + 1) % 7); if (d > Date.now()) d.setUTCDate(d.getUTCDate() - 7); return d.getTime(); }
async function runDue() {
  const s = lastSlot();
  await q("INSERT INTO settings(key,val)VALUES('last_payout',$1)ON CONFLICT DO NOTHING", [String(s)]);
  if ((await q("UPDATE settings SET val=$1 WHERE key='last_payout' AND val::bigint<$1 RETURNING key", [String(s)])).length) await payout();
}
cron.schedule("0 6 * * 6", () => runDue().catch(console.error), { timezone: "Africa/Nairobi" });
setInterval(() => runDue().catch(console.error), 5 * 6e4);
app.get("/health", (req, res) => res.send("ok"));
app.get("/api/cron/" + CB, W(async (req, res) => { await runDue(); res.json({ ok: true }); }));

// ---------- admin ----------
app.post("/api/admin/login", limit, W(async (req, res) => {
  if (!E.ADMIN_EMAIL || !E.ADMIN_PASSWORD || !same(low(req.body.email), low(E.ADMIN_EMAIL)) || !same(req.body.password || "", E.ADMIN_PASSWORD)) return res.status(401).json({ error: "Wrong details." });
  res.json({ token: sign({ role: "admin", exp: Date.now() + 288e5 }) });
}));
app.get("/api/admin/summary", auth("admin"), W(async (req, res) => {
  const acc = Object.fromEntries((await q("SELECT name,bal FROM accounts")).map(a => [a.name, a.bal]));
  const [s] = await q("SELECT (SELECT COALESCE(sum(bal),0)::int FROM users WHERE role='aff') owed,(SELECT COALESCE(sum(amount),0)::int FROM payouts WHERE status='paid') paidout,(SELECT count(*)::int FROM users WHERE paid) students,(SELECT count(*)::int FROM users WHERE code IS NOT NULL) used");
  res.json({ ...s, general: acc.general, adminBal: acc.admin, auto: await setting("auto") !== "off", next: nextSat(),
    affs: await q("SELECT id,email,phone,code,approved,bal FROM users WHERE role='aff' AND ver ORDER BY id DESC LIMIT 200"),
    complaints: await q("SELECT c.id,c.type,c.msg,c.status,u.email FROM complaints c JOIN users u ON u.id=c.user_id ORDER BY c.id DESC LIMIT 100"),
    payouts: await q("SELECT phone,amount,status,to_char(at,'DD Mon HH24:MI') at FROM payouts ORDER BY id DESC LIMIT 20") });
}));
app.post("/api/admin/approve/:id", auth("admin"), W(async (req, res) => res.json({ ok: await approve(+req.params.id) })));
app.post("/api/admin/auto", auth("admin"), W(async (req, res) => { await q("INSERT INTO settings(key,val)VALUES('auto',$1)ON CONFLICT(key)DO UPDATE SET val=$1", [req.body.on ? "on" : "off"]); res.json({ ok: true }); }));
app.post("/api/admin/credit", auth("admin"), W(async (req, res) => {
  const a = Math.floor(+req.body.amount); if (!(a >= 0)) return res.status(400).json({ error: "Invalid amount." });
  const ok = await tx(async db => {
    const { rows: [c] } = await db.query("SELECT user_id FROM complaints WHERE id=$1 AND status='Open' FOR UPDATE", [req.body.id]); if (!c) return false;
    if (a > 0) {
      if (!(await db.query("UPDATE accounts SET bal=bal-$1 WHERE name='general' AND bal>=$1", [a])).rowCount) return false;
      await db.query("UPDATE users SET bal=bal+$2 WHERE id=$1", [c.user_id, a]);
    }
    await db.query("UPDATE complaints SET status=$2 WHERE id=$1", [req.body.id, a ? `Resolved: KES ${a} credited` : "Resolved"]); return true;
  });
  res.status(ok ? 200 : 400).json(ok ? { ok } : { error: "Could not credit. Check the main account balance." });
}));
app.post("/api/admin/transfer", auth("admin"), W(async (req, res) => {
  const a = Math.floor(+req.body.amount);
  const ok = a > 0 && await tx(async db => { if (!(await db.query("UPDATE accounts SET bal=bal-$1 WHERE name='general' AND bal>=$1", [a])).rowCount) return false; await db.query("UPDATE accounts SET bal=bal+$1 WHERE name='admin'", [a]); return true; });
  res.status(ok ? 200 : 400).json(ok ? { ok } : { error: "Invalid amount or not enough in the main account." });
}));
app.post("/api/admin/payout-now", auth("admin"), W(async (req, res) => res.json({ sent: await payout() })));

app.use(express.static("public"));
(async () => {
  await q(`CREATE TABLE IF NOT EXISTS users(id serial PRIMARY KEY,role text,phone text,email text UNIQUE,pw text,ref text,ver bool DEFAULT false,paid bool DEFAULT false,approved bool DEFAULT false,code text UNIQUE,bal int DEFAULT 0,ref_by int);
CREATE TABLE IF NOT EXISTS otps(email text PRIMARY KEY,code text,kind text,exp bigint,tries int);
CREATE TABLE IF NOT EXISTS payments(id serial PRIMARY KEY,user_id int,checkout_id text UNIQUE,receipt text,status text DEFAULT 'pending',amount int);
CREATE TABLE IF NOT EXISTS accounts(name text PRIMARY KEY,bal int DEFAULT 0);
CREATE TABLE IF NOT EXISTS ledger(id serial PRIMARY KEY,note text,amount int,at timestamptz DEFAULT now());
CREATE TABLE IF NOT EXISTS payouts(id serial PRIMARY KEY,user_id int,phone text,amount int,status text,orig text,receipt text,at timestamptz DEFAULT now());
CREATE TABLE IF NOT EXISTS complaints(id serial PRIMARY KEY,user_id int,type text,msg text,status text DEFAULT 'Open',at timestamptz DEFAULT now());
CREATE TABLE IF NOT EXISTS settings(key text PRIMARY KEY,val text);
CREATE SEQUENCE IF NOT EXISTS code_seq MAXVALUE 5000;
INSERT INTO accounts(name)VALUES('general'),('admin')ON CONFLICT DO NOTHING;`);
  app.listen(E.PORT || 3000, () => { console.log("Study Room running"); runDue().catch(console.error); });
})();
