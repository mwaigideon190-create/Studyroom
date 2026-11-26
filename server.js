const express = require("express"), crypto = require("crypto");
const cron = require("node-cron");
const E = process.env, app = express();
app.use(express.json({ limit: "50kb" })); app.set("trust proxy", 1);
app.use((req, res, n) => { res.set("X-Content-Type-Options", "nosniff"); n(); });

const PRICE = 150, AFF = 35, SECRET = E.TOKEN_SECRET, CB = E.CALLBACK_SECRET;
// TEST_MODE=1 lets the app run with no Postgres and no M-Pesa. NEVER set it on the live site.
const TEST = E.TEST_MODE === "1", SQLITE = !E.DATABASE_URL;
if (SQLITE && !TEST) throw new Error("Set DATABASE_URL, or set TEST_MODE=1 for a test run.");
if (TEST) console.warn("*** TEST MODE: fake payments and payouts, data in a local file. Do not use for real money. ***");
let pool;
if (!SQLITE) {
  const { Pool } = require("pg");
  pool = new Pool({ connectionString: E.DATABASE_URL, ssl: /localhost/.test(E.DATABASE_URL) ? false : { rejectUnauthorized: false } });
} else {
  const { DatabaseSync } = require("node:sqlite"), db = new DatabaseSync(E.TEST_DB || "test.db");
  let lock = Promise.resolve();
  const run = (sql, p = []) => {
    sql = sql.replace(/\$(\d+)/g, "?$1").replace(/\s+FOR UPDATE/gi, "");
    const st = db.prepare(sql);
    if (/^\s*select/i.test(sql) || /returning/i.test(sql)) { const rows = st.all(...p); return { rows, rowCount: rows.length }; }
    return { rows: [], rowCount: Number(st.run(...p).changes) };
  };
  pool = {
    exec: s => db.exec(s),
    query: async (s, p) => run(s, p),
    connect: async () => { let rel; const prev = lock; lock = new Promise(r => rel = r); await prev;
      return { query: async (s, p) => /^\s*(BEGIN|COMMIT|ROLLBACK)/i.test(s) ? (db.exec(s), { rows: [], rowCount: 0 }) : run(s, p), release: () => rel() }; }
  };
}
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

// ---------- affiliate codes (1STUI00001 ... 1STUI05000) ----------
async function approve(id) {
  const [u] = await q("SELECT approved FROM users WHERE id=$1", [id]);
  if (!u || u.approved) return false;
  for (let i = 0; i < 5; i++) {
    const [{ n }] = await q("SELECT count(*) n FROM users WHERE code IS NOT NULL"), k = +n + 1;
    if (k > 5000) return false; // pool of 5000 used up
    try { await q("UPDATE users SET code=$2,approved=true WHERE id=$1 AND approved=false", [id, "1STUI" + String(k).padStart(5, "0")]); return true; } catch (e) { /* code taken at the same moment: retry */ }
  }
  return false;
}
const setting = async k => ((await q("SELECT val FROM settings WHERE key=$1", [k]))[0] || {}).val;
const myUnits = async id => { try { return JSON.parse((await setting("units:" + id)) || "[]"); } catch { return []; } };

// ---------- auth routes ----------
app.post("/api/signup", limit, W(async (req, res) => {
  const { role, password } = req.body, ph = phone(req.body.phone), em = low(req.body.email);
  if (!["stu", "aff"].includes(role) || !ph || !/^\S+@\S+\.\S+$/.test(em) || String(password || "").length < 6) return res.status(400).json({ error: "Please check your details." });
  const ref = role === "stu" ? String(req.body.ref || "").toUpperCase().trim() : null;
  if ((await q("SELECT id FROM users WHERE email=$1", [em])).length) return res.status(400).json({ error: "That email is already registered." });
  const [u] = await q("INSERT INTO users(role,phone,email,pw,ref,ver)VALUES($1,$2,$3,$4,$5,true)RETURNING *", [role, ph, em, hash(password), ref]);
  if (role === "aff" && await setting("auto") !== "off") await approve(u.id);
  res.json({ token: tok(u.id) });
}));
const tok = id => sign({ role: "user", id, exp: Date.now() + 3.15e11 });
app.post("/api/login", limit, W(async (req, res) => {
  const [u] = await q("SELECT * FROM users WHERE email=$1", [low(req.body.email)]);
  if (!u || !verifyPw(String(req.body.password || ""), u.pw)) return res.status(401).json({ error: "Wrong email or password." });
  res.json({ token: tok(u.id) });
}));
app.get("/api/me", auth("user"), W(async (req, res) => {
  const [u] = await q("SELECT id,role,phone,email,paid,approved,code,bal FROM users WHERE id=$1", [req.t.id]);
  const refs = u.role === "aff" && u.approved ? (await q("SELECT phone FROM users WHERE ref_by=$1 ORDER BY id", [u.id])).map(r => ({ p: String(r.phone).slice(-3) })) : [];
  res.json({ ...u, paid: isPaid(u), uni: await setting("uni:" + u.id), units: await myUnits(u.id), refs, next: nextSat() });
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
  if (TEST && !E.MPESA_KEY) { const cid = "TEST" + Date.now(); await q("INSERT INTO payments(user_id,checkout_id,amount)VALUES($1,$2,$3)", [u.id, cid, PRICE]); await credit(cid, "TEST" + u.id); return res.json({ ok: true }); }
  const ts = new Date().toISOString().replace(/\D/g, "").slice(0, 14), sc = E.MPESA_SHORTCODE;
  const d = await dpost("/mpesa/stkpush/v1/processrequest", { BusinessShortCode: sc, Password: Buffer.from(sc + E.MPESA_PASSKEY + ts).toString("base64"), Timestamp: ts, TransactionType: "CustomerPayBillOnline", Amount: PRICE, PartyA: u.phone, PartyB: sc, PhoneNumber: u.phone, CallBackURL: E.BASE_URL + "/api/mpesa/stk/" + CB, AccountReference: "StudyRoom", TransactionDesc: "Study Room access" });
  if (d.ResponseCode !== "0") return res.status(502).json({ error: "M-Pesa could not start the payment. Try again." });
  await q("INSERT INTO payments(user_id,checkout_id,amount)VALUES($1,$2,$3)", [u.id, d.CheckoutRequestID, PRICE]); res.json({ ok: true });
}));
async function credit(cid, receipt) {
  await tx(async db => {
    const { rows: [p] } = await db.query("UPDATE payments SET status='paid',receipt=$2 WHERE checkout_id=$1 AND status='pending' RETURNING *", [cid, receipt]);
    if (!p) return; // already processed: never credit twice
    const { rows: [u] } = await db.query("UPDATE users SET paid=true WHERE id=$1 RETURNING ref", [p.user_id]);
    const { rows: [a] } = u.ref ? await db.query("SELECT id,code FROM users WHERE role='aff' AND approved AND code=$1 FOR UPDATE", [u.ref]) : { rows: [] };
    if (a) {
      await db.query("UPDATE users SET bal=bal+$2 WHERE id=$1", [a.id, AFF]);
      await db.query("UPDATE users SET ref_by=$2 WHERE id=$1", [p.user_id, a.id]);
      await db.query("UPDATE accounts SET bal=bal+$1 WHERE name='general'", [PRICE - AFF]);
    } else await db.query("UPDATE accounts SET bal=bal+$1 WHERE name='general'", [PRICE]);
    await db.query("INSERT INTO ledger(note,amount)VALUES($1,$2)", [`${receipt}${a ? " via " + a.code : ""}`, PRICE]);
  });
}
app.post("/api/mpesa/stk/:s", W(async (req, res) => {
  res.json({ ResultCode: 0, ResultDesc: "OK" });
  if (req.params.s !== CB) return;
  const c = req.body && req.body.Body && req.body.Body.stkCallback; if (!c) return;
  const m = Object.fromEntries(((c.CallbackMetadata || {}).Item || []).map(i => [i.Name, i.Value]));
  if (c.ResultCode !== 0 || +m.Amount !== PRICE) return void await q("UPDATE payments SET status='failed' WHERE checkout_id=$1 AND status='pending'", [c.CheckoutRequestID]);
  await credit(c.CheckoutRequestID, m.MpesaReceiptNumber);
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
    if (TEST && !E.MPESA_KEY) { await q("UPDATE payouts SET status='paid',receipt='TEST' WHERE id=$1", [pid]); n++; continue; }
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
  const [r] = await q("SELECT val FROM settings WHERE key='last_payout'");
  if (+r.val < s && (await q("UPDATE settings SET val=$1 WHERE key='last_payout' AND val=$2 RETURNING key", [String(s), r.val])).length) await payout();
}
cron.schedule("0 6 * * 6", () => runDue().catch(console.error), { timezone: "Africa/Nairobi" });
setInterval(() => runDue().catch(console.error), 5 * 6e4);
app.get("/health", (req, res) => res.send("ok"));
app.get("/api/cron/" + CB, W(async (req, res) => { await runDue(); res.json({ ok: true }); }));

// ---------- admin ----------
app.post("/api/admin/login", limit, W(async (req, res) => {
  const phoneOk = !E.ADMIN_PHONE || same(phone(req.body.phone) || "x", phone(E.ADMIN_PHONE) || "y");
  if (!E.ADMIN_EMAIL || !E.ADMIN_PASSWORD || !phoneOk || !same(low(req.body.email), low(E.ADMIN_EMAIL)) || !same(req.body.password || "", E.ADMIN_PASSWORD)) return res.status(401).json({ error: "Wrong details." });
  res.json({ token: sign({ role: "admin", exp: Date.now() + 3.15e11 }) });
}));
const fmt = t => (t instanceof Date ? t : new Date(String(t).replace(" ", "T") + "Z")).toLocaleString("en-GB", { timeZone: "Africa/Nairobi", day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit" });
app.get("/api/admin/summary", auth("admin"), W(async (req, res) => {
  const acc = Object.fromEntries((await q("SELECT name,bal FROM accounts")).map(a => [a.name, a.bal]));
  const [s] = await q("SELECT (SELECT COALESCE(sum(bal),0) FROM users WHERE role='aff') owed,(SELECT COALESCE(sum(amount),0) FROM payouts WHERE status='paid') paidout,(SELECT count(*) FROM users WHERE paid) students,(SELECT count(*) FROM users WHERE code IS NOT NULL) used");
  res.json({ owed: +s.owed, paidout: +s.paidout, students: +s.students, used: +s.used, general: acc.general, adminBal: acc.admin, auto: await setting("auto") !== "off", next: nextSat(),
    affs: await q("SELECT id,email,phone,code,approved,bal FROM users WHERE role='aff' AND ver ORDER BY id DESC LIMIT 200"),
    complaints: await q("SELECT c.id,c.type,c.msg,c.status,u.email FROM complaints c JOIN users u ON u.id=c.user_id ORDER BY c.id DESC LIMIT 100"),
    payouts: (await q("SELECT phone,amount,status,at FROM payouts ORDER BY id DESC LIMIT 20")).map(p => ({ ...p, at: fmt(p.at) })) });
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


// ---------- university files (notes, past papers, CATs, exams) ----------
const CATS = ["Notes", "Past papers", "CATs", "Exams", "Quizzes"];
const UNIS = "University of Nairobi|Moi University|Kenyatta University|Egerton University|JKUAT|Maseno University|Masinde Muliro University of Science and Technology|Dedan Kimathi University of Technology|Chuka University|Technical University of Kenya|Technical University of Mombasa|Pwani University|Kisii University|University of Eldoret|Maasai Mara University|Jaramogi Oginga Odinga University of Science and Technology|Laikipia University|South Eastern Kenya University|Multimedia University of Kenya|University of Embu|Karatina University|Kibabii University|Garissa University|Taita Taveta University|Murang'a University of Technology|Machakos University|Meru University of Science and Technology|Kirinyaga University|Rongo University|Co-operative University of Kenya|Tom Mboya University|Alupe University|Tharaka University|Koitalel Samoei University|Mama Ngina University|Strathmore University|USIU-Africa|Daystar University|Catholic University of Eastern Africa|Mount Kenya University|Kenya Methodist University|KCA University|Africa Nazarene University|Pan Africa Christian University|Scott Christian University|Great Lakes University of Kisumu|Gretsa University|Kabarak University|University of Eastern Africa, Baraton|St. Paul's University|Adventist University of Africa|Aga Khan University|Kenya Highlands Evangelical University|Zetech University|Riara University|Lukenya University|Management University of Africa|Presbyterian University of East Africa|Africa International University|Tangaza University|Pioneer International University|Umma University|Inoorero University|Other".split("|");
// ---------- AI (needs ANTHROPIC_API_KEY; without it the app falls back to simple filename rules) ----------
const AIKEY = E.ANTHROPIC_API_KEY, AIMODEL = E.ANTHROPIC_MODEL || "claude-haiku-5-5";
async function ai(content, system, max) {
  if (!AIKEY) return null;
  try {
    const r = await fetch("https://api.anthropic.com/v1/messages", { method: "POST", signal: AbortSignal.timeout(60000), headers: { "x-api-key": AIKEY, "anthropic-version": "2023-06-01", "content-type": "application/json" }, body: JSON.stringify({ model: AIMODEL, max_tokens: max, system, messages: [{ role: "user", content }] }) });
    const d = await r.json(); if (!r.ok) throw new Error((d.error || {}).message || r.status);
    const m = (d.content || []).map(b => b.text || "").join("").match(/\{[\s\S]*\}/);
    return m ? JSON.parse(m[0]) : null;
  } catch (e) { console.error("AI:", e.message); return null; }
}
const SORT = "You sort study material for a Kenyan university study app. Reply with ONE JSON object and nothing else: {\"cat\":\"Notes|Past papers|CATs|Exams|Quizzes\",\"unit\":\"course unit name\",\"uni\":\"university\",\"title\":\"short title\",\"tags\":\"up to 12 lowercase topic keywords, comma separated\",\"questions\":[{\"q\":\"\",\"o\":[\"\",\"\"],\"a\":0}]}. Notes = lecture notes, handouts, summaries. CATs = continuous assessment tests. Exams = end-of-semester examinations. Past papers = papers from earlier years kept for revision. Quizzes = short practice questions. unit: use the unit code and name as printed on the document, and reuse the exact spelling of an existing unit when it is the same unit. uni: one name from the universities list when the document clearly names that university, otherwise All. title: short and clear, such as Cat 1 2026. questions: include only when cat is Quizzes and the content is multiple-choice questions with known answers (a is the index of the correct option); otherwise omit it.";
const FIND = "You help a student find study files. Reply with ONE JSON object and nothing else: {\"best\":[ids that directly match the search],\"related\":[ids about the same topic or unit that may also help]}. Use only ids from the catalog, at most 8 in each list, most useful first. Forgive spelling mistakes and short forms (cat, sem, intro).";
function guess(name, text) {
  const s = low(name + " " + text);
  return { cat: /quiz/.test(s) ? "Quizzes" : /\bcats?\b|continuous assessment/.test(s) ? "CATs" : /past ?papers?/.test(s) ? "Past papers" : /exam/.test(s) ? "Exams" : "Notes", uni: "All", unit: "General", tags: "", title: String(name).replace(/\.[a-z0-9]{2,4}$/i, "").replace(/[_-]+/g, " ").trim().slice(0, 150) || "Untitled" };
}
async function sortFile(buf, mime, name, units) { // decides university, unit, category, title and search tags
  const intro = "Filename: " + name + "\nExisting units: " + (units.join("; ") || "none yet") + "\nUniversities: " + UNIS.join("; "), parts = [];
  if (mime === "application/pdf" && buf.length < 2e7) parts.push({ type: "document", source: { type: "base64", media_type: mime, data: buf.toString("base64") } });
  else if (/^image\/(png|jpeg|webp|gif)$/.test(mime) && buf.length < 4e6) parts.push({ type: "image", source: { type: "base64", media_type: mime, data: buf.toString("base64") } });
  else if (mime === "text/plain") parts.push({ type: "text", text: "Content:\n" + buf.toString("utf8", 0, 20000) });
  const g = guess(name, mime === "text/plain" ? buf.toString("utf8", 0, 2000) : "");
  const r = (parts.length && await ai([...parts, { type: "text", text: intro }], SORT, 2000)) || await ai(intro, SORT, 500);
  if (!r) return { ...g, ai: false };
  const cat = CATS.includes(r.cat) ? r.cat : g.cat;
  let qs = null;
  if (cat === "Quizzes" && Array.isArray(r.questions)) { qs = r.questions.filter(x => x && typeof x.q === "string" && Array.isArray(x.o) && x.o.length > 1 && Number.isInteger(x.a) && x.a >= 0 && x.a < x.o.length).map(x => ({ q: x.q.slice(0, 500), o: x.o.map(o => String(o).slice(0, 300)), a: x.a })); if (!qs.length) qs = null; }
  return { ai: true, cat, uni: UNIS.includes(r.uni) ? r.uni : "All", unit: String(r.unit || "").trim().slice(0, 100) || g.unit, title: String(r.title || "").trim().slice(0, 150) || g.title, tags: String(Array.isArray(r.tags) ? r.tags.join(",") : r.tags || "").toLowerCase().slice(0, 300), questions: qs };
}
const isPaid = u => !!u.paid || (!!E.ADMIN_EMAIL && low(u.email) === low(E.ADMIN_EMAIL));
async function student(req, res) { // returns the paid student with his university, or answers the error itself
  const [u] = await q("SELECT id,email,role,paid FROM users WHERE id=$1", [req.t.id]);
  if (!u || u.role !== "stu" && low(u && u.email) !== low(E.ADMIN_EMAIL)) { res.status(403).json({ error: "Students only." }); return null; }
  if (!isPaid(u)) { res.status(402).json({ error: "Please pay to unlock." }); return null; }
  const uni = await setting("uni:" + u.id);
  if (!uni) { res.status(400).json({ error: "Choose your university first." }); return null; }
  return { ...u, uni };
}
app.post("/api/uni", auth("user"), W(async (req, res) => {
  const uni = String(req.body.uni || "").trim().slice(0, 100);
  if (!uni) return res.status(400).json({ error: "Choose a university." });
  const units = [...new Set((Array.isArray(req.body.units) ? req.body.units : []).map(x => String(x).trim().slice(0, 100)).filter(Boolean))].slice(0, 30);
  const put = (k, v) => q("INSERT INTO settings(key,val)VALUES($1,$2)ON CONFLICT(key)DO UPDATE SET val=$2", [k, v]);
  await put("uni:" + req.t.id, uni); await put("units:" + req.t.id, JSON.stringify(units)); res.json({ ok: true });
}));
app.get("/api/unit-options", auth("user"), W(async (req, res) => { // unit names for the profile setup screen (names only, no files)
  res.json((await q("SELECT DISTINCT unit FROM files WHERE uni=$1 OR uni='All' ORDER BY unit", [String(req.query.uni || "").slice(0, 100)])).map(r => r.unit));
}));
app.get("/api/units", auth("user"), W(async (req, res) => {
  const u = await student(req, res); if (!u) return;
  const all = await q("SELECT unit,count(*) n FROM files WHERE uni=$1 OR uni='All' GROUP BY unit ORDER BY unit", [u.uni]), mine = await myUnits(u.id);
  const cnt = Object.fromEntries(all.map(r => [low(r.unit), +r.n]));
  res.json({ mine: mine.map(x => ({ unit: x, n: cnt[low(x)] || 0 })), other: all.filter(r => !mine.some(x => low(x) === low(r.unit))).map(r => ({ unit: r.unit, n: +r.n })) });
}));
app.get("/api/files", auth("user"), W(async (req, res) => {
  const u = await student(req, res); if (!u) return;
  const unit = String(req.query.unit || ""), cat = String(req.query.cat || ""), w = ["(uni=$1 OR uni='All')"], p = [u.uni];
  if (unit) { p.push(unit); w.push("lower(unit)=lower($" + p.length + ")"); }
  if (cat) { p.push(cat); w.push("cat=$" + p.length); }
  const rows = await q("SELECT id,cat,title,unit,size FROM files WHERE " + w.join(" AND ") + " ORDER BY unit,cat,title LIMIT 400", p);
  res.json(rows.map(r => ({ ...r, id: String(r.id), url: "/api/file/" + r.id })));
}));
const sHits = new Map();
const slim = (req, res, n) => { const now = Date.now(), a = (sHits.get(req.ip) || []).filter(t => now - t < 6e4); a.push(now); sHits.set(req.ip, a); a.length > 20 ? res.status(429).json({ error: "Slow down a little." }) : n(); };
app.get("/api/search", auth("user"), slim, W(async (req, res) => { // exact matches first, then AI finds related files
  const u = await student(req, res); if (!u) return;
  const term = String(req.query.q || "").trim().slice(0, 120), out = { best: [], related: [] };
  if (!term) return res.json(out);
  const rows = (await q("SELECT id,cat,title,unit,size,tags FROM files WHERE uni=$1 OR uni='All' ORDER BY id DESC LIMIT 400", [u.uni])).map(r => ({ ...r, id: String(r.id) }));
  const words = low(term).split(/[^a-z0-9]+/).filter(x => x.length > 1), shape = r => ({ id: r.id, cat: r.cat, title: r.title, unit: r.unit, size: r.size, url: "/api/file/" + r.id });
  const hit = (r, x) => low(r.title + " " + r.unit).includes(x) ? 2 : low(r.cat + " " + (r.tags || "")).includes(x) ? 1 : 0;
  out.best = rows.map(r => [r, words.reduce((s, x) => s + hit(r, x), 0)]).filter(x => x[1] > 0).sort((a, b) => b[1] - a[1]).slice(0, 20).map(x => shape(x[0]));
  if (AIKEY && rows.length && out.best.length < 6) {
    const r = await ai('Student searched: "' + term + '"\nStudent\'s units: ' + ((await myUnits(u.id)).join("; ") || "unknown") + "\nCatalog (id|category|unit|title|tags):\n" + rows.map(x => [x.id, x.cat, x.unit, x.title, x.tags || ""].join("|")).join("\n"), FIND, 600);
    if (r) { const by = Object.fromEntries(rows.map(x => [x.id, x])), seen = new Set(out.best.map(x => x.id)), pick = a => (Array.isArray(a) ? a : []).map(String).filter(id => by[id] && !seen.has(id) && seen.add(id)).slice(0, 8).map(id => shape(by[id])); out.best = out.best.concat(pick(r.best)); out.related = pick(r.related); }
  }
  res.json(out);
}));
app.get("/api/file/:id", auth("user"), W(async (req, res) => {
  const u = await student(req, res); if (!u) return;
  const [f] = await q("SELECT title,mime,data FROM files WHERE id=$1 AND (uni=$2 OR uni='All')", [+req.params.id, u.uni]);
  if (!f) return res.status(404).json({ error: "File not found." });
  const safe = /^(application\/(pdf|json)|text\/plain|image\/(png|jpeg|webp|gif))$/.test(f.mime);
  res.set({ "Content-Type": safe ? f.mime + (f.mime === "text/plain" ? "; charset=utf-8" : "") : "application/octet-stream", "Content-Disposition": (safe ? "inline" : "attachment") + '; filename="' + encodeURIComponent(f.title) + '"', "Cache-Control": "private, max-age=0" });
  res.send(Buffer.from(f.data));
}));
// admin: upload / list / edit / delete. Body is the raw file; the AI works out university, unit, category and title.
app.post("/api/admin/file", auth("admin"), express.raw({ type: () => true, limit: "25mb" }), W(async (req, res) => {
  if (!Buffer.isBuffer(req.body) || !req.body.length) return res.status(400).json({ error: "Choose a file or paste some text." });
  const name = String(req.query.name || "Untitled").slice(0, 150), mime = String(req.headers["content-type"] || "application/octet-stream").split(";")[0].slice(0, 100);
  const m = await sortFile(req.body, mime, name, (await q("SELECT DISTINCT unit FROM files ORDER BY unit LIMIT 200")).map(r => r.unit));
  let body = req.body, type = mime;
  if (m.questions && mime === "text/plain") { body = Buffer.from(JSON.stringify({ q: m.questions })); type = "application/json"; } // typed quizzes become interactive quizzes
  await q("INSERT INTO files(uni,unit,cat,title,mime,size,data,tags)VALUES($1,$2,$3,$4,$5,$6,$7,$8)", [m.uni, m.unit, m.cat, m.title, type, body.length, body, m.tags]);
  res.json({ ok: true, ai: m.ai, uni: m.uni, unit: m.unit, cat: m.cat, title: m.title });
}));
app.patch("/api/admin/file/:id", auth("admin"), W(async (req, res) => { // fix something the AI got wrong
  const b = req.body || {}, uni = String(b.uni || "").trim(), unit = String(b.unit || "").trim().slice(0, 100), title = String(b.title || "").trim().slice(0, 150);
  if (!(uni === "All" || UNIS.includes(uni)) || !unit || !title || !CATS.includes(b.cat)) return res.status(400).json({ error: "Check the university, unit, category and title." });
  await q("UPDATE files SET uni=$2,unit=$3,cat=$4,title=$5 WHERE id=$1", [+req.params.id, uni, unit, b.cat, title]); res.json({ ok: true });
}));
app.get("/api/admin/files", auth("admin"), W(async (req, res) => res.json(await q("SELECT id,uni,unit,cat,title,size FROM files ORDER BY id DESC LIMIT 300"))));
app.delete("/api/admin/file/:id", auth("admin"), W(async (req, res) => { await q("DELETE FROM files WHERE id=$1", [+req.params.id]); res.json({ ok: true }); }));

app.use(express.static("public"));
const PK = SQLITE ? "INTEGER PRIMARY KEY AUTOINCREMENT" : "serial PRIMARY KEY", TS = SQLITE ? "TEXT DEFAULT CURRENT_TIMESTAMP" : "timestamptz DEFAULT now()";
const exec = s => SQLITE ? pool.exec(s) : q(s);
(async () => {
  await exec(`CREATE TABLE IF NOT EXISTS users(id ${PK},role text,phone text,email text UNIQUE,pw text,ref text,ver bool DEFAULT false,paid bool DEFAULT false,approved bool DEFAULT false,code text UNIQUE,bal int DEFAULT 0,ref_by int);
CREATE TABLE IF NOT EXISTS payments(id ${PK},user_id int,checkout_id text UNIQUE,receipt text,status text DEFAULT 'pending',amount int);
CREATE TABLE IF NOT EXISTS accounts(name text PRIMARY KEY,bal int DEFAULT 0);
CREATE TABLE IF NOT EXISTS ledger(id ${PK},note text,amount int,at ${TS});
CREATE TABLE IF NOT EXISTS payouts(id ${PK},user_id int,phone text,amount int,status text,orig text,receipt text,at ${TS});
CREATE TABLE IF NOT EXISTS complaints(id ${PK},user_id int,type text,msg text,status text DEFAULT 'Open',at ${TS});
CREATE TABLE IF NOT EXISTS settings(key text PRIMARY KEY,val text);
CREATE TABLE IF NOT EXISTS files(id ${PK},uni text,unit text,cat text,title text,mime text,size int,data ${SQLITE?"BLOB":"bytea"},tags text,at ${TS});
INSERT INTO accounts(name)VALUES('general'),('admin')ON CONFLICT DO NOTHING;`);
  try { await exec("ALTER TABLE files ADD COLUMN tags text"); } catch (e) { /* column already there */ }
  app.listen(E.PORT || 3000, () => { console.log("Study Room running"); runDue().catch(console.error); });
})();
