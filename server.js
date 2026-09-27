// FC JobDesk - leads, engineer availability, job offers (first to accept wins), materials
const express = require("express");
const crypto = require("crypto");
const path = require("path");
const bcrypt = require("bcryptjs");
const { types } = require("pg");
types.setTypeParser(1082, (v) => v); // DATE -> 'YYYY-MM-DD' string

const { pool, q, migrate } = require("./db");
const mail = require("./mail");
const { esc } = mail;

const PORT = process.env.PORT || 3000;
const BASE_URL = (process.env.BASE_URL || `http://localhost:${PORT}`).replace(/\/$/, "");
const OFFICE_EMAIL = process.env.OFFICE_EMAIL || "";
const LEAD_FORM_ORIGINS = (process.env.LEAD_FORM_ORIGINS || "https://fctrainingacademy.com,https://www.fctrainingacademy.com").split(",").map((s) => s.trim());
const KS_ORDER_WEBHOOK_URL = process.env.KS_ORDER_WEBHOOK_URL || "";
const OFFER_HOURS = Number(process.env.OFFER_HOURS || 4);
const SECURE_COOKIE = BASE_URL.startsWith("https://");

const app = express();
app.set("trust proxy", 1);
app.use(express.json({ limit: "200kb" }));
app.use(express.urlencoded({ extended: false, limit: "50kb" }));
app.use((req, res, next) => {
  res.set("X-Content-Type-Options", "nosniff");
  res.set("Referrer-Policy", "same-origin");
  if (!req.path.startsWith("/lead-form")) res.set("X-Frame-Options", "DENY");
  next();
});

// ---------- helpers ----------
const sha = (s) => crypto.createHash("sha256").update(s).digest("hex");
const token = () => crypto.randomBytes(32).toString("base64url");
const ref = (id) => `FC-${1000 + id}`;
const SLOT = { am: "Morning (8am–12pm)", pm: "Afternoon (12pm–5pm)" };
const niceDay = (d) => new Date(d + "T12:00:00Z").toLocaleDateString("en-GB", { weekday: "long", day: "numeric", month: "long", timeZone: "UTC" });
const outward = (pc) => String(pc || "").trim().toUpperCase().split(/\s+/)[0] || "";
const isDay = (s) => /^\d{4}-\d{2}-\d{2}$/.test(String(s || ""));
const clean = (s, n = 500) => (s == null ? null : String(s).trim().slice(0, n) || null);

function parseCookies(req) {
  const out = {};
  (req.headers.cookie || "").split(";").forEach((p) => {
    const i = p.indexOf("=");
    if (i > 0) out[p.slice(0, i).trim()] = decodeURIComponent(p.slice(i + 1).trim());
  });
  return out;
}
function setSession(res, value, maxAgeSec) {
  res.set("Set-Cookie", `jd_sess=${value}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAgeSec}${SECURE_COOKIE ? "; Secure" : ""}`);
}

const hits = new Map(); // tiny in-memory rate limiter
function limited(key, max, windowMs) {
  const now = Date.now();
  const arr = (hits.get(key) || []).filter((t) => now - t < windowMs);
  arr.push(now);
  hits.set(key, arr);
  return arr.length > max;
}

async function log(jobId, userId, text) {
  await q("INSERT INTO activity (job_id, user_id, text) VALUES ($1,$2,$3)", [jobId, userId || null, text]);
}

// ---------- auth middleware ----------
async function auth(req, res, next) {
  const t = parseCookies(req).jd_sess;
  if (t) {
    const r = await q(
      `SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id
       WHERE s.token_hash=$1 AND s.expires_at>now() AND u.active`, [sha(t)]);
    if (r.rows[0]) req.user = r.rows[0];
  }
  next();
}
app.use(auth);

const need = (role) => (req, res, next) => {
  if (!req.user) return res.status(401).json({ error: "Please sign in." });
  if (role && req.user.role !== role) return res.status(403).json({ error: "You don't have access to this." });
  // CSRF guard for API writes: browsers can't send this header cross-site without CORS approval
  if (req.method !== "GET" && req.get("X-JobDesk") !== "1") return res.status(403).json({ error: "Bad request." });
  next();
};
const wrapA = (fn) => (req, res) => fn(req, res).catch((e) => {
  console.error(e);
  res.status(500).json({ error: "Something went wrong. Please try again." });
});

// ---------- pages ----------
app.get("/static/base.css", (req, res) => { res.set("Cache-Control", "public, max-age=3600"); res.sendFile(path.join(__dirname, "base.css")); });
app.get("/", (req, res) => res.redirect(req.user ? "/app" : "/login"));
app.get("/login", (req, res) => res.sendFile(path.join(__dirname, "login.html")));
app.get("/set-password", (req, res) => res.sendFile(path.join(__dirname, "set-password.html")));
app.get("/app", (req, res) => (req.user ? res.sendFile(path.join(__dirname, "app.html")) : res.redirect("/login")));
app.get("/lead-form", (req, res) => {
  res.set("Content-Security-Policy", `frame-ancestors 'self' ${LEAD_FORM_ORIGINS.join(" ")}`);
  res.sendFile(path.join(__dirname, "lead-form.html"));
});
app.get("/healthz", (req, res) => res.send("ok"));

// ---------- auth API ----------
app.post("/api/login", wrapA(async (req, res) => {
  const email = String(req.body.email || "").trim().toLowerCase();
  if (limited("login:" + req.ip, 20, 15 * 60e3)) return res.status(429).json({ error: "Too many attempts. Wait 15 minutes." });
  const u = (await q("SELECT * FROM users WHERE lower(email)=$1", [email])).rows[0];
  const ok = u && u.active && u.password_hash && (await bcrypt.compare(String(req.body.password || ""), u.password_hash));
  if (!ok) return res.status(401).json({ error: "Email or password is wrong." });
  const t = token();
  await q("INSERT INTO sessions (token_hash, user_id, expires_at) VALUES ($1,$2, now() + interval '14 days')", [sha(t), u.id]);
  await q("UPDATE users SET last_login=now() WHERE id=$1", [u.id]);
  setSession(res, t, 14 * 86400);
  res.json({ ok: true, role: u.role });
}));

app.post("/api/logout", wrapA(async (req, res) => {
  const t = parseCookies(req).jd_sess;
  if (t) await q("DELETE FROM sessions WHERE token_hash=$1", [sha(t)]);
  setSession(res, "", 0);
  res.json({ ok: true });
}));

app.get("/api/me", (req, res) => {
  if (!req.user) return res.status(401).json({ error: "Please sign in." });
  const { id, name, email, role, phone, gas_safe_no } = req.user;
  res.json({ id, name, email, role, phone, gas_safe_no, mail: mail.enabled, ks: !!KS_ORDER_WEBHOOK_URL });
});

async function issuePasswordLink(user, kind) {
  const t = token();
  await q("INSERT INTO password_tokens (token_hash, user_id, expires_at) VALUES ($1,$2, now() + interval '72 hours')", [sha(t), user.id]);
  const link = `${BASE_URL}/set-password?t=${t}`;
  const invite = kind === "invite";
  await mail.send(user.email,
    invite ? "You've been added to FC JobDesk" : "Reset your FC JobDesk password",
    invite ? `Welcome, ${user.name.split(" ")[0]}` : "Reset your password",
    invite
      ? `<p>FC Training Academy has added you to <b>FC JobDesk</b>. You'll use it to set the days you're free and accept jobs.</p><p>Your username is <b>${esc(user.email)}</b>. Choose your own password using the button below. The link works for 72 hours.</p>`
      : `<p>Use the button below to choose a new password. The link works for 72 hours. If you didn't ask for this, ignore this email.</p>`,
    { href: link, label: invite ? "Set my password" : "Choose a new password" });
  return link;
}

app.post("/api/password/forgot", wrapA(async (req, res) => {
  const email = String(req.body.email || "").trim().toLowerCase();
  if (limited("forgot:" + req.ip, 5, 15 * 60e3)) return res.status(429).json({ error: "Too many requests. Wait 15 minutes." });
  const u = (await q("SELECT * FROM users WHERE lower(email)=$1 AND active", [email])).rows[0];
  if (u) await issuePasswordLink(u, "reset");
  res.json({ ok: true }); // same answer either way
}));

app.post("/api/password/set", wrapA(async (req, res) => {
  const t = String(req.body.token || ""), pw = String(req.body.password || "");
  if (pw.length < 10) return res.status(400).json({ error: "Use at least 10 characters." });
  const row = (await q("SELECT * FROM password_tokens WHERE token_hash=$1 AND NOT used AND expires_at>now()", [sha(t)])).rows[0];
  if (!row) return res.status(400).json({ error: "This link has expired or was already used. Ask the office for a new one." });
  await q("UPDATE users SET password_hash=$2 WHERE id=$1", [row.user_id, await bcrypt.hash(pw, 11)]);
  await q("UPDATE password_tokens SET used=TRUE WHERE token_hash=$1", [row.token_hash]);
  await q("DELETE FROM sessions WHERE user_id=$1", [row.user_id]);
  const u = (await q("SELECT email FROM users WHERE id=$1", [row.user_id])).rows[0];
  res.json({ ok: true, email: u.email });
}));

// ---------- team (office) ----------
app.get("/api/engineers", need("office"), wrapA(async (req, res) => {
  const r = await q(`SELECT id,name,email,phone,gas_safe_no,active,last_login,(password_hash IS NOT NULL) AS has_password
                     FROM users WHERE role='engineer' ORDER BY active DESC, name`);
  res.json(r.rows);
}));

app.post("/api/engineers", need("office"), wrapA(async (req, res) => {
  const name = clean(req.body.name, 80), email = clean(req.body.email, 120)?.toLowerCase();
  if (!name || !email || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return res.status(400).json({ error: "Enter a name and a valid email." });
  const exists = (await q("SELECT 1 FROM users WHERE lower(email)=$1", [email])).rows[0];
  if (exists) return res.status(400).json({ error: "That email is already on JobDesk." });
  const u = (await q(`INSERT INTO users (name,email,phone,gas_safe_no,role) VALUES ($1,$2,$3,$4,'engineer') RETURNING *`,
    [name, email, clean(req.body.phone, 40), clean(req.body.gas_safe_no, 20)])).rows[0];
  const link = await issuePasswordLink(u, "invite");
  res.json({ ok: true, id: u.id, link: mail.enabled ? null : link });
}));

app.patch("/api/engineers/:id", need("office"), wrapA(async (req, res) => {
  const f = {};
  for (const k of ["name", "phone", "gas_safe_no"]) if (k in req.body) f[k] = clean(req.body[k], 80);
  if ("active" in req.body) f.active = !!req.body.active;
  const keys = Object.keys(f);
  if (!keys.length) return res.json({ ok: true });
  await q(`UPDATE users SET ${keys.map((k, i) => `${k}=$${i + 2}`).join(",")} WHERE id=$1 AND role='engineer'`, [req.params.id, ...keys.map((k) => f[k])]);
  if (f.active === false) await q("DELETE FROM sessions WHERE user_id=$1", [req.params.id]);
  res.json({ ok: true });
}));

app.post("/api/engineers/:id/invite", need("office"), wrapA(async (req, res) => {
  const u = (await q("SELECT * FROM users WHERE id=$1 AND role='engineer'", [req.params.id])).rows[0];
  if (!u) return res.status(404).json({ error: "Engineer not found." });
  const link = await issuePasswordLink(u, u.password_hash ? "reset" : "invite");
  res.json({ ok: true, link: mail.enabled ? null : link });
}));

app.get("/api/outbox", need("office"), wrapA(async (req, res) => {
  res.json((await q("SELECT id,to_addr,subject,link,sent,error,at FROM outbox ORDER BY id DESC LIMIT 50")).rows);
}));

// ---------- jobs ----------
async function sweep() {
  // expire old offers; if a job has no live offers left and nobody accepted, it goes back to 'lead'
  await q("UPDATE offers SET status='expired' WHERE status='pending' AND expires_at<now()");
  await q(`UPDATE jobs j SET status='lead' WHERE status='offered'
           AND NOT EXISTS (SELECT 1 FROM offers o WHERE o.job_id=j.id AND o.status IN ('pending','accepted'))`);
}

const JOB_FIELDS = ["customer_name", "customer_phone", "customer_email", "address", "postcode", "job_type", "description", "appliance", "price_note", "office_notes"];

app.post("/api/jobs", need("office"), wrapA(async (req, res) => {
  const b = req.body;
  if (!clean(b.customer_name) || !clean(b.job_type)) return res.status(400).json({ error: "Customer name and job type are needed." });
  const r = await q(`INSERT INTO jobs (source,customer_name,customer_phone,customer_email,address,postcode,job_type,description,appliance,price_note,office_notes,day,slot)
                     VALUES ('manual',$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) RETURNING id`,
    [...JOB_FIELDS.map((k) => clean(b[k], k === "description" || k === "office_notes" ? 2000 : 200)), isDay(b.day) ? b.day : null, SLOT[b.slot] ? b.slot : null]);
  const id = r.rows[0].id;
  await q("UPDATE jobs SET ref=$2 WHERE id=$1", [id, ref(id)]);
  await log(id, req.user.id, "Lead added by " + req.user.name);
  res.json({ ok: true, id, ref: ref(id) });
}));

app.patch("/api/jobs/:id", need("office"), wrapA(async (req, res) => {
  const f = {};
  for (const k of JOB_FIELDS) if (k in req.body) f[k] = clean(req.body[k], 2000);
  if ("day" in req.body) f.day = isDay(req.body.day) ? req.body.day : null;
  if ("slot" in req.body) f.slot = SLOT[req.body.slot] ? req.body.slot : null;
  if (req.body.status === "cancelled" || req.body.status === "completed" || req.body.status === "lead") f.status = req.body.status;
  if (f.status === "cancelled" || f.status === "lead") {
    await q("UPDATE offers SET status='closed' WHERE job_id=$1 AND status='pending'", [req.params.id]);
    if (f.status === "lead") f.engineer_id = null;
  }
  if (f.status === "completed") f.completed_at = new Date();
  const keys = Object.keys(f);
  if (keys.length) await q(`UPDATE jobs SET ${keys.map((k, i) => `${k}=$${i + 2}`).join(",")} WHERE id=$1`, [req.params.id, ...keys.map((k) => f[k])]);
  if (f.status) await log(req.params.id, req.user.id, `Status set to ${f.status} by ${req.user.name}`);
  res.json({ ok: true });
}));

async function jobFor(req, id) {
  const j = (await q(`SELECT j.*, u.name AS engineer_name, u.phone AS engineer_phone FROM jobs j LEFT JOIN users u ON u.id=j.engineer_id WHERE j.id=$1`, [id])).rows[0];
  if (!j) return null;
  if (req.user.role === "engineer" && j.engineer_id !== req.user.id) return null;
  return j;
}

app.get("/api/jobs/:id", need(), wrapA(async (req, res) => {
  await sweep();
  const j = await jobFor(req, req.params.id);
  if (!j) return res.status(404).json({ error: "Job not found." });
  const out = { job: j };
  out.materials = (await q("SELECT * FROM materials WHERE job_id=$1", [j.id])).rows[0] || null;
  if (req.user.role === "office") {
    out.offers = (await q(`SELECT o.id,o.status,o.sent_at,o.expires_at,o.responded_at,u.name FROM offers o JOIN users u ON u.id=o.engineer_id WHERE job_id=$1 ORDER BY o.id DESC`, [j.id])).rows;
    out.activity = (await q(`SELECT a.text,a.at FROM activity a WHERE job_id=$1 ORDER BY a.id DESC LIMIT 40`, [j.id])).rows;
  }
  res.json(out);
}));

app.get("/api/leads", need("office"), wrapA(async (req, res) => {
  await sweep();
  const r = await q(`SELECT j.*, (SELECT count(*) FROM offers o WHERE o.job_id=j.id AND o.status='pending')::int AS pending_offers
                     FROM jobs j WHERE status IN ('lead','offered') ORDER BY created_at DESC`);
  res.json(r.rows);
}));

// Diary: engineers x days, with availability and jobs
app.get("/api/diary", need("office"), wrapA(async (req, res) => {
  await sweep();
  const from = isDay(req.query.from) ? req.query.from : new Date().toISOString().slice(0, 10);
  const days = Math.min(Number(req.query.days) || 7, 31);
  const engineers = (await q("SELECT id,name,phone FROM users WHERE role='engineer' AND active ORDER BY name")).rows;
  const avail = (await q(`SELECT engineer_id, day, slot FROM availability WHERE day >= $1::date AND day < $1::date + $2::int`, [from, days])).rows;
  const jobs = (await q(`SELECT id,ref,status,customer_name,postcode,job_type,day,slot,engineer_id FROM jobs
                         WHERE day >= $1::date AND day < $1::date + $2::int AND status IN ('offered','booked','completed')`, [from, days])).rows;
  res.json({ from, days, engineers, avail, jobs });
}));

// Who is free for a given day/slot (available and not already booked then)
app.get("/api/free", need("office"), wrapA(async (req, res) => {
  const { day, slot } = req.query;
  if (!isDay(day) || !SLOT[slot]) return res.status(400).json({ error: "Pick a day and a slot." });
  const r = await q(`SELECT u.id,u.name,
      EXISTS (SELECT 1 FROM availability a WHERE a.engineer_id=u.id AND a.day=$1 AND a.slot=$2) AS available,
      EXISTS (SELECT 1 FROM jobs j WHERE j.engineer_id=u.id AND j.day=$1 AND j.slot=$2 AND j.status='booked') AS busy
    FROM users u WHERE role='engineer' AND active ORDER BY name`, [day, slot]);
  res.json(r.rows);
}));

// Offer a job to 1-5 engineers. First to accept gets it.
app.post("/api/jobs/:id/offer", need("office"), wrapA(async (req, res) => {
  const { day, slot } = req.body;
  const ids = [...new Set((req.body.engineer_ids || []).map(Number))].filter(Boolean).slice(0, 5);
  if (!isDay(day) || !SLOT[slot]) return res.status(400).json({ error: "Pick a day and a morning or afternoon slot." });
  if (!ids.length) return res.status(400).json({ error: "Pick at least one engineer." });
  const hours = Math.min(Math.max(Number(req.body.hours) || OFFER_HOURS, 1), 72);
  const j = (await q("SELECT * FROM jobs WHERE id=$1", [req.params.id])).rows[0];
  if (!j) return res.status(404).json({ error: "Job not found." });
  if (!["lead", "offered"].includes(j.status)) return res.status(400).json({ error: "This job is already booked." });
  await q("UPDATE offers SET status='closed' WHERE job_id=$1 AND status='pending'", [j.id]);
  await q("UPDATE jobs SET day=$2, slot=$3, status='offered' WHERE id=$1", [j.id, day, slot]);
  const engs = (await q("SELECT * FROM users WHERE id = ANY($1) AND role='engineer' AND active", [ids])).rows;
  const links = [];
  for (const e of engs) {
    const t = token();
    await q("INSERT INTO offers (job_id, engineer_id, token, expires_at) VALUES ($1,$2,$3, now() + make_interval(hours => $4))", [j.id, e.id, t, hours]);
    const link = `${BASE_URL}/o/${t}`;
    links.push({ name: e.name, link });
    await mail.send(e.email, `New job offer ${j.ref}: ${j.job_type}, ${niceDay(day)}`,
      `New job: ${j.job_type}`,
      `<p><b>${esc(niceDay(day))}</b>, ${esc(SLOT[slot])}<br>Area: <b>${esc(outward(j.postcode) || "see job")}</b></p>
       ${j.description ? `<p>${esc(j.description)}</p>` : ""}
       <p>This job has been offered to ${engs.length} engineer${engs.length > 1 ? "s" : ""}. The first to accept gets it. The offer closes in ${hours} hour${hours > 1 ? "s" : ""}.</p>`,
      { href: link, label: "View and accept" });
  }
  await log(j.id, req.user.id, `Offered to ${engs.map((e) => e.name).join(", ")} for ${niceDay(day)} ${slot.toUpperCase()}`);
  res.json({ ok: true, sent: engs.length, links: mail.enabled ? null : links });
}));

// Office books an engineer directly (phone call etc.)
app.post("/api/jobs/:id/assign", need("office"), wrapA(async (req, res) => {
  const { day, slot } = req.body, eid = Number(req.body.engineer_id);
  if (!isDay(day) || !SLOT[slot] || !eid) return res.status(400).json({ error: "Pick a day, slot and engineer." });
  const e = (await q("SELECT * FROM users WHERE id=$1 AND role='engineer' AND active", [eid])).rows[0];
  if (!e) return res.status(400).json({ error: "Engineer not found." });
  await q("UPDATE offers SET status='closed' WHERE job_id=$1 AND status='pending'", [req.params.id]);
  await q("UPDATE jobs SET day=$2, slot=$3, engineer_id=$4, status='booked', booked_at=now() WHERE id=$1", [req.params.id, day, slot, eid]);
  await log(req.params.id, req.user.id, `Booked directly with ${e.name} by ${req.user.name}`);
  const j = (await q("SELECT * FROM jobs WHERE id=$1", [req.params.id])).rows[0];
  await notifyBooked(j, e);
  res.json({ ok: true });
}));

async function notifyBooked(j, e) {
  await mail.send(e.email, `Booked: ${j.ref} ${j.job_type}, ${niceDay(j.day)}`, `You're booked: ${j.job_type}`,
    `<p><b>${esc(niceDay(j.day))}</b>, ${esc(SLOT[j.slot])}</p>
     <p>${esc(j.customer_name)}<br>${esc(j.address || "")} ${esc(j.postcode || "")}<br>${esc(j.customer_phone || "")}</p>
     ${j.description ? `<p>${esc(j.description)}</p>` : ""}`,
    { href: `${BASE_URL}/app#job-${j.id}`, label: "Open job and book materials" });
  if (OFFICE_EMAIL) await mail.send(OFFICE_EMAIL, `Confirmed: ${j.ref} with ${e.name}`, `${e.name} accepted ${j.ref}`,
    `<p>${esc(j.job_type)} for ${esc(j.customer_name)}, ${esc(niceDay(j.day))} ${esc(SLOT[j.slot])}.</p>`, { href: `${BASE_URL}/app#job-${j.id}`, label: "Open job" });
  if (j.customer_email) await mail.send(j.customer_email, `Your appointment with FC Training Academy is confirmed`, "Your appointment is booked",
    `<p>Hello ${esc(j.customer_name.split(" ")[0])},</p><p>Your ${esc(j.job_type.toLowerCase())} is booked for <b>${esc(niceDay(j.day))}</b>, ${esc(SLOT[j.slot].toLowerCase())}. Your engineer will be <b>${esc(e.name)}</b>${e.gas_safe_no ? ` (Gas Safe ID ${esc(e.gas_safe_no)})` : ""}.</p><p>Need to change it? Call 0203 883 2009 and quote ${esc(j.ref)}.</p>`);
}

// Core rule: the first engineer to accept gets the job (row lock prevents double booking)
async function acceptOffer(offerId, engineerId) {
  const c = await pool.connect();
  try {
    await c.query("BEGIN");
    const o = (await c.query("SELECT * FROM offers WHERE id=$1 AND engineer_id=$2 FOR UPDATE", [offerId, engineerId])).rows[0];
    if (!o) { await c.query("ROLLBACK"); return { ok: false, msg: "Offer not found." }; }
    const j = (await c.query("SELECT * FROM jobs WHERE id=$1 FOR UPDATE", [o.job_id])).rows[0];
    if (o.status === "accepted") { await c.query("ROLLBACK"); return { ok: true, job: j, already: true }; }
    if (j.status === "booked" || j.status === "completed") { await c.query("ROLLBACK"); return { ok: false, msg: "Sorry, another engineer has already taken this job." }; }
    if (o.status !== "pending" || new Date(o.expires_at) < new Date() || j.status !== "offered") { await c.query("ROLLBACK"); return { ok: false, msg: "This offer has closed." }; }
    await c.query("UPDATE offers SET status='accepted', responded_at=now() WHERE id=$1", [o.id]);
    await c.query("UPDATE offers SET status='closed' WHERE job_id=$1 AND id<>$2 AND status='pending'", [j.id, o.id]);
    await c.query("UPDATE jobs SET engineer_id=$2, status='booked', booked_at=now() WHERE id=$1", [j.id, engineerId]);
    await c.query("COMMIT");
    const e = (await q("SELECT * FROM users WHERE id=$1", [engineerId])).rows[0];
    const job = (await q("SELECT * FROM jobs WHERE id=$1", [j.id])).rows[0];
    await log(j.id, engineerId, `Accepted by ${e.name}`);
    await notifyBooked(job, e);
    return { ok: true, job };
  } catch (e) {
    await c.query("ROLLBACK").catch(() => {});
    throw e;
  } finally { c.release(); }
}
async function declineOffer(offerId, engineerId) {
  const r = await q("UPDATE offers SET status='declined', responded_at=now() WHERE id=$1 AND engineer_id=$2 AND status='pending' RETURNING job_id", [offerId, engineerId]);
  if (r.rows[0]) {
    const e = (await q("SELECT name FROM users WHERE id=$1", [engineerId])).rows[0];
    await log(r.rows[0].job_id, engineerId, `Declined by ${e.name}`);
    await sweep();
  }
  return { ok: !!r.rows[0] };
}

// ---------- email link pages (no login needed; token is the key) ----------
function page(title, inner) {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex"><title>${esc(title)} · FC JobDesk</title><link rel="stylesheet" href="/static/base.css"></head>
<body class="solo"><main class="solo-card"><div class="brand">FC JobDesk</div>${inner}</main></body></html>`;
}
async function offerByToken(t) {
  return (await q(`SELECT o.*, j.ref, j.job_type, j.description, j.postcode, j.address, j.customer_name, j.customer_phone, j.day, j.slot, j.status AS job_status, j.engineer_id AS job_engineer, u.name AS eng_name
                   FROM offers o JOIN jobs j ON j.id=o.job_id JOIN users u ON u.id=o.engineer_id WHERE o.token=$1`, [t])).rows[0];
}
app.get("/o/:token", wrapA(async (req, res) => {
  await sweep();
  const o = await offerByToken(req.params.token);
  if (!o) return res.status(404).send(page("Offer not found", `<h1>Offer not found</h1><p>This link isn't valid. Check you opened the whole link from the email.</p>`));
  const head = `<h1>${esc(o.job_type)}</h1><p class="big">${esc(niceDay(o.day))}<br>${esc(SLOT[o.slot])}</p><p>Area: <b>${esc(outward(o.postcode))}</b> · Ref ${esc(o.ref)}</p>${o.description ? `<p>${esc(o.description)}</p>` : ""}`;
  if (o.status === "accepted" || (o.job_status === "booked" && o.job_engineer === o.engineer_id)) {
    return res.send(page("Booked", `${head}<div class="ok">You're booked on this job.</div><p>${esc(o.customer_name)}<br>${esc(o.address || "")} ${esc(o.postcode || "")}<br>${esc(o.customer_phone || "")}</p><p><a class="btn" href="/app#job-${o.job_id}">Open job and book materials</a></p>`));
  }
  if (o.status !== "pending") {
    const why = o.job_status === "booked" ? "Another engineer accepted this job first." : o.status === "declined" ? "You declined this job." : "This offer has closed.";
    return res.send(page("Offer closed", `${head}<div class="warn">${why}</div>`));
  }
  // Buttons POST, so email link-scanners that open links can't accept a job by accident
  res.send(page("Job offer", `${head}<p class="muted">Offered to ${esc(o.eng_name)}. First engineer to accept gets it. Closes ${esc(new Date(o.expires_at).toLocaleString("en-GB", { timeZone: "Europe/London", hour: "2-digit", minute: "2-digit", day: "numeric", month: "short" }))}.</p>
    <form method="post" action="/o/${esc(req.params.token)}/accept"><button class="btn big-btn" type="submit">Accept job</button></form>
    <form method="post" action="/o/${esc(req.params.token)}/decline"><button class="btn ghost" type="submit">I can't do it</button></form>`));
}));
app.post("/o/:token/accept", wrapA(async (req, res) => {
  const o = await offerByToken(req.params.token);
  if (!o) return res.redirect(`/o/${encodeURIComponent(req.params.token)}`);
  const r = await acceptOffer(o.id, o.engineer_id);
  if (!r.ok) return res.send(page("Not booked", `<h1>${esc(o.job_type)}</h1><div class="warn">${esc(r.msg)}</div>`));
  res.redirect(`/o/${encodeURIComponent(req.params.token)}`);
}));
app.post("/o/:token/decline", wrapA(async (req, res) => {
  const o = await offerByToken(req.params.token);
  if (o) await declineOffer(o.id, o.engineer_id);
  res.redirect(`/o/${encodeURIComponent(req.params.token)}`);
}));

// ---------- engineer API ----------
app.get("/api/my/week", need("engineer"), wrapA(async (req, res) => {
  await sweep();
  const from = isDay(req.query.from) ? req.query.from : new Date().toISOString().slice(0, 10);
  const days = Math.min(Number(req.query.days) || 14, 31);
  const avail = (await q("SELECT day, slot FROM availability WHERE engineer_id=$1 AND day >= $2::date AND day < $2::date + $3::int", [req.user.id, from, days])).rows;
  const jobs = (await q(`SELECT id,ref,status,customer_name,address,postcode,customer_phone,job_type,description,day,slot FROM jobs
                         WHERE engineer_id=$1 AND status IN ('booked','completed') AND day >= $2::date - 7 ORDER BY day, slot`, [req.user.id, from])).rows;
  const offers = (await q(`SELECT o.id, o.expires_at, j.ref, j.job_type, j.description, j.postcode, j.day, j.slot FROM offers o JOIN jobs j ON j.id=o.job_id
                           WHERE o.engineer_id=$1 AND o.status='pending' AND j.status='offered' ORDER BY j.day`, [req.user.id])).rows
    .map((o) => ({ ...o, area: outward(o.postcode), postcode: undefined }));
  res.json({ from, days, avail, jobs, offers });
}));

app.put("/api/my/availability", need("engineer"), wrapA(async (req, res) => {
  const { day, slot, on } = req.body;
  if (!isDay(day) || !SLOT[slot]) return res.status(400).json({ error: "Bad day or slot." });
  if (on) await q("INSERT INTO availability (engineer_id, day, slot) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING", [req.user.id, day, slot]);
  else await q("DELETE FROM availability WHERE engineer_id=$1 AND day=$2 AND slot=$3", [req.user.id, day, slot]);
  res.json({ ok: true });
}));

app.post("/api/offers/:id/accept", need("engineer"), wrapA(async (req, res) => {
  const r = await acceptOffer(Number(req.params.id), req.user.id);
  res.status(r.ok ? 200 : 409).json(r.ok ? { ok: true, job_id: r.job.id } : { error: r.msg });
}));
app.post("/api/offers/:id/decline", need("engineer"), wrapA(async (req, res) => {
  res.json(await declineOffer(Number(req.params.id), req.user.id));
}));

app.post("/api/jobs/:id/complete", need("engineer"), wrapA(async (req, res) => {
  const r = await q("UPDATE jobs SET status='completed', completed_at=now() WHERE id=$1 AND engineer_id=$2 AND status='booked' RETURNING id", [req.params.id, req.user.id]);
  if (!r.rows[0]) return res.status(400).json({ error: "Only your booked jobs can be completed." });
  await log(req.params.id, req.user.id, `Marked complete by ${req.user.name}`);
  res.json({ ok: true });
}));

// ---------- materials (for K's Plumbing Store) ----------
app.put("/api/jobs/:id/materials", need(), wrapA(async (req, res) => {
  const j = await jobFor(req, req.params.id);
  if (!j) return res.status(404).json({ error: "Job not found." });
  if (j.status !== "booked" && j.status !== "completed") return res.status(400).json({ error: "Materials can be added once the job is booked." });
  const lines = (Array.isArray(req.body.lines) ? req.body.lines : []).slice(0, 80)
    .map((l) => ({ item: clean(l.item, 120), qty: Math.max(1, Math.min(999, Number(l.qty) || 1)) })).filter((l) => l.item);
  const status = req.body.status === "ready" ? "ready" : "draft";
  await q(`INSERT INTO materials (job_id, boiler, lines, notes, status, updated_by, updated_at) VALUES ($1,$2,$3,$4,$5,$6,now())
           ON CONFLICT (job_id) DO UPDATE SET boiler=$2, lines=$3, notes=$4, status=CASE WHEN materials.status='sent' THEN 'sent' ELSE $5 END, updated_by=$6, updated_at=now()`,
    [j.id, clean(req.body.boiler, 160), JSON.stringify(lines), clean(req.body.notes, 1000), status, req.user.id]);
  if (status === "ready") await log(j.id, req.user.id, `Materials list marked ready by ${req.user.name} (${lines.length} lines)`);
  res.json({ ok: true });
}));

app.post("/api/jobs/:id/materials/send", need(), wrapA(async (req, res) => {
  const j = await jobFor(req, req.params.id);
  if (!j) return res.status(404).json({ error: "Job not found." });
  const m = (await q("SELECT * FROM materials WHERE job_id=$1", [j.id])).rows[0];
  if (!m || !m.lines.length) return res.status(400).json({ error: "Add some materials first." });
  if (!KS_ORDER_WEBHOOK_URL) return res.status(400).json({ error: "Ordering from K's Plumbing Store isn't switched on yet. Your list is saved." });
  const payload = { source: "fc-jobdesk", job_ref: j.ref, deliver_day: j.day, slot: j.slot, postcode: j.postcode, address: j.address,
    engineer: { name: req.user.name, email: req.user.email, phone: req.user.phone }, boiler: m.boiler, lines: m.lines, notes: m.notes };
  const r = await fetch(KS_ORDER_WEBHOOK_URL, { method: "POST", headers: { "Content-Type": "application/json", "X-JobDesk-Key": process.env.KS_ORDER_KEY || "" }, body: JSON.stringify(payload) });
  if (!r.ok) return res.status(502).json({ error: "K's Plumbing Store didn't accept the order. Try again or call them." });
  await q("UPDATE materials SET status='sent', sent_at=now() WHERE job_id=$1", [j.id]);
  await log(j.id, req.user.id, `Materials sent to K's Plumbing Store by ${req.user.name}`);
  res.json({ ok: true });
}));

// ---------- public lead form (website) ----------
app.options("/api/public/leads", (req, res) => { cors(req, res); res.sendStatus(204); });
function cors(req, res) {
  const o = req.get("Origin");
  if (o && LEAD_FORM_ORIGINS.includes(o)) { res.set("Access-Control-Allow-Origin", o); res.set("Vary", "Origin"); res.set("Access-Control-Allow-Headers", "Content-Type"); res.set("Access-Control-Allow-Methods", "POST"); }
}
app.post("/api/public/leads", wrapA(async (req, res) => {
  cors(req, res);
  const b = req.body || {};
  if (b.website) return res.json({ ok: true }); // honeypot: bots fill hidden field
  if (limited("lead:" + req.ip, 5, 60 * 60e3)) return res.status(429).json({ error: "Too many requests. Please call 0203 883 2009." });
  const name = clean(b.name, 80), phone = clean(b.phone, 40);
  if (!name || !phone) return res.status(400).json({ error: "Please give your name and phone number." });
  if (!b.consent) return res.status(400).json({ error: "Please tick the box so we can contact you." });
  const r = await q(`INSERT INTO jobs (source,customer_name,customer_phone,customer_email,address,postcode,job_type,description)
                     VALUES ('website',$1,$2,$3,$4,$5,$6,$7) RETURNING id`,
    [name, phone, clean(b.email, 120), clean(b.address, 200), clean(b.postcode, 12), clean(b.job_type, 80) || "Enquiry", clean(b.description, 1500)]);
  const id = r.rows[0].id;
  await q("UPDATE jobs SET ref=$2 WHERE id=$1", [id, ref(id)]);
  await log(id, null, "Lead from website form");
  if (OFFICE_EMAIL) await mail.send(OFFICE_EMAIL, `New website lead ${ref(id)}: ${clean(b.job_type, 80) || "Enquiry"}`, "New website lead",
    `<p>${esc(name)} · ${esc(phone)}<br>${esc(b.postcode || "")}</p><p>${esc(b.description || "")}</p>`, { href: `${BASE_URL}/app#job-${id}`, label: "Open lead" });
  res.json({ ok: true, ref: ref(id) });
}));

// ---------- boot ----------
async function boot() {
  await migrate();
  const { ADMIN_EMAIL, ADMIN_PASSWORD, ADMIN_NAME } = process.env;
  const hasOffice = (await q("SELECT 1 FROM users WHERE role='office' LIMIT 1")).rows[0];
  if (!hasOffice && ADMIN_EMAIL && ADMIN_PASSWORD) {
    await q("INSERT INTO users (name,email,role,password_hash) VALUES ($1,$2,'office',$3)", [ADMIN_NAME || "Office", ADMIN_EMAIL.toLowerCase(), await bcrypt.hash(ADMIN_PASSWORD, 11)]);
    console.log(`[boot] Office login created for ${ADMIN_EMAIL}. You can now remove ADMIN_PASSWORD from the environment.`);
  }
  app.listen(PORT, () => console.log(`[boot] FC JobDesk on ${BASE_URL} (email ${mail.enabled ? "on" : "off - links shown in Outbox"})`));
}
if (require.main === module) boot().catch((e) => { console.error(e); process.exit(1); });
module.exports = { app, boot };
