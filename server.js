// Plexus Onboarding Portal — server.
// Serves public/ and a JSON API backed by Postgres (DATABASE_URL). See README.md for the Replit secrets.
'use strict';
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { Pool } = require('pg');
const nodemailer = require('nodemailer');
const dns = require('dns');
const mailcfg = require('./mailcfg.js');
const { merge3, same } = require('./public/merge.js');

/* ---------------- config ---------------- */
const ROOT = path.join(__dirname, 'public');
const PORT = Number(process.env.PORT) || 3000;
const PLEXUS_DOMAIN = '@plexusclinical.com';
const ADMIN_EMAILS = (process.env.ADMIN_EMAILS || 'onboarding@plexusclinical.com,drimran@plexusclinical.com,dralhadheri@plexusclinical.com')
  .split(',').map((s) => s.trim().toLowerCase()).filter(Boolean);
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || '';
const APP_URL = (process.env.APP_URL || '').replace(/\/$/, '');
const MAIL_FROM = process.env.MAIL_FROM || 'Plexus Ancillary Services <onboarding@plexusclinical.com>';
const SECURE_SHARE_URL = process.env.SECURE_SHARE_URL || '';
const TZ = process.env.REMINDER_TZ || 'America/Phoenix';
const RC = { id: process.env.RINGCENTRAL_CLIENT_ID, secret: process.env.RINGCENTRAL_CLIENT_SECRET, jwt: process.env.RINGCENTRAL_JWT, from: process.env.RINGCENTRAL_FROM, server: process.env.RINGCENTRAL_SERVER || 'https://platform.ringcentral.com' };
const RC_ON = !!(RC.id && RC.secret && RC.jwt && RC.from);
const SESSION_HOURS = 12, CODE_MINUTES = 10, INVITE_DAYS = 7;
const PROD = process.env.NODE_ENV === 'production' || !!process.env.REPLIT_DEPLOYMENT;

if (!process.env.DATABASE_URL) { console.error('DATABASE_URL is not set. On Replit, add a PostgreSQL database (Tools → Database).'); process.exit(1); }
// TLS: AWS RDS needs it; the RDS CA bundle is baked into the Docker image (verify-full). Other hosts: sslmode=require in the URL.
const RDS_CA = ['/app/rds-ca.pem', path.join(__dirname, 'rds-ca.pem')].find((f) => { try { return fs.statSync(f).isFile(); } catch (e) { return false; } });
const dbSsl = /rds\.amazonaws\.com/.test(process.env.DATABASE_URL) || process.env.DATABASE_SSL === 'require'
  ? (RDS_CA ? { ca: fs.readFileSync(RDS_CA, 'utf8'), rejectUnauthorized: true } : { rejectUnauthorized: false })
  : /sslmode=require|neon\.tech/.test(process.env.DATABASE_URL) ? { rejectUnauthorized: false } : undefined;
const db = new Pool({ connectionString: process.env.DATABASE_URL.replace(/[?&]sslmode=[^&]*/, ''), ssl: dbSsl, max: Number(process.env.DB_POOL_MAX) || 8 });
const CRON_SECRET = process.env.CRON_SECRET || '';

// Optional server-level sender (SMTP_* settings). Settings → Email accounts take priority; this is the fallback.
const mailer = process.env.SMTP_HOST ? nodemailer.createTransport({
  host: process.env.SMTP_HOST, port: Number(process.env.SMTP_PORT) || 465, secure: (Number(process.env.SMTP_PORT) || 465) === 465,
  auth: process.env.SMTP_USER ? { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS } : undefined,
}) : null;
const MAIL_KEY = mailcfg.mailKey();

/* ---------------- schema ---------------- */
async function migrate() {
  await db.query(`
    create table if not exists facilities (id text primary key, site text not null default '', clinic text not null default '', coordinator text not null default '', target text not null default '',
      state jsonb not null, version integer not null default 1, created_at timestamptz not null default now(), updated_at timestamptz not null default now());
    create table if not exists settings (key text primary key, value jsonb not null, version integer not null default 1, updated_at timestamptz not null default now());
    create table if not exists accounts (email text primary key, name text not null default '', pw_hash text, google boolean not null default false,
      created_at timestamptz not null default now(), last_sign_in timestamptz);
    create table if not exists sessions (token_hash text primary key, email text not null, team text, expires_at timestamptz not null);
    create table if not exists auth_codes (email text primary key, code_hash text not null, attempts integer not null default 0, expires_at timestamptz not null, team text);
    create table if not exists email_log (id bigserial primary key, at timestamptz not null default now(), kind text, recipient text, subject text, ok boolean, error text);
    alter table email_log add column if not exists sender text;
    create table if not exists mail_accounts (id text primary key, provider text not null, from_email text not null, from_name text not null default '', username text not null,
      host text not null, port integer not null, password_enc text, created_at timestamptz not null default now(), created_by text, updated_at timestamptz not null default now(), updated_by text,
      last_ok_at timestamptz, last_error text, last_error_at timestamptz);
    create table if not exists admin_log (id bigserial primary key, at timestamptz not null default now(), who text not null, ev text not null, detail text not null default '');
  `);
}

/* ---------------- helpers ---------------- */
const sha = (s) => crypto.createHash('sha256').update(s).digest('hex');
const rand = (n = 32) => crypto.randomBytes(n).toString('base64url');
const lower = (s) => String(s || '').trim().toLowerCase();
const emailOk = (e) => /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(e);
const hashPw = (pw) => new Promise((ok, no) => { const salt = crypto.randomBytes(16); crypto.scrypt(pw, salt, 64, { N: 16384 }, (e, k) => e ? no(e) : ok(`s1$${salt.toString('hex')}$${k.toString('hex')}`)); });
const checkPw = (pw, stored) => new Promise((ok) => { const [, s, h] = String(stored || '').split('$'); if (!s || !h) return ok(false);
  crypto.scrypt(pw, Buffer.from(s, 'hex'), 64, { N: 16384 }, (e, k) => ok(!e && crypto.timingSafeEqual(k, Buffer.from(h, 'hex')))); });
const deepClone = (x) => JSON.parse(JSON.stringify(x));
/** Never persist anything that looks like a password, whatever the client sends. */
function stripSecrets(o) {
  if (Array.isArray(o)) return o.map(stripSecrets);
  if (o && typeof o === 'object') { const r = {}; for (const [k, v] of Object.entries(o)) { if (/^(password|passwd|pw|pass|secret)$/i.test(k)) continue; r[k] = stripSecrets(v); } return r; }
  return o;
}
function invitesOf(state) { const out = []; for (const [site, teams] of Object.entries((state && state.invites) || {})) for (const t of ['clinic', 'billing']) for (const x of (teams && teams[t]) || []) out.push({ site, team: t, rec: x }); return out; }

/* rate limit: per ip+bucket */
const hits = new Map();
function limited(req, bucket, max = 20, windowMs = 60000) {
  const ip = String(req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
  const k = bucket + '|' + ip, now = Date.now(), arr = (hits.get(k) || []).filter((t) => now - t < windowMs);
  arr.push(now); hits.set(k, arr); return arr.length > max;
}
setInterval(() => { const now = Date.now(); for (const [k, a] of hits) if (!a.some((t) => now - t < 120000)) hits.delete(k); }, 60000).unref();

/* ---------------- settings ---------------- */
async function getSetting(key, dflt) { const r = await db.query('select value, version from settings where key=$1', [key]); return r.rows[0] ? { value: r.rows[0].value, version: r.rows[0].version } : { value: dflt, version: 0 }; }
async function putSetting(key, value) {
  const r = await db.query(`insert into settings (key, value) values ($1, $2) on conflict (key) do update set value=$2, version=settings.version+1, updated_at=now() returning version`, [key, JSON.stringify(value)]);
  return r.rows[0].version;
}
const DEFAULT_USERS = [['onboarding', 'Plexus Onboarding', 'Admin'], ['billing', 'Plexus Billing', 'Billing'], ['drimran', 'Dr. Imran', 'Admin'], ['dralhadheri', 'Dr. Alhadheri', 'Admin']].map(([e, name, role]) => ({ email: e + PLEXUS_DOMAIN, name, role }));
async function staffUsers() { const u = (await getSetting('users', [])).value; return Array.isArray(u) && u.length ? u : DEFAULT_USERS; }
async function staffFor(email) {
  const u = (await staffUsers()).find((x) => lower(x.email) === email);
  if (ADMIN_EMAILS.includes(email)) return { email, name: (u && u.name) || email.split('@')[0], role: 'Admin' };
  if (u && !u.disabled && email.endsWith(PLEXUS_DOMAIN)) return { email, name: u.name || email, role: u.role || 'Reviewer' };
  return null;
}
const PERM = { users: ['Admin'], clinics: ['Admin', 'Coordinator'], invite: ['Admin', 'Coordinator'], review: ['Admin', 'Coordinator', 'Reviewer', 'Billing'], requirements: ['Admin'], reminders: ['Admin', 'Coordinator'], email: ['Admin'] };
const can = (me, p) => !!me && me.role === 'plexus' && (PERM[p] || []).includes(me.prole);
const SETTING_PERM = { users: 'users', reqDefaults: 'requirements', reminders: 'reminders' };

/* ---------------- identity ---------------- */
async function memberFor(email) {
  const r = await db.query('select id, site, state from facilities order by created_at');
  for (const f of r.rows) {
    const teams = [...new Set(invitesOf(f.state).filter((x) => lower(x.rec.email) === email).map((x) => x.team))];
    if (teams.length) { const rec = invitesOf(f.state).find((x) => lower(x.rec.email) === email).rec; return { email, name: rec.name || email, role: 'member', teams, fid: f.id, site: f.site }; }
  }
  return null;
}
async function identity(email, team) {
  const st = await staffFor(email);
  if (st) return { email, name: st.name, role: 'plexus', prole: st.role };
  const m = await memberFor(email);
  if (!m) return null;
  const acc = (await db.query('select name from accounts where email=$1', [email])).rows[0];
  if (acc && acc.name) m.name = acc.name;
  m.team = m.teams.includes(team) ? team : m.teams[0];
  return m;
}
function cookies(req) { const o = {}; for (const p of String(req.headers.cookie || '').split(';')) { const i = p.indexOf('='); if (i > 0) o[p.slice(0, i).trim()] = decodeURIComponent(p.slice(i + 1).trim()); } return o; }
const secureReq = (req) => PROD || req.headers['x-forwarded-proto'] === 'https';
async function startSession(req, res, email, team) {
  const tok = rand();
  await db.query('insert into sessions (token_hash, email, team, expires_at) values ($1,$2,$3, now() + interval \'' + SESSION_HOURS + ' hours\')', [sha(tok), email, team || null]);
  await db.query('update accounts set last_sign_in=now() where email=$1', [email]);
  res.setHeader('Set-Cookie', `pxo=${tok}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${SESSION_HOURS * 3600}${secureReq(req) ? '; Secure' : ''}`);
}
async function currentUser(req) {
  const tok = cookies(req).pxo; if (!tok) return null;
  const r = await db.query('update sessions set expires_at = now() + interval \'' + SESSION_HOURS + ' hours\' where token_hash=$1 and expires_at > now() returning email, team', [sha(tok)]);
  if (!r.rows[0]) return null;
  return identity(r.rows[0].email, r.rows[0].team);
}

/* ---------------- email + sms ---------------- */
/* Sending accounts (Settings → Email). Each message kind (code, invite, reminder) is sent from the account chosen
   for it; if that fails or none is chosen, the server-level SMTP_* sender is used. Sign-in codes are never lost:
   if no sender works, the code is written to the server log so an admin can't be locked out. */
const errText = (e) => String((e && e.message) || e || 'Unknown error').replace(/\s+/g, ' ').slice(0, 300);
async function mailRoutes() { const r = (await getSetting('mailRoutes', {})).value || {}; const o = {}; for (const k of mailcfg.KINDS) o[k] = typeof r[k] === 'string' ? r[k] : ''; return o; }
const transports = new Map(); // account id -> { stamp, t }
async function assertPublicHost(host) {
  if (!PROD) return;
  const addrs = await dns.promises.lookup(host, { all: true });
  if (!addrs.length || addrs.some((a) => mailcfg.privateHost(a.address))) throw new Error('That mail server address points to a private network.');
}
async function accountTransport(a) {
  if (!MAIL_KEY) throw new Error('Email accounts can’t be used until the server has its MAIL_KEY secret.');
  if (!a.password_enc) throw new Error('No password saved for this account.');
  const stamp = new Date(a.updated_at).getTime(), hit = transports.get(a.id);
  if (hit && hit.stamp === stamp) return hit.t;
  await assertPublicHost(a.host);
  const t = nodemailer.createTransport(mailcfg.transportOptions(a, mailcfg.decrypt(a.password_enc, MAIL_KEY, a.id), { prod: PROD }));
  transports.set(a.id, { stamp, t });
  return t;
}
async function noteAccount(id, ok, error) {
  if (ok) await db.query('update mail_accounts set last_ok_at=now(), last_error=null, last_error_at=null where id=$1', [id]).catch(() => {});
  else await db.query('update mail_accounts set last_error=$2, last_error_at=now() where id=$1', [id, error]).catch(() => {});
}
async function deliver(account, to, subject, text) {
  const t = await accountTransport(account);
  await t.sendMail({ from: mailcfg.fromHeader(account), to, subject, text });
}
async function sendEmail(kind, to, subject, text) {
  let ok = false, error = null, sender = null;
  const id = (await mailRoutes())[kind];
  const acc = id ? (await db.query('select * from mail_accounts where id=$1', [id])).rows[0] : null;
  if (acc) {
    try { await deliver(acc, to, subject, text); ok = true; sender = acc.from_email; await noteAccount(acc.id, true); }
    catch (e) { error = errText(e); await noteAccount(acc.id, false, error); console.error('[email failed]', kind, 'via', acc.from_email, error); }
  }
  if (!ok && mailer) {
    try { await mailer.sendMail({ from: MAIL_FROM, to, subject, text }); ok = true; sender = 'server: ' + (process.env.SMTP_USER || MAIL_FROM); }
    catch (e) { error = errText(e); console.error('[email failed]', kind, 'via server sender', error); }
  }
  if (!ok && (!acc && !mailer || kind === 'code')) console.log(`[email not sent — written here instead] kind=${kind} to=${to} subject="${subject}"\n${text}\n`);
  // Never store a sign-in code in the log; the subject of a code email contains it.
  await db.query('insert into email_log (kind, recipient, subject, ok, error, sender) values ($1,$2,$3,$4,$5,$6)', [kind, to, kind === 'code' ? 'Sign-in code' : subject, ok, ok ? null : error, sender]).catch(() => {});
  return ok;
}
async function emailOn() { return !!mailer || Object.values(await mailRoutes()).some(Boolean); }
async function senderSummary() {
  const routes = await mailRoutes(), out = {};
  const rows = (await db.query('select id, from_email from mail_accounts')).rows;
  for (const k of mailcfg.KINDS) { const a = rows.find((x) => x.id === routes[k]); out[k] = a ? a.from_email : mailer ? (process.env.SMTP_USER || MAIL_FROM) : ''; }
  return out;
}
const adminLog = (who, ev, detail = '') => db.query('insert into admin_log (who, ev, detail) values ($1,$2,$3)', [who, ev, String(detail).slice(0, 500)]).catch(() => {});
let rcToken = null;
async function sendSms(to, text) {
  if (!RC_ON) return false;
  try {
    if (!rcToken || rcToken.exp < Date.now() + 60000) {
      const r = await fetch(RC.server + '/restapi/oauth/token', { method: 'POST', headers: { Authorization: 'Basic ' + Buffer.from(RC.id + ':' + RC.secret).toString('base64'), 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer', assertion: RC.jwt }) });
      const j = await r.json(); if (!r.ok) throw new Error(j.error_description || 'RingCentral auth failed');
      rcToken = { v: j.access_token, exp: Date.now() + j.expires_in * 1000 };
    }
    const digits = (p) => '+1' + String(p).replace(/\D/g, '').slice(-10);
    const r = await fetch(RC.server + '/restapi/v1.0/account/~/extension/~/sms', { method: 'POST', headers: { Authorization: 'Bearer ' + rcToken.v, 'Content-Type': 'application/json' },
      body: JSON.stringify({ from: { phoneNumber: digits(RC.from) }, to: [{ phoneNumber: digits(to) }], text }) });
    if (!r.ok) throw new Error('RingCentral SMS ' + r.status);
    return true;
  } catch (e) { console.error('[sms failed]', String(e.message || e)); return false; }
}
const baseUrl = (req) => APP_URL || (req ? `${req.headers['x-forwarded-proto'] || 'http'}://${req.headers['x-forwarded-host'] || req.headers.host}` : '');
let lastBaseUrl = APP_URL;

async function sendCode(email, team) {
  const code = String(crypto.randomInt(100000, 1000000));
  await db.query(`insert into auth_codes (email, code_hash, attempts, expires_at, team) values ($1,$2,0, now() + interval '${CODE_MINUTES} minutes', $3)
    on conflict (email) do update set code_hash=$2, attempts=0, expires_at=now() + interval '${CODE_MINUTES} minutes', team=$3`, [email, sha(email + ':' + code), team || null]);
  await sendEmail('code', email, `${code} is your Plexus verification code`, `Your Plexus Onboarding verification code is ${code}.\n\nIt expires in ${CODE_MINUTES} minutes. If you didn't try to sign in, you can ignore this email.`);
}

/* ---------------- facility state ---------------- */
const MEMBER_LOCKED = ['invites', 'reminders', 'reqOverride', 'remOverride', 'reqDefaults', 'settings'];
function forMember(state) { const s = deepClone(state); for (const x of invitesOf(s)) delete x.rec.token; return s; }
function memberGuard(base, next) {
  const n = deepClone(next);
  for (const k of MEMBER_LOCKED) { if (base && k in base) n[k] = deepClone(base[k]); else delete n[k]; }
  for (const [k, t] of Object.entries(n.tasks || {})) {
    const was = base && base.tasks && base.tasks[k] ? base.tasks[k].state : 'not_started';
    if (t && ['verified', 'waived', 'changes'].includes(t.state) && t.state !== was) { t.state = was; if (base && base.tasks && base.tasks[k]) t.reason = base.tasks[k].reason; }
  }
  return n;
}
async function canSee(me, fid) { return me.role === 'plexus' || me.fid === fid; }
async function saveFacility(fid, mutate) {
  const c = await db.connect();
  try {
    await c.query('begin');
    const r = await c.query('select state, version from facilities where id=$1 for update', [fid]);
    if (!r.rows[0]) { await c.query('rollback'); return null; }
    const next = stripSecrets(await mutate(r.rows[0].state));
    const v = r.rows[0].version + 1;
    await c.query('update facilities set state=$2, version=$3, site=$4, clinic=$5, updated_at=now() where id=$1', [fid, JSON.stringify(next), v, next.site || '', next.clinic || '']);
    await c.query('commit');
    return { state: next, version: v };
  } catch (e) { await c.query('rollback').catch(() => {}); throw e; } finally { c.release(); }
}
const stamp = () => new Date().toLocaleString('en-US', { timeZone: TZ });

/* ---------------- reminders ---------------- */
const REM_DEFAULT = { enabled: true, every: 3, business: true, teams: 'both', stopOnSubmit: true, max: 6, noWeekends: true, email: true, text: false, senderName: 'Plexus Ancillary Services',
  tpl: { clinic: { subject: 'Reminder: finish onboarding for {clinic}', body: 'Hi {first_name},\n\nThis is a friendly reminder to finish the clinic onboarding for {clinic}. You have {remaining} left to complete.\n\nPick up where you left off: {link}\n\nThank you,\n{sender}' },
    billing: { subject: 'Reminder: billing onboarding for {clinic}', body: 'Hi {first_name},\n\nThis is a friendly reminder to finish the billing onboarding for {clinic}. You have {remaining} left to complete.\n\nPick up where you left off: {link}\n\nThank you,\n{sender}' } },
  sms: 'Plexus: Hi {first_name}, {remaining} left in the {team} onboarding for {clinic}. Continue here: {link}' };
async function reminderSettings() { const r = (await getSetting('reminders', {})).value || {}; return { ...REM_DEFAULT, ...r, tpl: { clinic: { ...REM_DEFAULT.tpl.clinic, ...((r.tpl || {}).clinic || {}) }, billing: { ...REM_DEFAULT.tpl.billing, ...((r.tpl || {}).billing || {}) } } }; }
const fillTpl = (s, ctx) => String(s || '').replace(/\{(\w+)\}/g, (m, k) => (ctx[k] !== undefined ? ctx[k] : m));
function addBusinessDays(d, n, biz) { const r = new Date(d); let k = 0; while (k < n) { r.setDate(r.getDate() + 1); if (!biz || (r.getDay() !== 0 && r.getDay() !== 6)) k++; } return r; }
function plan(state, team, rem) {
  const ov = state.remOverride || {}; const on = ov.enabled !== undefined ? ov.enabled : rem.enabled; const every = ov.every || rem.every;
  const inv = ((state.invites || {})[state.site] || {})[team] || [];
  if (!on || !inv.length || (rem.teams !== 'both' && rem.teams !== team)) return null;
  const sum = ((state._summary || {})[team]) || null;
  if (sum && ((rem.stopOnSubmit && sum.submitted) || sum.remaining === 0)) return null;
  const log = (state.reminders || []).filter((r) => r.team === team);
  if (log.length >= rem.max) return null;
  const last = log.length ? log[0].at : (inv.map((x) => x.sentAt).filter(Boolean).sort()[0] || new Date().toISOString());
  return { next: addBusinessDays(new Date(last), every, rem.business), people: inv, remaining: sum ? sum.remaining : null };
}
async function sendReminder(fid, team, by) {
  const rem = await reminderSettings();
  let entry = null;
  const res = await saveFacility(fid, async (state) => {
    const inv = ((state.invites || {})[state.site] || {})[team] || [];
    const remaining = (((state._summary || {})[team]) || {}).remaining;
    const link = (lastBaseUrl || '') + '/?view=' + team;
    const msgs = [], to = [], texts = [];
    for (const p of inv) {
      const ctx = { first_name: (p.name || '').trim().split(/\s+/)[0] || 'there', clinic: state.site || 'your clinic', team, remaining: remaining == null ? 'a few sections' : remaining === 1 ? '1 section' : `${remaining} sections`, link, sender: rem.senderName };
      const m = { name: p.name, email: p.email, phone: p.phone || '', subject: '', body: '', sms: '' };
      if (rem.email !== false) { m.subject = fillTpl(rem.tpl[team].subject, ctx); m.body = fillTpl(rem.tpl[team].body, ctx); if (await sendEmail('reminder', p.email, m.subject, m.body)) to.push(p.email); }
      if (rem.text && RC_ON && p.phone && String(p.phone).replace(/\D/g, '').length >= 10) { m.sms = fillTpl(rem.sms, ctx) + ' Reply STOP to opt out.'; if (await sendSms(p.phone, m.sms)) texts.push(p.phone); }
      msgs.push(m);
    }
    const channels = [to.length && 'Email', texts.length && 'Text'].filter(Boolean);
    entry = { at: new Date().toISOString(), team, to, texts, channels, msgs, auto: by === 'Automatic', by };
    state.reminders = [entry, ...(state.reminders || [])];
    state.audit = [{ t: stamp(), who: by, ev: `${team === 'billing' ? 'Billing' : 'Clinic'} team reminder sent${channels.length ? ' (' + channels.join(' + ') + ')' : ''}`, d: [to.length ? 'Email: ' + to.join(', ') : '', texts.length ? 'Text: ' + texts.join(', ') : ''].filter(Boolean).join(' · ') || 'No reachable recipients' }, ...(state.audit || [])];
    return state;
  });
  return res;
}
function localParts(d) { const p = Object.fromEntries(new Intl.DateTimeFormat('en-US', { timeZone: TZ, weekday: 'short', hour: 'numeric', hour12: false }).formatToParts(d).map((x) => [x.type, x.value])); return { day: p.weekday, hour: Number(p.hour) % 24 }; }
/* Only one server runs a reminder pass at a time (AWS may run several copies); a Postgres advisory lock guards it. */
async function reminderTick() {
  const c = await db.connect().catch(() => null); if (!c) return { ran: false };
  try {
    const got = (await c.query('select pg_try_advisory_lock(7310431) as ok')).rows[0].ok;
    if (!got) return { ran: false, reason: 'another server is sending' };
    try { await reminderPass(); return { ran: true }; } finally { await c.query('select pg_advisory_unlock(7310431)'); }
  } finally { c.release(); }
}
async function reminderPass() {
  try {
    const rem = await reminderSettings();
    if (!rem.enabled) return;
    const now = new Date(), lp = localParts(now);
    if (lp.hour < 9 || lp.hour >= 17) return; // send only 9am–5pm clinic time
    if (rem.noWeekends && (lp.day === 'Sat' || lp.day === 'Sun')) return;
    const r = await db.query('select id, state from facilities');
    for (const f of r.rows) for (const team of ['clinic', 'billing']) {
      const p = plan(f.state, team, rem);
      if (p && p.next <= now) await sendReminder(f.id, team, 'Automatic');
    }
  } catch (e) { console.error('[reminders]', e.message); }
}

/* ---------------- http ---------------- */
const TYPES = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.svg': 'image/svg+xml', '.png': 'image/png', '.ico': 'image/x-icon', '.json': 'application/json' };
const SECURITY = {
  'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'same-origin', 'X-Frame-Options': 'SAMEORIGIN', 'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
  'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline' https://accounts.google.com/gsi/client; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://accounts.google.com/gsi/style; font-src https://fonts.gstatic.com; img-src 'self' data: https://*.googleusercontent.com; connect-src 'self' https://accounts.google.com/gsi/; frame-src https://accounts.google.com/gsi/; frame-ancestors 'self'",
};
const send = (res, code, obj) => { res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...SECURITY }); res.end(JSON.stringify(obj)); };
const fail = (res, code, msg) => send(res, code, { error: msg });
function body(req) { return new Promise((ok, no) => { let n = 0; const chunks = []; req.on('data', (c) => { n += c.length; if (n > 5e6) { no(new Error('too large')); req.destroy(); } else chunks.push(c); }); req.on('end', () => { try { ok(chunks.length ? JSON.parse(Buffer.concat(chunks).toString('utf8')) : {}); } catch (e) { no(e); } }); req.on('error', no); }); }

async function facilityList(me) {
  const r = me.role === 'plexus' ? await db.query('select id, site, clinic, coordinator, target, version from facilities order by created_at') : await db.query('select id, site, clinic, coordinator, target, version from facilities where id=$1', [me.fid]);
  return r.rows;
}
async function accountSummary() {
  const r = await db.query('select email, google, pw_hash is not null as has_pw, created_at, last_sign_in from accounts');
  return Object.fromEntries(r.rows.map((a) => [a.email, { method: a.google && !a.has_pw ? 'google' : 'password', created: a.created_at, lastSignIn: a.last_sign_in }]));
}

const routes = [];
const route = (method, pattern, fn, opts = {}) => routes.push({ method, re: new RegExp('^' + pattern.replace(/:(\w+)/g, '(?<$1>[^/]+)') + '$'), fn, opts });

route('GET', '/api/config', async () => ({ googleClientId: GOOGLE_CLIENT_ID, ringcentral: { connected: RC_ON, from: RC_ON ? RC.from : '' }, email: await emailOn(), secureShareUrl: SECURE_SHARE_URL }), { open: true });

route('GET', '/api/bootstrap', async (req, me) => {
  const config = { googleClientId: GOOGLE_CLIENT_ID, ringcentral: { connected: RC_ON, from: RC_ON ? RC.from : '' }, email: await emailOn(), secureShareUrl: SECURE_SHARE_URL };
  if (!me) return { me: null, config };
  if (me.role === 'plexus') config.senders = await senderSummary();
  lastBaseUrl = baseUrl(req);
  const facs = await facilityList(me);
  const states = {};
  const r = me.role === 'plexus' ? await db.query('select id, state, version from facilities') : await db.query('select id, state, version from facilities where id=$1', [me.fid]);
  for (const f of r.rows) states[f.id] = { state: me.role === 'plexus' ? f.state : forMember(f.state), version: f.version };
  const settings = {};
  for (const k of ['reqDefaults', 'reminders'].concat(me.role === 'plexus' ? ['users'] : [])) settings[k] = await getSetting(k, k === 'users' ? [] : {});
  return { me, config, facs, states, settings, accounts: me.role === 'plexus' ? await accountSummary() : {} };
}, { open: true });

route('POST', '/api/sync', async (req, me, b) => {
  const have = b.versions || {}, sv = b.settings || {};
  const facs = await facilityList(me), changed = {};
  const stale = facs.filter((f) => have[f.id] !== f.version).map((f) => f.id);
  if (stale.length) { const r = await db.query('select id, state, version from facilities where id = any($1)', [stale]); for (const f of r.rows) changed[f.id] = { state: me.role === 'plexus' ? f.state : forMember(f.state), version: f.version }; }
  const settings = {};
  for (const k of ['reqDefaults', 'reminders'].concat(me.role === 'plexus' ? ['users'] : [])) { const s = await getSetting(k, k === 'users' ? [] : {}); if (s.version !== sv[k]) settings[k] = s; }
  return { facs, changed, settings, accounts: me.role === 'plexus' ? await accountSummary() : undefined };
});

route('POST', '/api/facilities', async (req, me, b) => {
  if (!can(me, 'clinics')) throw Object.assign(new Error('Not allowed'), { status: 403 });
  const id = String(b.id || ('f' + rand(9))).replace(/[^\w-]/g, '').slice(0, 40);
  const state = stripSecrets(b.state || {}); state.fid = id;
  await db.query('insert into facilities (id, site, clinic, coordinator, target, state) values ($1,$2,$3,$4,$5,$6) on conflict (id) do nothing', [id, state.site || '', state.clinic || '', b.coordinator || '', b.target || '', JSON.stringify(state)]);
  const r = await db.query('select state, version from facilities where id=$1', [id]);
  return { id, state: r.rows[0].state, version: r.rows[0].version };
});
route('POST', '/api/facilities/:id/meta', async (req, me, b, p) => {
  if (!can(me, 'clinics')) throw Object.assign(new Error('Not allowed'), { status: 403 });
  await db.query('update facilities set coordinator=$2, target=$3 where id=$1', [p.id, String(b.coordinator || '').slice(0, 120), String(b.target || '').slice(0, 40)]);
  return { ok: true };
});
route('POST', '/api/facilities/:id/save', async (req, me, b, p) => {
  if (!(await canSee(me, p.id))) throw Object.assign(new Error('Not allowed'), { status: 403 });
  const base = b.base || null; let next = b.next;
  if (!next || typeof next !== 'object') throw Object.assign(new Error('Missing data'), { status: 400 });
  if (me.role !== 'plexus') next = memberGuard(base, next);
  const r = await saveFacility(p.id, (cur) => {
    if (me.role !== 'plexus') { // members never see invite tokens, so merge against their view and keep the server's tokens
      const merged = merge3(base || forMember(cur), next, cur); for (const k of MEMBER_LOCKED) if (k in cur) merged[k] = cur[k]; return merged;
    }
    return base ? merge3(base, next, cur) : merge3(cur, next, cur);
  });
  if (!r) throw Object.assign(new Error('Clinic not found'), { status: 404 });
  return { state: me.role === 'plexus' ? r.state : forMember(r.state), version: r.version };
});

route('POST', '/api/facilities/:id/invites', async (req, me, b, p) => {
  if (!can(me, 'invite')) throw Object.assign(new Error('Not allowed'), { status: 403 });
  const team = b.team === 'billing' ? 'billing' : 'clinic';
  const people = (Array.isArray(b.people) ? b.people : []).map((x) => ({ name: String(x.name || '').trim().slice(0, 120), email: lower(x.email), phone: String(x.phone || '').trim().slice(0, 30) })).filter((x) => x.email);
  if (!people.length || people.some((x) => !emailOk(x.email))) throw Object.assign(new Error('Check the email addresses.'), { status: 400 });
  if (people.some((x) => x.email.endsWith(PLEXUS_DOMAIN))) throw Object.assign(new Error('Plexus staff are added in Settings → Users & roles, not invited to a clinic.'), { status: 400 });
  // An email can belong to only one clinic.
  const other = await db.query('select id, site, state from facilities where id <> $1', [p.id]);
  for (const f of other.rows) for (const x of invitesOf(f.state)) if (people.some((y) => y.email === lower(x.rec.email))) throw Object.assign(new Error(`${x.rec.email} is already invited to ${f.site}.`), { status: 400 });
  lastBaseUrl = baseUrl(req);
  const toSend = [];
  const r = await saveFacility(p.id, (state) => {
    state.invites = state.invites || {}; const site = state.site || ''; state.invites[site] = state.invites[site] || { clinic: [], billing: [] };
    const l = state.invites[site][team] = state.invites[site][team] || [];
    const nowIso = new Date().toISOString(), sent = new Date().toLocaleString('en-US', { timeZone: TZ, month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' });
    for (const x of people) {
      let rec = l.find((y) => lower(y.email) === x.email);
      if (rec) { rec.token = rand(24); rec.sentAt = nowIso; rec.sent = sent; if (x.name) rec.name = x.name; if (x.phone) rec.phone = x.phone; }
      else { rec = { id: rand(8), name: x.name, email: x.email, phone: x.phone, sent, sentAt: nowIso, token: rand(24) }; l.push(rec); }
      toSend.push({ ...rec });
    }
    state.audit = [{ t: stamp(), who: me.name + ' – Plexus team', ev: `${team === 'billing' ? 'Billing' : 'Clinic'} onboarding invitation sent — ${site}`, d: people.map((x) => x.email).join(', ') }, ...(state.audit || [])];
    return state;
  });
  for (const x of toSend) {
    const link = `${baseUrl(req)}/?invite=${encodeURIComponent(x.token)}`;
    await sendEmail('invite', x.email, `You're invited: ${r.state.site} ${team} onboarding with Plexus`,
      `Hi ${(x.name || '').split(' ')[0] || 'there'},\n\nPlexus Ancillary Services invited you to complete the ${team} onboarding for ${r.state.site}.\n\nCreate your account here (the link works once and expires in ${INVITE_DAYS} days):\n${link}\n\nQuestions? Reply to this email.\n\nPlexus Ancillary Services`);
  }
  return { state: r.state, version: r.version, emailed: await emailOn() };
});

route('POST', '/api/facilities/:id/remind', async (req, me, b, p) => {
  if (!can(me, 'reminders')) throw Object.assign(new Error('Not allowed'), { status: 403 });
  lastBaseUrl = baseUrl(req);
  const r = await sendReminder(p.id, b.team === 'billing' ? 'billing' : 'clinic', me.name);
  return { state: r.state, version: r.version };
});

route('PUT', '/api/settings/:key', async (req, me, b, p) => {
  const perm = SETTING_PERM[p.key];
  if (!perm || !can(me, perm)) throw Object.assign(new Error('Not allowed'), { status: 403 });
  let value = b.value;
  if (p.key === 'users') {
    if (!Array.isArray(value)) throw Object.assign(new Error('Bad list'), { status: 400 });
    value = value.filter((u) => u && emailOk(lower(u.email)) && lower(u.email).endsWith(PLEXUS_DOMAIN)).map((u) => ({ ...u, email: lower(u.email), disabled: ADMIN_EMAILS.includes(lower(u.email)) ? false : !!u.disabled, role: ADMIN_EMAILS.includes(lower(u.email)) ? 'Admin' : u.role }));
  }
  if (p.key === 'reminders' && value) delete value.rc;
  return { version: await putSetting(p.key, stripSecrets(value)) };
});

/* ---- Settings → Email (Admins only). Passwords are write-only: no response ever includes one. ---- */
const notAllowed = () => Object.assign(new Error('Not allowed'), { status: 403 });
const bad = (m) => Object.assign(new Error(m), { status: 400 });
const ACCOUNT_COLS = 'id, provider, from_email, from_name, username, host, port, password_enc is not null as has_password, created_at, created_by, updated_at, updated_by, last_ok_at, last_error, last_error_at';
const publicAccount = (a) => ({ id: a.id, provider: a.provider, fromEmail: a.from_email, fromName: a.from_name, username: a.username, host: a.host, port: a.port, hasPassword: a.has_password,
  createdAt: a.created_at, createdBy: a.created_by, updatedAt: a.updated_at, updatedBy: a.updated_by, lastOkAt: a.last_ok_at, lastError: a.last_error, lastErrorAt: a.last_error_at });
async function mailState() {
  const accounts = (await db.query(`select ${ACCOUNT_COLS} from mail_accounts order by created_at`)).rows.map(publicAccount);
  const recent = (await db.query('select at, kind, recipient, ok, error, sender from email_log order by id desc limit 25')).rows; // no subjects: older rows may hold codes
  const changes = (await db.query('select at, who, ev, detail from admin_log order by id desc limit 25')).rows;
  return { accounts, routes: await mailRoutes(), kinds: mailcfg.KINDS, presets: mailcfg.PRESETS, keyReady: !!MAIL_KEY,
    serverSender: mailer ? (process.env.SMTP_USER || MAIL_FROM) : null, recent, changes };
}
async function accountRow(id) { return (await db.query(`select ${ACCOUNT_COLS} from mail_accounts where id=$1`, [String(id)])).rows[0] || null; }
const KIND_LABEL = { code: 'Sign-in codes', invite: 'Invitations', reminder: 'Reminders' };

route('GET', '/api/mail', async (req, me) => { if (!can(me, 'email')) throw notAllowed(); return mailState(); });

route('POST', '/api/mail/accounts', async (req, me, b) => {
  if (!can(me, 'email')) throw notAllowed();
  if (!MAIL_KEY) throw bad('The server is missing its MAIL_KEY secret, so passwords can’t be stored safely yet.');
  const { value: v, error } = mailcfg.validateAccount(b, { prod: PROD }); if (error) throw bad(error);
  if ((await db.query('select 1 from mail_accounts where from_email=$1', [v.fromEmail])).rows[0]) throw bad('That address is already connected. Edit it instead.');
  const id = 'm' + rand(9);
  await db.query('insert into mail_accounts (id, provider, from_email, from_name, username, host, port, password_enc, created_by, updated_by) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$9)',
    [id, v.provider, v.fromEmail, v.fromName, v.username, v.host, v.port, mailcfg.encrypt(v.password, MAIL_KEY, id), me.email]);
  await adminLog(me.email, 'Connected sending account', v.fromEmail);
  // The first account connected sends everything until an admin chooses otherwise.
  const routes = await mailRoutes();
  if (!Object.values(routes).some(Boolean)) { await putSetting('mailRoutes', Object.fromEntries(mailcfg.KINDS.map((k) => [k, id]))); await adminLog(me.email, 'Chose sender for all messages', v.fromEmail); }
  return { id, ...(await mailState()) };
}, { limit: 'mail' });

route('PUT', '/api/mail/accounts/:id', async (req, me, b, p) => {
  if (!can(me, 'email')) throw notAllowed();
  const prev = await accountRow(p.id); if (!prev) throw Object.assign(new Error('That account was removed.'), { status: 404 });
  const { value: v, error } = mailcfg.validateAccount(b, { prod: PROD, prev }); if (error) throw bad(error);
  if (v.password && !MAIL_KEY) throw bad('The server is missing its MAIL_KEY secret, so passwords can’t be stored safely yet.');
  if ((await db.query('select 1 from mail_accounts where from_email=$1 and id<>$2', [v.fromEmail, p.id])).rows[0]) throw bad('Another account already uses that address.');
  await db.query(`update mail_accounts set provider=$2, from_email=$3, from_name=$4, username=$5, host=$6, port=$7, password_enc=coalesce($8, password_enc), updated_at=now(), updated_by=$9, last_error=null, last_error_at=null where id=$1`,
    [p.id, v.provider, v.fromEmail, v.fromName, v.username, v.host, v.port, v.password ? mailcfg.encrypt(v.password, MAIL_KEY, p.id) : null, me.email]);
  transports.delete(p.id);
  await adminLog(me.email, v.password ? 'Updated sending account and its password' : 'Updated sending account', v.fromEmail);
  return mailState();
}, { limit: 'mail' });

route('DELETE', '/api/mail/accounts/:id', async (req, me, b, p) => {
  if (!can(me, 'email')) throw notAllowed();
  const prev = await accountRow(p.id); if (!prev) return mailState();
  await db.query('delete from mail_accounts where id=$1', [p.id]); transports.delete(p.id);
  const routes = await mailRoutes(), cleared = mailcfg.KINDS.filter((k) => routes[k] === p.id);
  if (cleared.length) { for (const k of cleared) routes[k] = ''; await putSetting('mailRoutes', routes); }
  await adminLog(me.email, 'Removed sending account', prev.from_email + (cleared.length ? ' (was sending ' + cleared.map((k) => KIND_LABEL[k].toLowerCase()).join(', ') + ')' : ''));
  return mailState();
});

route('PUT', '/api/mail/routes', async (req, me, b) => {
  if (!can(me, 'email')) throw notAllowed();
  const ids = new Set((await db.query('select id from mail_accounts')).rows.map((r) => r.id)), prev = await mailRoutes(), next = {};
  for (const k of mailcfg.KINDS) { const v = String((b.routes || {})[k] || ''); if (v && !ids.has(v)) throw bad('Choose a connected account.'); next[k] = v; }
  await putSetting('mailRoutes', next);
  const names = Object.fromEntries((await db.query('select id, from_email from mail_accounts')).rows.map((r) => [r.id, r.from_email]));
  const diff = mailcfg.KINDS.filter((k) => prev[k] !== next[k]).map((k) => `${KIND_LABEL[k]}: ${names[next[k]] || (mailer ? 'server sender' : 'not sent')}`);
  if (diff.length) await adminLog(me.email, 'Changed which account sends what', diff.join(' · '));
  return mailState();
});

route('POST', '/api/mail/accounts/:id/test', async (req, me, b, p) => {
  if (!can(me, 'email')) throw notAllowed();
  const acc = (await db.query('select * from mail_accounts where id=$1', [p.id])).rows[0]; if (!acc) throw Object.assign(new Error('That account was removed.'), { status: 404 });
  const to = lower(b.to || me.email); if (!emailOk(to)) throw bad('Enter a valid address for the test email.');
  try {
    await deliver(acc, to, 'Test email from Plexus Onboarding Portals', `This is a test from Settings → Email.\n\nIt was sent from ${acc.from_email}. If you got it, this account is ready to use.\n\nSent by ${me.name} (${me.email}).`);
    await noteAccount(acc.id, true);
    await db.query('insert into email_log (kind, recipient, subject, ok, sender) values ($1,$2,$3,true,$4)', ['test', to, 'Test email', acc.from_email]).catch(() => {});
    return { ok: true, to, ...(await mailState()) };
  } catch (e) {
    const error = errText(e); await noteAccount(acc.id, false, error);
    await db.query('insert into email_log (kind, recipient, subject, ok, error, sender) values ($1,$2,$3,false,$4,$5)', ['test', to, 'Test email', error, acc.from_email]).catch(() => {});
    return { ok: false, error, ...(await mailState()) };
  }
}, { limit: 'mailtest' });

/* ---- auth ---- */
route('GET', '/api/invite/:token', async (req, me, b, p) => {
  const r = await db.query('select id, site, state from facilities');
  for (const f of r.rows) for (const x of invitesOf(f.state)) if (x.rec.token && x.rec.token === p.token) {
    const expired = !x.rec.sentAt || Date.now() - new Date(x.rec.sentAt).getTime() > INVITE_DAYS * 864e5;
    const acc = (await db.query('select pw_hash is not null as has_pw, google from accounts where email=$1', [lower(x.rec.email)])).rows[0];
    return { email: x.rec.email, name: x.rec.name || '', site: f.site, team: x.team, expired, hasAccount: !!(acc && (acc.has_pw || acc.google)) };
  }
  throw Object.assign(new Error('This invitation link is invalid or was replaced by a newer one.'), { status: 404 });
}, { open: true, limit: 'invite' });

route('POST', '/api/invite/:token/accept', async (req, me, b, p) => {
  const r = await db.query('select id, site, state from facilities');
  let hit = null; for (const f of r.rows) for (const x of invitesOf(f.state)) if (x.rec.token && x.rec.token === p.token) hit = { f, x };
  if (!hit) throw Object.assign(new Error('This invitation link is invalid or was replaced by a newer one.'), { status: 404 });
  if (Date.now() - new Date(hit.x.rec.sentAt).getTime() > INVITE_DAYS * 864e5) throw Object.assign(new Error('This invitation expired. Ask your Plexus coordinator to resend it.'), { status: 410 });
  const name = String(b.name || '').trim().slice(0, 120), pw = String(b.password || '');
  if (!name) throw Object.assign(new Error('Enter your full name.'), { status: 400 });
  if (pw.length < 12) throw Object.assign(new Error('Use at least 12 characters for your password.'), { status: 400 });
  const email = lower(hit.x.rec.email);
  await db.query('insert into accounts (email, name, pw_hash) values ($1,$2,$3) on conflict (email) do update set name=$2, pw_hash=$3', [email, name, await hashPw(pw)]);
  // Single use: retire the token once the account exists.
  await saveFacility(hit.f.id, (state) => { for (const x of invitesOf(state)) if (x.rec.token === p.token) { delete x.rec.token; if (!x.rec.name) x.rec.name = name; } return state; });
  const m = await memberFor(email);
  await sendCode(email, hit.x.team);
  return { email, teams: m ? m.teams : [hit.x.team] };
}, { open: true, limit: 'auth' });

route('POST', '/api/auth/login', async (req, me, b) => {
  const email = lower(b.email);
  if (!emailOk(email)) throw Object.assign(new Error('Enter a valid email address.'), { status: 400 });
  if (email.endsWith(PLEXUS_DOMAIN)) { // staff: emailed code, no password
    if (await staffFor(email)) await sendCode(email);
    return { email, teams: [], staff: true }; // same answer either way, so the form can't be used to list staff
  }
  const acc = (await db.query('select pw_hash from accounts where email=$1', [email])).rows[0];
  const m = await memberFor(email);
  if (!acc || !acc.pw_hash || !m || !(await checkPw(String(b.password || ''), acc.pw_hash))) throw Object.assign(new Error('That email and password don’t match.'), { status: 401 });
  await sendCode(email, m.teams[0]);
  return { email, teams: m.teams };
}, { open: true, limit: 'auth' });

route('POST', '/api/auth/verify', async (req, me, b, p, res) => {
  const email = lower(b.email), code = String(b.code || '').replace(/\D/g, '');
  const r = (await db.query('select code_hash, attempts, expires_at, team from auth_codes where email=$1', [email])).rows[0];
  if (!r || new Date(r.expires_at) < new Date()) throw Object.assign(new Error('That code expired. Sign in again to get a new one.'), { status: 400 });
  if (r.attempts >= 5) throw Object.assign(new Error('Too many tries. Sign in again to get a new code.'), { status: 429 });
  if (sha(email + ':' + code) !== r.code_hash) { await db.query('update auth_codes set attempts=attempts+1 where email=$1', [email]); throw Object.assign(new Error('That code isn’t right.'), { status: 400 }); }
  await db.query('delete from auth_codes where email=$1', [email]);
  const who = await identity(email, b.team || r.team);
  if (!who) throw Object.assign(new Error('This account no longer has access.'), { status: 403 });
  if (who.role === 'plexus') await db.query('insert into accounts (email, name) values ($1,$2) on conflict (email) do nothing', [email, who.name]);
  await startSession(req, res, email, who.team);
  return { me: who };
}, { open: true, limit: 'auth' });

route('POST', '/api/auth/google', async (req, me, b, p, res) => {
  if (!GOOGLE_CLIENT_ID) throw Object.assign(new Error('Google sign-in is not set up yet.'), { status: 400 });
  const r = await fetch('https://oauth2.googleapis.com/tokeninfo?id_token=' + encodeURIComponent(String(b.credential || '')));
  const t = await r.json().catch(() => ({}));
  if (!r.ok || t.aud !== GOOGLE_CLIENT_ID || !['accounts.google.com', 'https://accounts.google.com'].includes(t.iss) || String(t.email_verified) !== 'true' || Number(t.exp) * 1000 < Date.now())
    throw Object.assign(new Error('Google sign-in failed. Try again.'), { status: 401 });
  const email = lower(t.email);
  const who = await identity(email, b.team);
  if (!who) throw Object.assign(new Error(email.endsWith(PLEXUS_DOMAIN) ? 'This Google account hasn’t been added in Users & roles. Ask onboarding@plexusclinical.com for access.' : 'This Google account hasn’t been invited.'), { status: 403 });
  await db.query('insert into accounts (email, name, google) values ($1,$2,true) on conflict (email) do update set google=true', [email, who.name || t.name || email]);
  await startSession(req, res, email, who.team);
  return { me: who };
}, { open: true, limit: 'auth' });

/* For AWS EventBridge Scheduler (or any cron): POST /api/cron/reminders with header x-cron-secret. */
route('POST', '/api/cron/reminders', async (req) => {
  const got = String(req.headers['x-cron-secret'] || '');
  if (!CRON_SECRET || got.length !== CRON_SECRET.length || !crypto.timingSafeEqual(Buffer.from(got), Buffer.from(CRON_SECRET))) throw Object.assign(new Error('Not allowed'), { status: 403 });
  return reminderTick();
}, { open: true, limit: 'cron' });

route('POST', '/api/auth/team', async (req, me, b) => {
  if (me.role !== 'member' || !me.teams.includes(b.team)) throw Object.assign(new Error('Not allowed'), { status: 403 });
  await db.query('update sessions set team=$2 where token_hash=$1', [sha(cookies(req).pxo), b.team]);
  return { me: { ...me, team: b.team } };
});
route('POST', '/api/auth/logout', async (req, me, b, p, res) => {
  const tok = cookies(req).pxo; if (tok) await db.query('delete from sessions where token_hash=$1', [sha(tok)]);
  res.setHeader('Set-Cookie', 'pxo=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0');
  return { ok: true };
}, { open: true });

async function handleApi(req, res, url) {
  const r = routes.find((x) => x.method === req.method && x.re.test(url));
  if (!r) return fail(res, 404, 'Not found');
  if (req.method !== 'GET' && !String(req.headers['content-type'] || '').startsWith('application/json')) return fail(res, 415, 'JSON only'); // also blocks cross-site form posts
  if (r.opts.limit && limited(req, r.opts.limit, 20)) return fail(res, 429, 'Too many attempts. Wait a minute and try again.');
  try {
    const me = await currentUser(req);
    if (!r.opts.open && !me) return fail(res, 401, 'Sign in again.');
    const b = req.method === 'GET' ? {} : await body(req);
    const out = await r.fn(req, me, b, url.match(r.re).groups || {}, res);
    send(res, 200, out);
  } catch (e) {
    if (!e.status) console.error('[api]', req.method, url, e);
    fail(res, e.status || 500, e.status ? e.message : 'Something went wrong. Try again.');
  }
}

const server = http.createServer((req, res) => {
  const url = decodeURIComponent((req.url || '/').split('?')[0]);
  if (url === '/healthz') { db.query('select 1').then(() => { res.writeHead(200, { 'Content-Type': 'text/plain' }); res.end('ok'); }, () => { res.writeHead(503, { 'Content-Type': 'text/plain' }); res.end('db unavailable'); }); return; }
  if (url.startsWith('/api/')) return handleApi(req, res, url);
  let file = path.normalize(path.join(ROOT, url === '/' ? 'index.html' : url));
  if (!file.startsWith(ROOT)) { res.writeHead(403); return res.end(); }
  fs.stat(file, (err, st) => {
    if (err || !st.isFile()) file = path.join(ROOT, 'index.html');
    fs.readFile(file, (e, buf) => {
      if (e) { res.writeHead(500); return res.end('Server error'); }
      res.writeHead(200, { 'Content-Type': TYPES[path.extname(file)] || 'application/octet-stream', 'Cache-Control': /\.(html|js)$/.test(file) ? 'no-cache' : 'public, max-age=300', ...SECURITY, ...(secureReq(req) ? { 'Strict-Transport-Security': 'max-age=31536000' } : {}) });
      res.end(buf);
    });
  });
});

migrate().then(() => {
  server.listen(PORT, '0.0.0.0', () => console.log(`Plexus Onboarding Portal on http://localhost:${PORT} — server email ${mailer ? 'on' : 'off'}, email accounts ${MAIL_KEY ? 'ready' : 'OFF (no MAIL_KEY)'}, Google sign-in ${GOOGLE_CLIENT_ID ? 'on' : 'off'}, RingCentral ${RC_ON ? 'on' : 'off'}`));
  if (process.env.DISABLE_INTERNAL_SCHEDULER !== 'true') setInterval(reminderTick, 10 * 60 * 1000).unref();
  setInterval(() => db.query('delete from sessions where expires_at < now(); delete from auth_codes where expires_at < now()').catch(() => {}), 3600 * 1000).unref();
}).catch((e) => { console.error('Database setup failed:', e.message); process.exit(1); });
for (const sig of ['SIGTERM', 'SIGINT']) process.on(sig, () => { server.close(() => db.end().finally(() => process.exit(0))); setTimeout(() => process.exit(0), 8000).unref(); });
