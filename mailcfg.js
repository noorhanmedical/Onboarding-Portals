// Sending accounts for Settings → Email: presets, validation, and password encryption.
// Passwords are encrypted with AES-256-GCM. The key comes from MAIL_KEY (AWS Secrets Manager in
// production) and is never stored in the database. A password is never returned to the browser.
'use strict';
const crypto = require('crypto');
const net = require('net');

const KINDS = ['code', 'invite', 'reminder'];
const PRESETS = {
  google: { label: 'Google Workspace / Gmail', host: 'smtp.gmail.com', port: 465 },
  microsoft: { label: 'Microsoft 365', host: 'smtp.office365.com', port: 587 },
  ses: { label: 'Amazon SES', host: '', port: 465 },
  other: { label: 'Other', host: '', port: 587 },
};
const PORTS = [25, 465, 587, 2465, 2525, 2587];
const emailOk = (e) => /^[^\s@<>"]+@[^\s@<>"]+\.[^\s@<>"]{2,}$/.test(e);
const clean = (s, n = 120) => String(s == null ? '' : s).replace(/[\r\n<>"\\]/g, ' ').replace(/\s+/g, ' ').trim().slice(0, n);

function keyFrom(secret) { return crypto.createHash('sha256').update('plexus-mail|' + secret).digest(); }
/** Returns the encryption key, or null when MAIL_KEY is missing in production (callers must refuse to store passwords). */
function mailKey(env = process.env) {
  if (env.MAIL_KEY) return keyFrom(env.MAIL_KEY);
  const prod = env.NODE_ENV === 'production' || !!env.REPLIT_DEPLOYMENT;
  return prod ? null : keyFrom('local-dev-only');
}
function encrypt(plain, key, aad) {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', key, iv);
  c.setAAD(Buffer.from(String(aad)));
  const ct = Buffer.concat([c.update(String(plain), 'utf8'), c.final()]);
  return 'v1:' + Buffer.concat([iv, c.getAuthTag(), ct]).toString('base64');
}
function decrypt(blob, key, aad) {
  const raw = Buffer.from(String(blob).replace(/^v1:/, ''), 'base64');
  const d = crypto.createDecipheriv('aes-256-gcm', key, raw.subarray(0, 12));
  d.setAAD(Buffer.from(String(aad)));
  d.setAuthTag(raw.subarray(12, 28));
  return Buffer.concat([d.update(raw.subarray(28)), d.final()]).toString('utf8');
}

function privateHost(h) {
  const host = String(h).toLowerCase();
  if (host === 'localhost' || host.endsWith('.local') || host.endsWith('.internal')) return true;
  if (!net.isIP(host)) return false;
  return /^(10\.|127\.|169\.254\.|192\.168\.|0\.|172\.(1[6-9]|2\d|3[01])\.)/.test(host) || host === '::1' || /^f[cd]/.test(host) || host.startsWith('fe80');
}
/**
 * Checks what an admin typed for a sending account. `prev` is the stored account when editing (a blank
 * password keeps the saved one). Returns { value, error }.
 */
function validateAccount(input, { prod, prev } = {}) {
  const b = input || {};
  const provider = PRESETS[b.provider] ? b.provider : 'other';
  const fromEmail = clean(b.fromEmail, 200).toLowerCase();
  if (!emailOk(fromEmail)) return { error: 'Enter the email address the messages come from.' };
  const fromName = clean(b.fromName) || 'Plexus Ancillary Services';
  const username = clean(b.username, 200) || fromEmail;
  let host = clean(b.host, 200).toLowerCase(), port = Number(b.port);
  if (provider === 'google' || provider === 'microsoft') { host = PRESETS[provider].host; port = PRESETS[provider].port; }
  if (!host) return { error: provider === 'ses' ? 'Enter the SES SMTP endpoint, e.g. email-smtp.us-west-2.amazonaws.com.' : 'Enter the mail server address.' };
  if (!/^[a-z0-9.-]{3,200}$/.test(host)) return { error: 'The mail server address doesn’t look right.' };
  if (prod && privateHost(host)) return { error: 'Use the mail provider’s public server address.' };
  if (!PORTS.includes(port)) return { error: 'Use port 465 or 587 (or 25, 2465, 2525, 2587).' };
  const password = typeof b.password === 'string' ? b.password : '';
  if (password.length > 500) return { error: 'That password is too long.' };
  if (!password && !(prev && prev.has_password)) return { error: provider === 'google' ? 'Paste the Google app password for this account.' : 'Enter the password for this account.' };
  return { value: { provider, fromEmail, fromName, username, host, port, password } };
}
/** Nodemailer transport options. Port 465/2465 use TLS from the start; others must upgrade with STARTTLS in production. */
function transportOptions(a, pass, { prod } = {}) {
  const implicit = a.port === 465 || a.port === 2465;
  return { host: a.host, port: a.port, secure: implicit, requireTLS: !implicit && !!prod, auth: { user: a.username, pass }, connectionTimeout: 15000, greetingTimeout: 15000, socketTimeout: 30000 };
}
const fromHeader = (a) => ({ name: clean(a.from_name || a.fromName) || 'Plexus Ancillary Services', address: a.from_email || a.fromEmail });

module.exports = { KINDS, PRESETS, PORTS, mailKey, encrypt, decrypt, validateAccount, transportOptions, fromHeader, privateHost, clean };
