const test = require('node:test'), assert = require('node:assert');
const m = require('../mailcfg.js');

test('passwords round-trip, and a stored password cannot be moved to another account', () => {
  const key = m.mailKey({ MAIL_KEY: 'k1' });
  const blob = m.encrypt('app-pass-123', key, 'acc1');
  assert.ok(!blob.includes('app-pass-123'));
  assert.equal(m.decrypt(blob, key, 'acc1'), 'app-pass-123');
  assert.throws(() => m.decrypt(blob, key, 'acc2'));
  assert.throws(() => m.decrypt(blob, m.mailKey({ MAIL_KEY: 'other' }), 'acc1'));
});

test('production without MAIL_KEY has no key (so passwords are refused, never stored with a fallback key)', () => {
  assert.equal(m.mailKey({ NODE_ENV: 'production' }), null);
  assert.ok(m.mailKey({ NODE_ENV: 'development' }));
});

test('Google and Microsoft presets fix the server and port', () => {
  const g = m.validateAccount({ provider: 'google', fromEmail: 'Onboarding@PlexusClinical.com', password: 'x', host: 'evil.example', port: 25 });
  assert.equal(g.value.host, 'smtp.gmail.com');
  assert.equal(g.value.port, 465);
  assert.equal(g.value.fromEmail, 'onboarding@plexusclinical.com');
  assert.equal(g.value.username, 'onboarding@plexusclinical.com');
  assert.equal(m.validateAccount({ provider: 'microsoft', fromEmail: 'a@b.com', password: 'x' }).value.port, 587);
});

test('validation: bad email, missing password, odd ports, private hosts in production', () => {
  assert.ok(m.validateAccount({ provider: 'google', fromEmail: 'nope', password: 'x' }).error);
  assert.ok(m.validateAccount({ provider: 'google', fromEmail: 'a@b.com' }).error);
  assert.ok(!m.validateAccount({ provider: 'google', fromEmail: 'a@b.com' }, { prev: { has_password: true } }).error, 'blank password keeps the saved one');
  assert.ok(m.validateAccount({ provider: 'other', fromEmail: 'a@b.com', password: 'x', host: 'smtp.x.com', port: 5432 }).error);
  assert.ok(m.validateAccount({ provider: 'other', fromEmail: 'a@b.com', password: 'x', host: '10.0.0.5', port: 587 }, { prod: true }).error);
  assert.ok(m.validateAccount({ provider: 'other', fromEmail: 'a@b.com', password: 'x', host: 'localhost', port: 587 }, { prod: true }).error);
  assert.ok(!m.validateAccount({ provider: 'other', fromEmail: 'a@b.com', password: 'x', host: 'localhost', port: 2525 }).error, 'local testing allowed outside production');
});

test('display names cannot inject extra headers or addresses', () => {
  const v = m.validateAccount({ provider: 'google', fromEmail: 'a@b.com', fromName: 'Plexus\r\nBcc: x@evil.com <x@evil.com>', password: 'x' }).value;
  assert.ok(!/[\r\n<>]/.test(v.fromName));
  assert.deepEqual(m.fromHeader({ from_name: v.fromName, from_email: 'a@b.com' }).address, 'a@b.com');
});

test('STARTTLS is required in production on non-465 ports', () => {
  assert.equal(m.transportOptions({ host: 'h', port: 587, username: 'u' }, 'p', { prod: true }).requireTLS, true);
  assert.equal(m.transportOptions({ host: 'h', port: 465, username: 'u' }, 'p', { prod: true }).secure, true);
});
