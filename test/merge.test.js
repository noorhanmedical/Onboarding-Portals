const test = require('node:test'), assert = require('node:assert');
const { merge3 } = require('../public/merge.js');
const base = { org: { npi: '', phone: '' }, logins: [{ id: 'a', name: 'Athena' }], audit: [{ ev: 'x' }], days: ['Mon'] };
test('different fields from two people both survive', () => {
  const clinic = { ...base, org: { npi: '123', phone: '' } }, billing = { ...base, org: { npi: '', phone: '555' } };
  assert.deepEqual(merge3(base, clinic, billing).org, { npi: '123', phone: '555' });
});
test('both add logins; one edits, one deletes', () => {
  const mine = { ...base, logins: [{ id: 'a', name: 'Athena One' }, { id: 'm', name: 'Quest' }] };
  const theirs = { ...base, logins: [{ id: 'a', name: 'Athena' }, { id: 't', name: 'Availity' }] };
  assert.deepEqual(merge3(base, mine, theirs).logins.map((x) => x.id + ':' + x.name).sort(), ['a:Athena One', 'm:Quest', 't:Availity']);
  const del = { ...base, logins: [] };
  assert.deepEqual(merge3(base, del, base).logins, []);
});
test('audit entries from both sides are kept, newest first', () => {
  const mine = { ...base, audit: [{ ev: 'mine' }, { ev: 'x' }] }, theirs = { ...base, audit: [{ ev: 'theirs' }, { ev: 'x' }] };
  assert.deepEqual(merge3(base, mine, theirs).audit.map((a) => a.ev), ['mine', 'theirs', 'x']);
});
test('same field changed by both: mine wins', () => {
  assert.equal(merge3(base, { ...base, org: { npi: '1', phone: '' } }, { ...base, org: { npi: '2', phone: '' } }).org.npi, '1');
});
test('primitive arrays set-merge', () => {
  assert.deepEqual(merge3(base, { ...base, days: ['Mon', 'Tue'] }, { ...base, days: ['Wed'] }).days.sort(), ['Tue', 'Wed']);
});
