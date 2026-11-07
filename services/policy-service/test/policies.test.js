'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { decide } = require('../src/policies');

const U1 = '11111111-1111-4111-8111-111111111111';
const U2 = '22222222-2222-4222-8222-222222222222';
const ADM = '99999999-9999-4999-8999-999999999999';
const ALL = ['orders:read', 'orders:write', 'invoices:read', 'invoices:write', 'invoices:pay'];

const user = (id = U1, scopes = ALL) => ({ id, role: 'user', scopes });
const admin = { id: ADM, role: 'admin', scopes: ALL };
const order = (owner, status = 'pending') => ({ type: 'order', id: 'a'.repeat(8) + '-aaaa-4aaa-8aaa-' + 'a'.repeat(12), owner_id: owner, status });
const invoice = (owner, status) => ({ type: 'invoice', owner_id: owner, status });

test('owner boleh membaca order miliknya', () => {
  assert.equal(decide({ subject: user(), action: 'order:read', resource: order(U1) }).allow, true);
});

test('BOLA: user lain tidak boleh membaca order orang lain (NOT_OWNER)', () => {
  const d = decide({ subject: user(U2), action: 'order:read', resource: order(U1) });
  assert.equal(d.allow, false);
  assert.equal(d.code, 'NOT_OWNER');
});

test('RBAC: admin boleh mengakses resource siapapun', () => {
  assert.equal(decide({ subject: admin, action: 'order:read', resource: order(U1) }).allow, true);
  assert.equal(decide({ subject: admin, action: 'invoice:read', resource: invoice(U1, 'paid') }).allow, true);
});

test('list: user -> visibility own, admin -> all', () => {
  assert.equal(decide({ subject: user(), action: 'invoice:list', resource: null }).visibility, 'own');
  assert.equal(decide({ subject: admin, action: 'invoice:list', resource: null }).visibility, 'all');
});

test('ABAC: invoice paid tidak bisa diubah/dihapus oleh owner', () => {
  for (const action of ['invoice:update', 'invoice:delete']) {
    const d = decide({ subject: user(), action, resource: invoice(U1, 'paid') });
    assert.equal(d.allow, false);
    assert.equal(d.code, 'ABAC_DENIED');
  }
});

test('ABAC: admin tetap boleh mengubah/menghapus invoice paid', () => {
  for (const action of ['invoice:update', 'invoice:delete']) {
    assert.equal(decide({ subject: admin, action, resource: invoice(U1, 'paid') }).allow, true);
  }
});

test('ABAC: invoice issued milik sendiri boleh diubah', () => {
  assert.equal(decide({ subject: user(), action: 'invoice:update', resource: invoice(U1, 'issued') }).allow, true);
});

test('ownership dievaluasi sebelum ABAC (tidak bocor status resource orang lain)', () => {
  const d = decide({ subject: user(U2), action: 'invoice:update', resource: invoice(U1, 'paid') });
  assert.equal(d.code, 'NOT_OWNER');
});

test('scope: token tanpa orders:write tidak bisa membuat order', () => {
  const d = decide({ subject: user(U1, ['orders:read']), action: 'order:create', resource: null });
  assert.equal(d.allow, false);
  assert.equal(d.code, 'MISSING_SCOPE');
});

test('invoice:create untuk order milik orang lain ditolak', () => {
  const d = decide({
    subject: user(U2), action: 'invoice:create',
    resource: { type: 'invoice', owner_id: U1, order_status: 'pending' },
  });
  assert.equal(d.code, 'NOT_OWNER');
});

test('invoice:create untuk order yang sudah di-invoice ditolak (INVALID_STATE)', () => {
  const d = decide({
    subject: user(), action: 'invoice:create',
    resource: { type: 'invoice', owner_id: U1, order_status: 'invoiced' },
  });
  assert.equal(d.code, 'INVALID_STATE');
});

test('invoice:pay hanya untuk status issued', () => {
  assert.equal(decide({ subject: user(), action: 'invoice:pay', resource: invoice(U1, 'issued') }).allow, true);
  assert.equal(decide({ subject: user(), action: 'invoice:pay', resource: invoice(U1, 'paid') }).code, 'INVALID_STATE');
});

test('order yang sudah invoiced tidak bisa diubah user, tapi bisa oleh admin', () => {
  assert.equal(decide({ subject: user(), action: 'order:update', resource: order(U1, 'invoiced') }).code, 'INVALID_STATE');
  assert.equal(decide({ subject: admin, action: 'order:update', resource: order(U1, 'invoiced') }).allow, true);
});

test('action tidak dikenal ditolak (default deny)', () => {
  assert.equal(decide({ subject: admin, action: 'order:hack', resource: null }).allow, false);
});

test('aksi tanpa atribut resource ditolak', () => {
  assert.equal(decide({ subject: user(), action: 'order:read', resource: null }).code, 'MISSING_RESOURCE');
});
