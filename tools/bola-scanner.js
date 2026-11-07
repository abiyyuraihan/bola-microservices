#!/usr/bin/env node
'use strict';

/**
 * Automated BOLA scanner.
 * Membuat 2 user biasa (A = korban, B = penyerang) + login admin, lalu mencoba
 * mengakses resource A memakai token B lewat semua endpoint. Exit code 1 jika ada celah.
 *
 *   BASE_URL=http://localhost:3000 ADMIN_EMAIL=... ADMIN_PASSWORD=... node tools/bola-scanner.js
 *   Tambahkan --rate-limit untuk menguji rate limit per-user & deteksi probing.
 */

const BASE = process.env.BASE_URL || 'http://localhost:3000';
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || 'admin@example.com';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const WITH_RATE = process.argv.includes('--rate-limit');

const c = {
  green: (s) => `\x1b[32m${s}\x1b[0m`,
  red: (s) => `\x1b[31m${s}\x1b[0m`,
  dim: (s) => `\x1b[2m${s}\x1b[0m`,
  bold: (s) => `\x1b[1m${s}\x1b[0m`,
};
const results = [];

async function api(method, path, { token, body } = {}) {
  const res = await fetch(BASE + path, {
    method,
    headers: { ...(token ? { authorization: `Bearer ${token}` } : {}), ...(body ? { 'content-type': 'application/json' } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  let json = null;
  try { json = await res.json(); } catch { /* 204 / non-json */ }
  return { status: res.status, json };
}

function check(name, ok, detail = '') {
  results.push({ name, ok });
  console.log(`${ok ? c.green('PASS') : c.red('FAIL')}  ${name}${ok ? '' : c.dim(`  -> ${detail}`)}`);
}
const expectStatus = (name, res, allowed) => check(name, allowed.includes(res.status), `status ${res.status}, diharapkan ${allowed.join('/')}`);
const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');

async function newUser(label, password) {
  const email = `scan.${label}.${Math.random().toString(36).slice(2, 8)}@example.test`;
  const reg = await api('POST', '/auth/register', { body: { email, password } });
  if (reg.status !== 201) throw new Error(`register ${label} gagal: ${reg.status} ${JSON.stringify(reg.json)}`);
  const tokens = await login(email, password);
  return { email, id: reg.json.data.id, token: tokens.accessToken };
}

async function login(email, password, scope) {
  const r = await api('POST', '/auth/login', { body: { email, password, ...(scope ? { scope } : {}) } });
  if (r.status !== 200) throw new Error(`login ${email} gagal: ${r.status} ${JSON.stringify(r.json)}`);
  return r.json.data;
}

(async () => {
  console.log(c.bold(`\nBOLA scanner -> ${BASE}\n`));
  const password = 'Sup3r-Scanner-Pass!';

  const A = await newUser('victim', password);
  const B = await newUser('attacker', password);
  const admin = ADMIN_PASSWORD ? (await login(ADMIN_EMAIL, ADMIN_PASSWORD)).accessToken : null;
  if (!admin) console.log(c.dim('ADMIN_PASSWORD tidak diset: test RBAC/ABAC admin dilewati\n'));

  // ---- Arrange: A membuat order + invoice ----
  const orderRes = await api('POST', '/orders', { token: A.token, body: { items: [{ productName: 'Keyboard', quantity: 2, unitPrice: 150000 }] } });
  const orderId = orderRes.json && orderRes.json.data && orderRes.json.data.id;
  const invRes = await api('POST', '/invoices', { token: A.token, body: { orderId, description: 'Invoice korban' } });
  const invoiceId = invRes.json && invRes.json.data && invRes.json.data.id;
  if (!orderId || !invoiceId) throw new Error(`Arrange gagal: order=${orderRes.status} invoice=${invRes.status}`);
  check('Arrange: A membuat order & invoice dengan UUID', /^[0-9a-f-]{36}$/.test(orderId) && /^[0-9a-f-]{36}$/.test(invoiceId));
  check('Arrange: amount invoice dihitung server (300000)', invRes.json.data.amount === 300000, `amount=${invRes.json.data.amount}`);

  const DENY = [403, 404];

  // ---- 1. Akses tanpa / dengan token palsu ----
  expectStatus('Tanpa token -> 401', await api('GET', '/orders'), [401]);
  const parts = B.token.split('.');
  const forgedPayload = { ...JSON.parse(Buffer.from(parts[1], 'base64url').toString()), role: 'admin' };
  expectStatus('Token dimodifikasi (role=admin) -> 401', await api('GET', `/orders/${orderId}`, { token: `${parts[0]}.${b64(forgedPayload)}.${parts[2]}` }), [401]);
  const noneToken = `${b64({ alg: 'none', typ: 'JWT' })}.${b64({ sub: A.id, role: 'admin', scope: 'orders:read', iss: 'bola-auth-service', aud: 'bola-api', exp: Math.floor(Date.now() / 1000) + 600 })}.`;
  expectStatus('Token alg=none -> 401', await api('GET', `/orders/${orderId}`, { token: noneToken }), [401]);

  // ---- 2. IDOR / BOLA pada order ----
  expectStatus('B GET order milik A', await api('GET', `/orders/${orderId}`, { token: B.token }), DENY);
  expectStatus('B PATCH order milik A', await api('PATCH', `/orders/${orderId}`, { token: B.token, body: { items: [{ productName: 'x', quantity: 1, unitPrice: 1 }] } }), DENY);
  expectStatus('B DELETE order milik A', await api('DELETE', `/orders/${orderId}`, { token: B.token }), DENY);

  // ---- 3. IDOR / BOLA pada invoice ----
  expectStatus('B GET invoice milik A', await api('GET', `/invoices/${invoiceId}`, { token: B.token }), DENY);
  expectStatus('B PATCH invoice milik A', await api('PATCH', `/invoices/${invoiceId}`, { token: B.token, body: { description: 'hacked' } }), DENY);
  expectStatus('B bayar invoice milik A', await api('POST', `/invoices/${invoiceId}/pay`, { token: B.token }), DENY);
  expectStatus('B DELETE invoice milik A', await api('DELETE', `/invoices/${invoiceId}`, { token: B.token }), DENY);

  // ---- 4. Referensi objek lintas service ----
  const order2 = await api('POST', '/orders', { token: A.token, body: { items: [{ productName: 'Mouse', quantity: 1, unitPrice: 50000 }] } });
  expectStatus('B membuat invoice dari order milik A', await api('POST', '/invoices', { token: B.token, body: { orderId: order2.json.data.id } }), DENY);

  // ---- 5. Kebocoran lewat list ----
  const listO = await api('GET', '/orders', { token: B.token });
  check('List order B tidak berisi order A', listO.status === 200 && !listO.json.data.some((o) => o.ownerId === A.id), JSON.stringify(listO.json).slice(0, 120));
  const listI = await api('GET', '/invoices', { token: B.token });
  check('List invoice B tidak berisi invoice A', listI.status === 200 && !listI.json.data.some((i) => i.ownerId === A.id), JSON.stringify(listI.json).slice(0, 120));

  // ---- 6. ID berurutan / bukan UUID ----
  expectStatus('GET /orders/1 (ID berurutan) ditolak', await api('GET', '/orders/1', { token: B.token }), [400, 404]);
  expectStatus('GET /invoices/1 (ID berurutan) ditolak', await api('GET', '/invoices/1', { token: B.token }), [400, 404]);

  // ---- 7. Mass assignment ----
  const mass = await api('POST', '/orders', { token: B.token, body: { ownerId: A.id, owner_id: A.id, items: [{ productName: 'x', quantity: 1, unitPrice: 1 }] } });
  check('Mass assignment ownerId pada order tidak berhasil', mass.status === 400 || (mass.status === 201 && mass.json.data.ownerId === B.id), `status ${mass.status}`);
  const regAdmin = await api('POST', '/auth/register', { body: { email: `scan.role.${Date.now()}@example.test`, password, role: 'admin' } });
  check('Register dengan role=admin tidak menghasilkan admin', regAdmin.status === 400 || (regAdmin.status === 201 && regAdmin.json.data.role === 'user'), `status ${regAdmin.status}`);

  // ---- 8. Scoped token ----
  const roTokens = await login(B.email, password, ['invoices:read']);
  expectStatus('Token scope invoices:read tidak bisa POST /orders', await api('POST', '/orders', { token: roTokens.accessToken, body: { items: [{ productName: 'x', quantity: 1, unitPrice: 1 }] } }), [403]);
  expectStatus('Token scope invoices:read bisa GET /invoices', await api('GET', '/invoices', { token: roTokens.accessToken }), [200]);

  // ---- 9. ABAC: invoice paid ----
  const pay = await api('POST', `/invoices/${invoiceId}/pay`, { token: A.token });
  expectStatus('A (owner) membayar invoice miliknya', pay, [200]);
  expectStatus('ABAC: owner PATCH invoice paid ditolak', await api('PATCH', `/invoices/${invoiceId}`, { token: A.token, body: { description: 'edit setelah paid' } }), [403]);
  expectStatus('ABAC: owner DELETE invoice paid ditolak', await api('DELETE', `/invoices/${invoiceId}`, { token: A.token }), [403]);

  // ---- 10. RBAC admin ----
  if (admin) {
    expectStatus('RBAC: admin GET order milik A', await api('GET', `/orders/${orderId}`, { token: admin }), [200]);
    expectStatus('RBAC: admin GET invoice milik A', await api('GET', `/invoices/${invoiceId}`, { token: admin }), [200]);
    expectStatus('ABAC: admin boleh PATCH invoice paid', await api('PATCH', `/invoices/${invoiceId}`, { token: admin, body: { description: 'dikoreksi admin' } }), [200]);
    const adminList = await api('GET', '/invoices?limit=100', { token: admin });
    check('RBAC: admin melihat invoice semua user', adminList.status === 200 && adminList.json.pagination.total >= 1);
  }

  // ---- 11. Rate limiting & deteksi probing (opsional) ----
  if (WITH_RATE) {
    console.log(c.dim('\nUji rate limit (opsional)...'));
    const C = await newUser('ratelimit', password);
    let got429 = false;
    for (let i = 0; i < 400 && !got429; i += 1) got429 = (await api('GET', '/orders', { token: C.token })).status === 429;
    check('Rate limit per-user mengembalikan 429', got429);

    const D = await newUser('prober', password);
    let blocked = false;
    for (let i = 0; i < 60 && !blocked; i += 1) {
      const r = await api('GET', `/orders/${crypto.randomUUID()}`, { token: D.token });
      blocked = r.status === 429;
    }
    check('Probing UUID acak memicu pemblokiran sementara (429)', blocked);
  }

  const failed = results.filter((r) => !r.ok);
  console.log(`\n${c.bold('Ringkasan')}: ${results.length - failed.length}/${results.length} lulus`);
  if (failed.length) {
    console.log(c.red(`${failed.length} pengujian GAGAL: potensi celah BOLA!`));
    process.exit(1);
  }
  console.log(c.green('Tidak ditemukan celah BOLA pada skenario yang diuji.'));
})().catch((err) => { console.error(c.red(`Scanner error: ${err.message}`)); process.exit(2); });
