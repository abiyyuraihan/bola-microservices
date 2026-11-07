'use strict';

const bcrypt = require('bcryptjs');
const { randomUUID } = require('node:crypto');
const { createApp, finalize, listen } = require('../../../shared/app');
const { createPool } = require('../../../shared/db');
const { required } = require('../../../shared/config');
const { buildRouter } = require('./routes');

async function seedAdmin(pool) {
  const { ADMIN_EMAIL, ADMIN_PASSWORD } = process.env;
  if (!ADMIN_EMAIL || !ADMIN_PASSWORD) return;
  const email = ADMIN_EMAIL.toLowerCase();
  const [rows] = await pool.query('SELECT id FROM users WHERE email = ?', [email]);
  if (rows.length) return;
  const hash = await bcrypt.hash(ADMIN_PASSWORD, 12);
  await pool.query('INSERT INTO users (id, email, password_hash, role) VALUES (?, ?, ?, ?)', [randomUUID(), email, hash, 'admin']);
  console.log(`[auth-service] admin awal dibuat: ${email}`);
}

(async () => {
  required('JWT_ACCESS_SECRET');
  const pool = await createPool();
  await seedAdmin(pool);

  const app = createApp('auth-service');
  app.use('/auth', buildRouter(pool));
  finalize(app);
  listen(app, 'auth-service', Number(process.env.PORT || 3001), () => pool.end());
})().catch((err) => { console.error(err); process.exit(1); });
