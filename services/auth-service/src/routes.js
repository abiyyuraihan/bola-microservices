'use strict';

const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { z } = require('zod');
const { randomUUID, randomBytes, createHash } = require('node:crypto');
const { signAccessToken } = require('../../../shared/jwt');
const { authenticate, validate, asyncH } = require('../../../shared/middleware');
const { E } = require('../../../shared/errors');

const ALL_SCOPES = ['orders:read', 'orders:write', 'invoices:read', 'invoices:write', 'invoices:pay'];
// Scope = batas atas kemampuan token. Perbedaan hak user vs admin diputuskan policy-service (RBAC/ABAC).
const ROLE_SCOPES = { user: ALL_SCOPES, admin: ALL_SCOPES };

const REFRESH_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const DUMMY_HASH = bcrypt.hashSync('dummy-password-untuk-timing', 12);
const sha256 = (s) => createHash('sha256').update(s).digest('hex');

const emailSchema = z.string().trim().email().max(190).transform((s) => s.toLowerCase());

// .strict() => field tak dikenal (mis. "role": "admin") ditolak, mencegah mass assignment.
const registerSchema = z.object({
  email: emailSchema,
  password: z.string().min(10).max(72),
}).strict();

const loginSchema = z.object({
  email: emailSchema,
  password: z.string().min(1).max(72),
  scope: z.array(z.enum(ALL_SCOPES)).min(1).optional(),
}).strict();

const refreshSchema = z.object({ refreshToken: z.string().min(32).max(256) }).strict();

function buildRouter(pool) {
  const router = express.Router();

  async function issueTokens(user, scopes) {
    const accessToken = signAccessToken({ userId: user.id, role: user.role, scopes });
    const refreshToken = randomBytes(48).toString('hex');
    await pool.query(
      'INSERT INTO refresh_tokens (id, user_id, token_hash, scope, expires_at) VALUES (?, ?, ?, ?, ?)',
      [randomUUID(), user.id, sha256(refreshToken), scopes.join(' '), new Date(Date.now() + REFRESH_TTL_MS)],
    );
    const { iat, exp } = jwt.decode(accessToken);
    return { accessToken, refreshToken, tokenType: 'Bearer', expiresIn: exp - iat, scope: scopes.join(' ') };
  }

  router.post('/register', validate(registerSchema), asyncH(async (req, res) => {
    const { email, password } = req.body;
    const id = randomUUID();                       // UUID dibuat server, bukan auto-increment
    const hash = await bcrypt.hash(password, 12);
    try {
      // role SELALU 'user' pada registrasi publik
      await pool.query('INSERT INTO users (id, email, password_hash, role) VALUES (?, ?, ?, ?)', [id, email, hash, 'user']);
    } catch (err) {
      if (err.code === 'ER_DUP_ENTRY') throw E.conflict('Email sudah terdaftar');
      throw err;
    }
    res.status(201).json({ data: { id, email, role: 'user' } });
  }));

  router.post('/login', validate(loginSchema), asyncH(async (req, res) => {
    const { email, password, scope } = req.body;
    const [rows] = await pool.query('SELECT id, email, password_hash, role FROM users WHERE email = ?', [email]);
    const user = rows[0];
    // bcrypt.compare tetap dijalankan walau user tidak ada => timing seragam (anti user enumeration)
    const ok = await bcrypt.compare(password, user ? user.password_hash : DUMMY_HASH);
    if (!user || !ok) throw E.unauthorized('Email atau password salah');

    const allowed = ROLE_SCOPES[user.role];
    let scopes = allowed;
    if (scope) {
      // Down-scoping: client boleh minta scope LEBIH SEDIKIT, tidak boleh lebih dari hak rolenya.
      if (!scope.every((s) => allowed.includes(s))) throw E.forbidden('Scope yang diminta melebihi hak role');
      scopes = [...new Set(scope)];
    }
    res.json({ data: await issueTokens(user, scopes) });
  }));

  router.post('/refresh', validate(refreshSchema), asyncH(async (req, res) => {
    const [rows] = await pool.query(
      `SELECT rt.id, rt.user_id, rt.scope, rt.expires_at, rt.revoked, u.email, u.role
         FROM refresh_tokens rt JOIN users u ON u.id = rt.user_id
        WHERE rt.token_hash = ?`,
      [sha256(req.body.refreshToken)],
    );
    const row = rows[0];
    if (!row) throw E.unauthorized('Refresh token tidak valid');
    if (row.revoked) {
      // Token yang sudah dipakai dipakai lagi => indikasi pencurian; cabut semua sesi user.
      await pool.query('UPDATE refresh_tokens SET revoked = 1 WHERE user_id = ?', [row.user_id]);
      throw E.unauthorized('Refresh token tidak valid');
    }
    if (new Date(row.expires_at) < new Date()) throw E.unauthorized('Refresh token kedaluwarsa');

    const [r] = await pool.query('UPDATE refresh_tokens SET revoked = 1 WHERE id = ? AND revoked = 0', [row.id]);
    if (r.affectedRows !== 1) throw E.unauthorized('Refresh token tidak valid');

    const scopes = row.scope.split(' ').filter((s) => ROLE_SCOPES[row.role].includes(s));
    res.json({ data: await issueTokens({ id: row.user_id, role: row.role }, scopes) });
  }));

  router.post('/logout', authenticate, validate(refreshSchema), asyncH(async (req, res) => {
    // Hanya bisa mencabut refresh token milik sendiri (ownership check juga di sini)
    await pool.query('UPDATE refresh_tokens SET revoked = 1 WHERE token_hash = ? AND user_id = ?',
      [sha256(req.body.refreshToken), req.user.id]);
    res.status(204).end();
  }));

  // Tidak ada :id di URL => user hanya bisa melihat dirinya sendiri (id diambil dari token).
  router.get('/me', authenticate, asyncH(async (req, res) => {
    const [rows] = await pool.query('SELECT id, email, role, created_at FROM users WHERE id = ?', [req.user.id]);
    if (!rows[0]) throw E.notFound();
    const u = rows[0];
    res.json({ data: { id: u.id, email: u.email, role: u.role, scopes: req.user.scopes, createdAt: u.created_at } });
  }));

  return router;
}

module.exports = { buildRouter };
