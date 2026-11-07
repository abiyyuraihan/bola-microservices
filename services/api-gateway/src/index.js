'use strict';

/**
 * API Gateway = Policy Enforcement Point (PEP) lapis pertama.
 *  - Satu-satunya service yang terekspos ke luar
 *  - Verifikasi JWT, cek scope kasar, rate limit per-user, deteksi probing BOLA
 *  - Hanya meneruskan route yang di-allowlist (/internal/* tidak pernah dirouting)
 * Service di belakang tetap memverifikasi JWT lagi + meminta keputusan ke policy-service.
 */

const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const { createProxyMiddleware } = require('http-proxy-middleware');

const { requestId, accessLog, listen } = require('../../../shared/app');
const { authenticate } = require('../../../shared/middleware');
const { notFoundHandler, errorHandler } = require('../../../shared/errors');
const { int, required } = require('../../../shared/config');
const { DenyTracker } = require('./denyTracker');

required('JWT_ACCESS_SECRET');

const URLS = {
  auth: process.env.AUTH_SERVICE_URL || 'http://auth-service:3001',
  order: process.env.ORDER_SERVICE_URL || 'http://order-service:3002',
  invoice: process.env.INVOICE_SERVICE_URL || 'http://invoice-service:3003',
};

const denyTracker = new DenyTracker({
  threshold: int('DENY_THRESHOLD', 25),
  windowMs: int('DENY_WINDOW_MS', 5 * 60_000),
  blockMs: int('DENY_BLOCK_MS', 15 * 60_000),
});

const errorBody = (req, code, message) => ({ error: { code, message, requestId: req.id } });
const limited = (message) => (req, res) => res.status(429).json(errorBody(req, 'RATE_LIMITED', message));

// ---------- Rate limiting ----------
const ipLimiter = rateLimit({
  windowMs: 60_000, limit: 600, standardHeaders: 'draft-7', legacyHeaders: false,
  handler: limited('Terlalu banyak request dari IP ini'),
});
const authLimiter = rateLimit({
  windowMs: 15 * 60_000, limit: int('AUTH_RATE_LIMIT', 30), standardHeaders: 'draft-7', legacyHeaders: false,
  handler: limited('Terlalu banyak percobaan autentikasi, coba lagi nanti'),
});
// Per-USER (bukan per-IP): key diambil dari identitas di JWT yang sudah diverifikasi.
const userLimiter = rateLimit({
  windowMs: 60_000,
  limit: (req) => (req.user.role === 'admin' ? int('USER_RATE_LIMIT', 120) * 5 : int('USER_RATE_LIMIT', 120)),
  keyGenerator: (req) => `u:${req.user.id}`,
  standardHeaders: 'draft-7', legacyHeaders: false,
  handler: limited('Rate limit per-user terlampaui'),
});
const writeLimiter = rateLimit({
  windowMs: 60_000, limit: int('WRITE_RATE_LIMIT', 30),
  keyGenerator: (req) => `w:${req.user.id}`,
  skip: (req) => ['GET', 'HEAD', 'OPTIONS'].includes(req.method),
  standardHeaders: 'draft-7', legacyHeaders: false,
  handler: limited('Rate limit operasi tulis terlampaui'),
});

// ---------- Guards ----------
function probeGuard(req, res, next) {
  const wait = denyTracker.blockedFor(req.user.id);
  if (wait > 0) {
    res.set('Retry-After', String(wait));
    return res.status(429).json(errorBody(req, 'TEMPORARILY_BLOCKED', 'Terlalu banyak akses ditolak. Akun diblokir sementara.'));
  }
  return next();
}

// Cek scope kasar berdasarkan method; keputusan detail tetap di policy-service.
const coarseScope = (resource) => (req, res, next) => {
  let needed = ['GET', 'HEAD'].includes(req.method) ? `${resource}:read` : `${resource}:write`;
  if (resource === 'invoices' && req.method === 'POST' && /^\/[^/]+\/pay\/?$/.test(req.path)) needed = 'invoices:pay';
  if (!req.user.scopes.includes(needed)) {
    denyTracker.record(req.user.id);
    return res.status(403).json(errorBody(req, 'FORBIDDEN', 'Scope token tidak mencukupi'));
  }
  return next();
};

const guard = (resource) => [authenticate, probeGuard, userLimiter, writeLimiter, coarseScope(resource)];

// ---------- Proxy ----------
function makeProxy(target, pathFilter) {
  return createProxyMiddleware({
    target,
    changeOrigin: true,
    pathFilter,
    proxyTimeout: 10_000,
    timeout: 10_000,
    on: {
      proxyReq: (proxyReq, req) => {
        proxyReq.setHeader('x-request-id', req.id);
        ['x-user-id', 'x-user-role', 'x-forwarded-user'].forEach((h) => proxyReq.removeHeader(h));
      },
      proxyRes: (proxyRes, req) => {
        if (req.user && (proxyRes.statusCode === 403 || proxyRes.statusCode === 404)) {
          denyTracker.record(req.user.id);
        }
      },
      error: (err, req, res) => {
        console.error(JSON.stringify({ level: 'error', reqId: req.id, msg: 'proxy error', err: err.message }));
        if (res && typeof res.writeHead === 'function' && !res.headersSent) {
          res.writeHead(502, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify(errorBody(req, 'BAD_GATEWAY', 'Layanan tujuan tidak merespons')));
        }
      },
    },
  });
}

// ---------- App ----------
const app = express();
app.disable('x-powered-by');
app.use(helmet());
const origins = (process.env.CORS_ORIGINS || '').split(',').map((s) => s.trim()).filter(Boolean);
app.use(cors({ origin: origins.length ? origins : false }));
app.use(requestId({ trust: false }));
app.use(accessLog('api-gateway'));
app.get('/health', (req, res) => res.json({ status: 'ok', service: 'api-gateway' }));

app.use((req, res, next) => {
  if (Number(req.get('content-length') || 0) > 1_000_000) {
    return res.status(413).json(errorBody(req, 'PAYLOAD_TOO_LARGE', 'Payload terlalu besar'));
  }
  return next();
});
app.use(ipLimiter);

// Auth: endpoint publik hanya dibatasi per-IP; sisanya wajib token.
app.post(['/auth/register', '/auth/login', '/auth/refresh'], authLimiter);
app.use(['/auth/me', '/auth/logout'], authenticate, probeGuard, userLimiter);

// Resource: wajib token + scope + rate limit per-user.
app.use('/orders', ...guard('orders'));
app.use('/invoices', ...guard('invoices'));

// Allowlist route yang diteruskan (regex lebih ketat dari guard di atas => tidak ada bypass).
app.use(makeProxy(URLS.auth, (p) => /^\/auth\/(register|login|refresh|me|logout)$/.test(p)));
app.use(makeProxy(URLS.order, (p) => /^\/orders(\/|$)/.test(p)));
app.use(makeProxy(URLS.invoice, (p) => /^\/invoices(\/|$)/.test(p)));

app.use(notFoundHandler);
app.use(errorHandler);

listen(app, 'api-gateway', Number(process.env.PORT || 3000));
