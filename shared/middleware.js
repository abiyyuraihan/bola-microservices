'use strict';

const { z } = require('zod');
const { verifyAccessToken, verifyServiceToken } = require('./jwt');
const { E } = require('./errors');

const asyncH = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

function authenticate(req, res, next) {
  const [type, token] = (req.get('authorization') || '').split(' ');
  if (type !== 'Bearer' || !token) return next(E.unauthorized());
  try {
    const p = verifyAccessToken(token);
    req.user = {
      id: p.sub,
      role: p.role,
      scopes: typeof p.scope === 'string' ? p.scope.split(' ').filter(Boolean) : [],
      jti: p.jti,
    };
    return next();
  } catch {
    return next(E.unauthorized('Token tidak valid atau kedaluwarsa'));
  }
}

// Claim-based authorization: token harus membawa SEMUA scope yang dibutuhkan.
function requireScope(...needed) {
  return (req, res, next) => {
    if (needed.every((s) => req.user.scopes.includes(s))) return next();
    return next(E.forbidden('Scope token tidak mencukupi'));
  };
}

// Autentikasi service-to-service.
function requireService(audience, allowedIssuers) {
  return (req, res, next) => {
    const [type, token] = (req.get('authorization') || '').split(' ');
    if (type !== 'Bearer' || !token) return next(E.unauthorized());
    try {
      const p = verifyServiceToken(token, audience);
      if (!allowedIssuers.includes(p.iss)) return next(E.forbidden('Service tidak diizinkan'));
      req.service = p.iss;
      return next();
    } catch {
      return next(E.unauthorized('Service token tidak valid'));
    }
  };
}

// Anti-IDOR tahap 1: ID harus UUID. ID berurutan (1, 2, 3) langsung ditolak.
const uuidSchema = z.string().uuid();
function validateUuidParams(...names) {
  return (req, res, next) => {
    for (const n of names) {
      if (!uuidSchema.safeParse(req.params[n]).success) {
        return next(E.badRequest(`Parameter ${n} harus berupa UUID`));
      }
    }
    return next();
  };
}

function validate(schema, source = 'body') {
  return (req, res, next) => {
    const result = schema.safeParse(req[source]);
    if (!result.success) {
      return next(E.badRequest('Validasi gagal', result.error.issues.map((i) => ({
        path: i.path.join('.'), message: i.message,
      }))));
    }
    req[source] = result.data;
    return next();
  };
}

module.exports = { asyncH, authenticate, requireScope, requireService, validateUuidParams, validate };
