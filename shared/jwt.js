'use strict';

const jwt = require('jsonwebtoken');
const { randomUUID } = require('node:crypto');
const { required } = require('./config');

const ISSUER = 'bola-auth-service';
const AUDIENCE = 'bola-api';

// ---- Access token milik user (claim-based, scoped) ----
function signAccessToken({ userId, role, scopes }) {
  return jwt.sign({ role, scope: scopes.join(' ') }, required('JWT_ACCESS_SECRET'), {
    algorithm: 'HS256',
    subject: userId,
    issuer: ISSUER,
    audience: AUDIENCE,
    expiresIn: process.env.ACCESS_TOKEN_TTL || '15m',
    jwtid: randomUUID(),
  });
}

function verifyAccessToken(token) {
  // algorithms di-pin => menolak "alg: none" dan algorithm confusion
  return jwt.verify(token, required('JWT_ACCESS_SECRET'), {
    algorithms: ['HS256'],
    issuer: ISSUER,
    audience: AUDIENCE,
  });
}

// ---- Token service-to-service (secret BERBEDA dari token user) ----
function signServiceToken(from, to) {
  return jwt.sign({}, required('INTERNAL_JWT_SECRET'), {
    algorithm: 'HS256',
    issuer: from,
    audience: to,
    expiresIn: '60s',
  });
}

function verifyServiceToken(token, audience) {
  return jwt.verify(token, required('INTERNAL_JWT_SECRET'), { algorithms: ['HS256'], audience });
}

module.exports = { signAccessToken, verifyAccessToken, signServiceToken, verifyServiceToken };
