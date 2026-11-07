'use strict';

const express = require('express');
const helmet = require('helmet');
const { randomUUID } = require('node:crypto');
const { notFoundHandler, errorHandler } = require('./errors');

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

// trust=true hanya untuk service internal (id berasal dari gateway). Gateway selalu membuat id baru.
function requestId({ trust = false } = {}) {
  return (req, res, next) => {
    const incoming = req.get('x-request-id');
    req.id = trust && incoming && UUID_RE.test(incoming) ? incoming : randomUUID();
    res.set('x-request-id', req.id);
    next();
  };
}

function accessLog(name) {
  return (req, res, next) => {
    const start = Date.now();
    res.on('finish', () => {
      console.log(JSON.stringify({
        svc: name, reqId: req.id, method: req.method,
        path: req.originalUrl.split('?')[0], status: res.statusCode,
        ms: Date.now() - start, user: req.user && req.user.id,
      }));
    });
    next();
  };
}

function createApp(name) {
  const app = express();
  app.disable('x-powered-by');
  app.use(helmet());
  app.use(requestId({ trust: true }));
  app.use(accessLog(name));
  app.use(express.json({ limit: '100kb' }));
  app.get('/health', (req, res) => res.json({ status: 'ok', service: name }));
  return app;
}

function finalize(app) {
  app.use(notFoundHandler);
  app.use(errorHandler);
}

function listen(app, name, port, onShutdown = async () => {}) {
  const server = app.listen(port, () => console.log(`[${name}] listening on :${port}`));
  const stop = (signal) => {
    console.log(`[${name}] ${signal} diterima, shutting down`);
    server.close(async () => {
      await Promise.resolve(onShutdown()).catch(() => {});
      process.exit(0);
    });
    setTimeout(() => process.exit(1), 10_000).unref();
  };
  process.on('SIGTERM', () => stop('SIGTERM'));
  process.on('SIGINT', () => stop('SIGINT'));
  return server;
}

module.exports = { createApp, finalize, listen, requestId, accessLog };
