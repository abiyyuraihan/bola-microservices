'use strict';

class AppError extends Error {
  constructor(status, code, message, details) {
    super(message);
    this.status = status;
    this.code = code;
    this.details = details;
  }
}

const E = {
  badRequest: (message = 'Request tidak valid', details) => new AppError(400, 'BAD_REQUEST', message, details),
  unauthorized: (message = 'Autentikasi diperlukan') => new AppError(401, 'UNAUTHORIZED', message),
  forbidden: (message = 'Akses ditolak') => new AppError(403, 'FORBIDDEN', message),
  // 404 juga dipakai untuk "bukan pemilik" supaya keberadaan resource orang lain tidak bocor.
  notFound: (message = 'Resource tidak ditemukan') => new AppError(404, 'NOT_FOUND', message),
  conflict: (message = 'Konflik state resource') => new AppError(409, 'CONFLICT', message),
  unavailable: (message = 'Layanan sementara tidak tersedia') => new AppError(503, 'SERVICE_UNAVAILABLE', message),
};

function notFoundHandler(req, res) {
  res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Resource tidak ditemukan', requestId: req.id } });
}

// eslint-disable-next-line no-unused-vars
function errorHandler(err, req, res, next) {
  if (res.headersSent) return next(err);
  if (err instanceof AppError) {
    return res.status(err.status).json({
      error: { code: err.code, message: err.message, details: err.details, requestId: req.id },
    });
  }
  if (err && err.type === 'entity.parse.failed') {
    return res.status(400).json({ error: { code: 'BAD_REQUEST', message: 'JSON tidak valid', requestId: req.id } });
  }
  if (err && err.type === 'entity.too.large') {
    return res.status(413).json({ error: { code: 'PAYLOAD_TOO_LARGE', message: 'Payload terlalu besar', requestId: req.id } });
  }
  console.error(JSON.stringify({ level: 'error', reqId: req.id, message: err && err.message, stack: err && err.stack }));
  return res.status(500).json({ error: { code: 'INTERNAL_ERROR', message: 'Terjadi kesalahan pada server', requestId: req.id } });
}

module.exports = { AppError, E, notFoundHandler, errorHandler };
