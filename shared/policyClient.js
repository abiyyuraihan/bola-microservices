'use strict';

// Policy Enforcement Point (di sisi service) -> bertanya ke Policy Decision Point (policy-service).
const { signServiceToken } = require('./jwt');
const { AppError, E } = require('./errors');

const policyUrl = () => process.env.POLICY_SERVICE_URL || 'http://policy-service:3004';

async function decide(serviceName, req, action, resource) {
  try {
    const res = await fetch(`${policyUrl()}/v1/decide`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        authorization: `Bearer ${signServiceToken(serviceName, 'policy-service')}`,
        'x-request-id': req.id,
      },
      body: JSON.stringify({
        subject: { id: req.user.id, role: req.user.role, scopes: req.user.scopes },
        action,
        resource: resource || null,
        requestId: req.id,
        service: serviceName,
      }),
      signal: AbortSignal.timeout(3000),
    });
    if (!res.ok) throw new Error(`policy-service status ${res.status}`);
    return await res.json();
  } catch (err) {
    console.error(JSON.stringify({ level: 'error', reqId: req.id, msg: 'policy-service gagal', err: err.message }));
    // FAIL CLOSED: kalau PDP tidak bisa diajak bicara, akses ditolak.
    throw new AppError(503, 'POLICY_UNAVAILABLE', 'Layanan otorisasi tidak tersedia');
  }
}

async function authorize(serviceName, req, action, resource) {
  const decision = await decide(serviceName, req, action, resource);
  if (decision.allow) return decision;
  switch (decision.code) {
    case 'NOT_OWNER': throw E.notFound();                 // jangan bocorkan eksistensi resource
    case 'INVALID_STATE': throw E.conflict(decision.reason);
    default: throw E.forbidden(decision.reason);
  }
}

module.exports = { authorize };
