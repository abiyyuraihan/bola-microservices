'use strict';

const { signServiceToken } = require('../../../shared/jwt');
const { E } = require('../../../shared/errors');

const baseUrl = () => process.env.ORDER_SERVICE_URL || 'http://order-service:3002';

function call(method, path, reqId, body) {
  return fetch(`${baseUrl()}${path}`, {
    method,
    headers: {
      authorization: `Bearer ${signServiceToken('invoice-service', 'order-service')}`,
      'content-type': 'application/json',
      'x-request-id': reqId,
    },
    body: body ? JSON.stringify(body) : undefined,
    signal: AbortSignal.timeout(4000),
  });
}

async function getOrder(id, reqId) {
  let res;
  try {
    res = await call('GET', `/internal/orders/${id}`, reqId);
  } catch {
    throw E.unavailable('Order service tidak tersedia');
  }
  if (res.status === 404) return null;
  if (!res.ok) throw E.unavailable('Order service tidak tersedia');
  return (await res.json()).data;
}

async function markInvoiced(id, reqId) {
  try {
    const res = await call('PATCH', `/internal/orders/${id}/status`, reqId, { status: 'invoiced' });
    if (!res.ok) console.error(JSON.stringify({ level: 'warn', reqId, msg: 'gagal menandai order invoiced', status: res.status }));
  } catch (err) {
    console.error(JSON.stringify({ level: 'warn', reqId, msg: 'gagal menandai order invoiced', err: err.message }));
  }
}

module.exports = { getOrder, markInvoiced };
