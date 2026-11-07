'use strict';

/**
 * Policy Decision Point (PDP).
 * Urutan evaluasi (semua harus lolos):
 *   1. Scope token  (claim-based)
 *   2. RBAC         (role boleh melakukan action?)
 *   3. Ownership    (admin: semua; user: hanya miliknya)  -> NOT_OWNER
 *   4. ABAC         (atribut resource/subject, mis. invoice paid)
 */

const ACTION_SCOPE = {
  'order:list': 'orders:read',
  'order:read': 'orders:read',
  'order:create': 'orders:write',
  'order:update': 'orders:write',
  'order:delete': 'orders:write',
  'invoice:list': 'invoices:read',
  'invoice:read': 'invoices:read',
  'invoice:create': 'invoices:write',
  'invoice:update': 'invoices:write',
  'invoice:delete': 'invoices:write',
  'invoice:pay': 'invoices:pay',
};

const ROLE_PERMISSIONS = {
  user: new Set(Object.keys(ACTION_SCOPE)),
  admin: new Set(['*']),
};

const NO_RESOURCE_ACTIONS = new Set(['order:list', 'invoice:list', 'order:create']);

const allow = (extra = {}) => ({ allow: true, code: 'OK', reason: 'Diizinkan', ...extra });
const deny = (code, reason, rule) => ({ allow: false, code, reason, rule });

// ---- ABAC rules ----
const ABAC_RULES = [
  {
    name: 'paid-invoice-immutable',
    evaluate: ({ subject, action, resource }) => {
      if (resource && resource.type === 'invoice' && resource.status === 'paid'
        && ['invoice:update', 'invoice:delete'].includes(action) && subject.role !== 'admin') {
        return deny('ABAC_DENIED', 'Invoice berstatus paid tidak dapat diubah atau dihapus kecuali oleh admin', 'paid-invoice-immutable');
      }
      return null;
    },
  },
  {
    name: 'pay-only-issued-invoice',
    evaluate: ({ action, resource }) => {
      if (action === 'invoice:pay' && resource && resource.status !== 'issued') {
        return deny('INVALID_STATE', 'Hanya invoice berstatus issued yang dapat dibayar', 'pay-only-issued-invoice');
      }
      return null;
    },
  },
  {
    name: 'order-editable-only-when-pending',
    evaluate: ({ subject, action, resource }) => {
      if (resource && resource.type === 'order' && ['order:update', 'order:delete'].includes(action)
        && resource.status !== 'pending' && subject.role !== 'admin') {
        return deny('INVALID_STATE', 'Order yang sudah di-invoice tidak dapat diubah atau dihapus', 'order-editable-only-when-pending');
      }
      return null;
    },
  },
  {
    name: 'invoice-only-for-pending-order',
    evaluate: ({ action, resource }) => {
      if (action === 'invoice:create' && resource && resource.order_status !== 'pending') {
        return deny('INVALID_STATE', 'Order ini sudah memiliki invoice', 'invoice-only-for-pending-order');
      }
      return null;
    },
  },
];

function decide({ subject, action, resource }) {
  const requiredScope = ACTION_SCOPE[action];
  if (!requiredScope) return deny('UNKNOWN_ACTION', 'Action tidak dikenal');

  // 1. Scope
  if (!subject.scopes.includes(requiredScope)) {
    return deny('MISSING_SCOPE', `Token tidak memiliki scope ${requiredScope}`);
  }

  // 2. RBAC
  const perms = ROLE_PERMISSIONS[subject.role];
  if (!perms || !(perms.has('*') || perms.has(action))) {
    return deny('ROLE_NOT_ALLOWED', 'Role tidak diizinkan melakukan aksi ini');
  }
  const isAdmin = subject.role === 'admin';

  // List: tidak ada resource tunggal; service wajib memfilter query sesuai visibility.
  if (action.endsWith(':list')) return allow({ visibility: isAdmin ? 'all' : 'own' });

  if (!NO_RESOURCE_ACTIONS.has(action) && (!resource || !resource.owner_id)) {
    return deny('MISSING_RESOURCE', 'Atribut resource wajib disertakan');
  }

  // 3. Ownership
  if (resource && resource.owner_id && !isAdmin && resource.owner_id !== subject.id) {
    return deny('NOT_OWNER', 'Resource bukan milik subject', 'ownership');
  }

  // 4. ABAC
  for (const rule of ABAC_RULES) {
    const verdict = rule.evaluate({ subject, action, resource });
    if (verdict) return verdict;
  }
  return allow();
}

module.exports = { decide, ACTION_SCOPE };
