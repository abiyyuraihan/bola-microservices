'use strict';

const express = require('express');
const { z } = require('zod');
const { randomUUID } = require('node:crypto');
const { requireService, validate, asyncH } = require('../../../shared/middleware');
const { decide } = require('./policies');

const bodySchema = z.object({
  subject: z.object({
    id: z.string().uuid(),
    role: z.enum(['user', 'admin']),
    scopes: z.array(z.string().max(64)).max(32),
  }),
  action: z.string().max(64),
  resource: z.object({
    type: z.string().max(32),
    id: z.string().uuid().optional(),
    owner_id: z.string().uuid().optional(),
    status: z.string().max(32).optional(),
    order_status: z.string().max(32).optional(),
  }).nullable(),
  requestId: z.string().max(64).optional(),
  service: z.string().max(32).optional(),
});

function buildRouter(pool) {
  const router = express.Router();

  router.post(
    '/decide',
    requireService('policy-service', ['order-service', 'invoice-service']),
    validate(bodySchema),
    asyncH(async (req, res) => {
      const { subject, action, resource, requestId, service } = req.body;
      const decision = decide({ subject, action, resource });

      // Audit trail semua keputusan (best effort; tidak menghalangi response).
      pool.query(
        `INSERT INTO decision_logs
           (id, request_id, service, subject_id, role, action, resource_type, resource_id, effect, code, reason)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [randomUUID(), requestId || req.id, service || req.service, subject.id, subject.role, action,
          resource ? resource.type : null, resource ? resource.id || null : null,
          decision.allow ? 'allow' : 'deny', decision.code, decision.reason],
      ).catch((err) => console.error('[policy] gagal menulis audit log:', err.message));

      res.json(decision);
    }),
  );

  return router;
}

module.exports = { buildRouter };
