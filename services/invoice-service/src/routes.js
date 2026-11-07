'use strict';

const express = require('express');
const { z } = require('zod');
const { randomUUID } = require('node:crypto');
const {
  authenticate, requireScope, validate, validateUuidParams, asyncH,
} = require('../../../shared/middleware');
const { authorize } = require('../../../shared/policyClient');
const { E } = require('../../../shared/errors');
const { getOrder, markInvoiced } = require('./orderClient');

const SERVICE = 'invoice-service';

const createSchema = z.object({
  orderId: z.string().uuid(),
  description: z.string().trim().max(255).optional(),
}).strict();

// Schema PATCH berbeda per role: user hanya boleh mengubah description.
const userPatchSchema = z.object({ description: z.string().trim().max(255) }).strict();
const adminPatchSchema = z.object({
  description: z.string().trim().max(255).optional(),
  amount: z.number().positive().max(10_000_000_000).optional(),
  status: z.enum(['issued', 'paid', 'void']).optional(),
}).strict().refine((o) => Object.keys(o).length > 0, { message: 'Minimal satu field harus diisi' });

const listQuerySchema = z.object({
  page: z.coerce.number().int().min(1).default(1),
  limit: z.coerce.number().int().min(1).max(100).default(20),
  status: z.enum(['issued', 'paid', 'void']).optional(),
});

const COLUMNS = { description: 'description', amount: 'amount', status: 'status' };
const invoiceAttrs = (i) => ({ type: 'invoice', id: i.id, owner_id: i.owner_id, status: i.status });

const toInvoice = (r) => ({
  id: r.id,
  orderId: r.order_id,
  ownerId: r.owner_id,
  amount: Number(r.amount),
  status: r.status,
  description: r.description,
  paidAt: r.paid_at,
  createdAt: r.created_at,
  updatedAt: r.updated_at,
});

function buildRouter(pool) {
  const router = express.Router();

  async function loadInvoice(id) {
    const [rows] = await pool.query('SELECT * FROM invoices WHERE id = ?', [id]);
    return rows[0];
  }

  router.get('/', authenticate, requireScope('invoices:read'), validate(listQuerySchema, 'query'), asyncH(async (req, res) => {
    const decision = await authorize(SERVICE, req, 'invoice:list', null);
    const { page, limit, status } = req.query;

    const conds = [];
    const params = [];
    if (decision.visibility !== 'all') { conds.push('owner_id = ?'); params.push(req.user.id); }
    if (status) { conds.push('status = ?'); params.push(status); }
    const where = conds.length ? `WHERE ${conds.join(' AND ')}` : '';

    const [[{ total }]] = await pool.query(`SELECT COUNT(*) AS total FROM invoices ${where}`, params);
    const [rows] = await pool.query(
      `SELECT * FROM invoices ${where} ORDER BY created_at DESC LIMIT ? OFFSET ?`,
      [...params, limit, (page - 1) * limit],
    );
    res.json({ data: rows.map(toInvoice), pagination: { page, limit, total } });
  }));

  router.post('/', authenticate, requireScope('invoices:write'), validate(createSchema), asyncH(async (req, res) => {
    // Referensi objek lintas service: orderId dari client TIDAK dipercaya.
    const order = await getOrder(req.body.orderId, req.id);
    if (!order) throw E.notFound();
    await authorize(SERVICE, req, 'invoice:create', {
      type: 'invoice', owner_id: order.ownerId, order_status: order.status,
    });

    const id = randomUUID();
    try {
      await pool.query(
        `INSERT INTO invoices (id, order_id, owner_id, amount, status, description)
         VALUES (?, ?, ?, ?, 'issued', ?)`,
        [id, order.id, order.ownerId, order.totalAmount, req.body.description || null], // amount dari order, bukan dari client
      );
    } catch (err) {
      if (err.code === 'ER_DUP_ENTRY') throw E.conflict('Order ini sudah memiliki invoice');
      throw err;
    }
    await markInvoiced(order.id, req.id);
    res.status(201).json({ data: toInvoice(await loadInvoice(id)) });
  }));

  router.get('/:id', authenticate, requireScope('invoices:read'), validateUuidParams('id'), asyncH(async (req, res) => {
    const invoice = await loadInvoice(req.params.id);
    if (!invoice) throw E.notFound();
    await authorize(SERVICE, req, 'invoice:read', invoiceAttrs(invoice));
    res.json({ data: toInvoice(invoice) });
  }));

  router.patch('/:id', authenticate, requireScope('invoices:write'), validateUuidParams('id'), asyncH(async (req, res) => {
    const invoice = await loadInvoice(req.params.id);
    if (!invoice) throw E.notFound();
    await authorize(SERVICE, req, 'invoice:update', invoiceAttrs(invoice));

    const isAdmin = req.user.role === 'admin';
    const parsed = (isAdmin ? adminPatchSchema : userPatchSchema).safeParse(req.body);
    if (!parsed.success) {
      throw E.badRequest('Validasi gagal', parsed.error.issues.map((i) => ({ path: i.path.join('.'), message: i.message })));
    }

    const sets = [];
    const values = [];
    for (const [key, value] of Object.entries(parsed.data)) {
      sets.push(`${COLUMNS[key]} = ?`);
      values.push(value);
    }
    if (parsed.data.status === 'paid') sets.push('paid_at = UTC_TIMESTAMP()');

    // Defense-in-depth: aturan ownership & "paid immutable" juga dikunci di SQL.
    const [r] = await pool.query(
      `UPDATE invoices SET ${sets.join(', ')}
        WHERE id = ? AND (? OR (owner_id = ? AND status <> 'paid'))`,
      [...values, invoice.id, isAdmin ? 1 : 0, req.user.id],
    );
    if (r.affectedRows !== 1) throw E.conflict('Invoice tidak dapat diubah');
    res.json({ data: toInvoice(await loadInvoice(invoice.id)) });
  }));

  router.post('/:id/pay', authenticate, requireScope('invoices:pay'), validateUuidParams('id'), asyncH(async (req, res) => {
    const invoice = await loadInvoice(req.params.id);
    if (!invoice) throw E.notFound();
    await authorize(SERVICE, req, 'invoice:pay', invoiceAttrs(invoice));

    const isAdmin = req.user.role === 'admin';
    const [r] = await pool.query(
      `UPDATE invoices SET status = 'paid', paid_at = UTC_TIMESTAMP()
        WHERE id = ? AND status = 'issued' AND (? OR owner_id = ?)`,
      [invoice.id, isAdmin ? 1 : 0, req.user.id],
    );
    if (r.affectedRows !== 1) throw E.conflict('Invoice tidak dapat dibayar');
    res.json({ data: toInvoice(await loadInvoice(invoice.id)) });
  }));

  router.delete('/:id', authenticate, requireScope('invoices:write'), validateUuidParams('id'), asyncH(async (req, res) => {
    const invoice = await loadInvoice(req.params.id);
    if (!invoice) throw E.notFound();
    await authorize(SERVICE, req, 'invoice:delete', invoiceAttrs(invoice));

    const isAdmin = req.user.role === 'admin';
    const [r] = await pool.query(
      `DELETE FROM invoices WHERE id = ? AND (? OR (owner_id = ? AND status <> 'paid'))`,
      [invoice.id, isAdmin ? 1 : 0, req.user.id],
    );
    if (r.affectedRows !== 1) throw E.conflict('Invoice tidak dapat dihapus');
    res.status(204).end();
  }));

  return router;
}

module.exports = { buildRouter };
