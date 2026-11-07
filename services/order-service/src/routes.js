'use strict';

const express = require('express');
const { z } = require('zod');
const { randomUUID } = require('node:crypto');
const {
  authenticate, requireScope, requireService, validate, validateUuidParams, asyncH,
} = require('../../../shared/middleware');
const { authorize } = require('../../../shared/policyClient');
const { E } = require('../../../shared/errors');

const SERVICE = 'order-service';

const itemSchema = z.object({
  productName: z.string().trim().min(1).max(120),
  quantity: z.number().int().min(1).max(1000),
  unitPrice: z.number().positive().max(1_000_000_000),
}).strict();

// Tidak ada ownerId / status / totalAmount dari client (anti mass-assignment).
const itemsBodySchema = z.object({ items: z.array(itemSchema).min(1).max(50) }).strict();

const listQuerySchema = z.object({
  page: z.coerce.number().int().min(1).default(1),
  limit: z.coerce.number().int().min(1).max(100).default(20),
});

const computeTotal = (items) => items.reduce((sum, i) => sum + Math.round(i.unitPrice * 100) * i.quantity, 0) / 100;
const orderAttrs = (o) => ({ type: 'order', id: o.id, owner_id: o.owner_id, status: o.status });

const toOrder = (row, items) => ({
  id: row.id,
  ownerId: row.owner_id,
  status: row.status,
  totalAmount: Number(row.total_amount),
  ...(items ? { items } : {}),
  createdAt: row.created_at,
  updatedAt: row.updated_at,
});

function buildRouter(pool) {
  const router = express.Router();

  async function loadOrder(id) {
    const [rows] = await pool.query('SELECT * FROM orders WHERE id = ?', [id]);
    return rows[0];
  }

  async function loadItems(orderId) {
    const [rows] = await pool.query(
      'SELECT id, product_name, quantity, unit_price FROM order_items WHERE order_id = ?', [orderId],
    );
    return rows.map((r) => ({ id: r.id, productName: r.product_name, quantity: r.quantity, unitPrice: Number(r.unit_price) }));
  }

  const itemRows = (orderId, items) => items.map((i) => [randomUUID(), orderId, i.productName, i.quantity, i.unitPrice]);

  router.get('/', authenticate, requireScope('orders:read'), validate(listQuerySchema, 'query'), asyncH(async (req, res) => {
    const decision = await authorize(SERVICE, req, 'order:list', null);
    const { page, limit } = req.query;

    // Ownership di level query: user biasa SELALU difilter owner_id dari token.
    const all = decision.visibility === 'all';
    const where = all ? '' : 'WHERE owner_id = ?';
    const params = all ? [] : [req.user.id];

    const [[{ total }]] = await pool.query(`SELECT COUNT(*) AS total FROM orders ${where}`, params);
    const [rows] = await pool.query(
      `SELECT * FROM orders ${where} ORDER BY created_at DESC LIMIT ? OFFSET ?`,
      [...params, limit, (page - 1) * limit],
    );
    res.json({ data: rows.map((r) => toOrder(r)), pagination: { page, limit, total } });
  }));

  router.post('/', authenticate, requireScope('orders:write'), validate(itemsBodySchema), asyncH(async (req, res) => {
    await authorize(SERVICE, req, 'order:create', null);

    const id = randomUUID();
    const { items } = req.body;
    const conn = await pool.getConnection();
    try {
      await conn.beginTransaction();
      // owner_id SELALU dari token, total dihitung server.
      await conn.query('INSERT INTO orders (id, owner_id, status, total_amount) VALUES (?, ?, ?, ?)',
        [id, req.user.id, 'pending', computeTotal(items)]);
      await conn.query('INSERT INTO order_items (id, order_id, product_name, quantity, unit_price) VALUES ?',
        [itemRows(id, items)]);
      await conn.commit();
    } catch (err) {
      await conn.rollback();
      throw err;
    } finally {
      conn.release();
    }
    const order = await loadOrder(id);
    res.status(201).json({ data: toOrder(order, await loadItems(id)) });
  }));

  router.get('/:id', authenticate, requireScope('orders:read'), validateUuidParams('id'), asyncH(async (req, res) => {
    const order = await loadOrder(req.params.id);
    if (!order) throw E.notFound();
    await authorize(SERVICE, req, 'order:read', orderAttrs(order));
    res.json({ data: toOrder(order, await loadItems(order.id)) });
  }));

  router.patch('/:id', authenticate, requireScope('orders:write'), validateUuidParams('id'), validate(itemsBodySchema), asyncH(async (req, res) => {
    const order = await loadOrder(req.params.id);
    if (!order) throw E.notFound();
    await authorize(SERVICE, req, 'order:update', orderAttrs(order));

    const isAdmin = req.user.role === 'admin';
    const { items } = req.body;
    const conn = await pool.getConnection();
    try {
      await conn.beginTransaction();
      // Defense-in-depth: kepemilikan & status dicek ULANG di SQL, bukan hanya di policy.
      const [r] = await conn.query(
        `UPDATE orders SET total_amount = ?
          WHERE id = ? AND (? OR (owner_id = ? AND status = 'pending'))`,
        [computeTotal(items), order.id, isAdmin ? 1 : 0, req.user.id],
      );
      if (r.affectedRows !== 1) throw E.conflict('Order tidak dapat diubah');
      await conn.query('DELETE FROM order_items WHERE order_id = ?', [order.id]);
      await conn.query('INSERT INTO order_items (id, order_id, product_name, quantity, unit_price) VALUES ?',
        [itemRows(order.id, items)]);
      await conn.commit();
    } catch (err) {
      await conn.rollback();
      throw err;
    } finally {
      conn.release();
    }
    res.json({ data: toOrder(await loadOrder(order.id), await loadItems(order.id)) });
  }));

  router.delete('/:id', authenticate, requireScope('orders:write'), validateUuidParams('id'), asyncH(async (req, res) => {
    const order = await loadOrder(req.params.id);
    if (!order) throw E.notFound();
    await authorize(SERVICE, req, 'order:delete', orderAttrs(order));

    const isAdmin = req.user.role === 'admin';
    const [r] = await pool.query(
      `DELETE FROM orders WHERE id = ? AND (? OR (owner_id = ? AND status = 'pending'))`,
      [order.id, isAdmin ? 1 : 0, req.user.id],
    );
    if (r.affectedRows !== 1) throw E.conflict('Order tidak dapat dihapus');
    res.status(204).end();
  }));

  return router;
}

// Endpoint internal: hanya bisa dipanggil invoice-service dengan service token.
// Tidak pernah dirouting oleh API gateway.
function buildInternalRouter(pool) {
  const router = express.Router();
  router.use(requireService('order-service', ['invoice-service']));

  router.get('/orders/:id', validateUuidParams('id'), asyncH(async (req, res) => {
    const [rows] = await pool.query('SELECT id, owner_id, status, total_amount FROM orders WHERE id = ?', [req.params.id]);
    if (!rows[0]) throw E.notFound();
    const o = rows[0];
    res.json({ data: { id: o.id, ownerId: o.owner_id, status: o.status, totalAmount: Number(o.total_amount) } });
  }));

  router.patch('/orders/:id/status', validateUuidParams('id'),
    validate(z.object({ status: z.literal('invoiced') }).strict()),
    asyncH(async (req, res) => {
      const [r] = await pool.query(`UPDATE orders SET status = 'invoiced' WHERE id = ? AND status = 'pending'`, [req.params.id]);
      if (r.affectedRows !== 1) throw E.conflict('Status order tidak dapat diubah');
      res.status(204).end();
    }));

  return router;
}

module.exports = { buildRouter, buildInternalRouter };
