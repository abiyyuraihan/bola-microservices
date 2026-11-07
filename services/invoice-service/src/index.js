'use strict';

const { createApp, finalize, listen } = require('../../../shared/app');
const { createPool } = require('../../../shared/db');
const { required } = require('../../../shared/config');
const { buildRouter } = require('./routes');

(async () => {
  required('JWT_ACCESS_SECRET');
  required('INTERNAL_JWT_SECRET');
  const pool = await createPool();
  const app = createApp('invoice-service');
  app.use('/invoices', buildRouter(pool));
  finalize(app);
  listen(app, 'invoice-service', Number(process.env.PORT || 3003), () => pool.end());
})().catch((err) => { console.error(err); process.exit(1); });
