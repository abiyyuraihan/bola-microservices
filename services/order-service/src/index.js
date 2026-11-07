'use strict';

const { createApp, finalize, listen } = require('../../../shared/app');
const { createPool } = require('../../../shared/db');
const { required } = require('../../../shared/config');
const { buildRouter, buildInternalRouter } = require('./routes');

(async () => {
  required('JWT_ACCESS_SECRET');
  required('INTERNAL_JWT_SECRET');
  const pool = await createPool();
  const app = createApp('order-service');
  app.use('/orders', buildRouter(pool));
  app.use('/internal', buildInternalRouter(pool));
  finalize(app);
  listen(app, 'order-service', Number(process.env.PORT || 3002), () => pool.end());
})().catch((err) => { console.error(err); process.exit(1); });
