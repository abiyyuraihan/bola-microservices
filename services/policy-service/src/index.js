'use strict';

const { createApp, finalize, listen } = require('../../../shared/app');
const { createPool } = require('../../../shared/db');
const { required } = require('../../../shared/config');
const { buildRouter } = require('./routes');

(async () => {
  required('INTERNAL_JWT_SECRET');
  const pool = await createPool();
  const app = createApp('policy-service');
  app.use('/v1', buildRouter(pool));
  finalize(app);
  listen(app, 'policy-service', Number(process.env.PORT || 3004), () => pool.end());
})().catch((err) => { console.error(err); process.exit(1); });
