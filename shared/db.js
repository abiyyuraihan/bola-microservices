'use strict';

const mysql = require('mysql2/promise');
const { required } = require('./config');

async function createPool() {
  const pool = mysql.createPool({
    host: required('DB_HOST'),
    port: Number(process.env.DB_PORT || 3306),
    user: required('DB_USER'),
    password: required('DB_PASSWORD'),
    database: required('DB_NAME'),
    waitForConnections: true,
    connectionLimit: 10,
    timezone: 'Z',
  });

  for (let attempt = 1; attempt <= 20; attempt += 1) {
    try {
      await pool.query('SELECT 1');
      return pool;
    } catch (err) {
      console.log(`[db] menunggu MySQL... (${attempt}/20) ${err.code || err.message}`);
      await new Promise((r) => setTimeout(r, 2000));
    }
  }
  throw new Error('Tidak dapat terhubung ke MySQL');
}

module.exports = { createPool };
