'use strict';

function required(name) {
  const value = process.env[name];
  if (!value) throw new Error(`Environment variable ${name} wajib diisi`);
  return value;
}

function int(name, fallback) {
  const raw = process.env[name];
  if (!raw) return fallback;
  const n = parseInt(raw, 10);
  return Number.isNaN(n) ? fallback : n;
}

module.exports = { required, int };
