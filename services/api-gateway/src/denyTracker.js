'use strict';

/**
 * Mendeteksi pola probing BOLA: user yang terus-menerus mendapat 403/404
 * (menebak ID milik orang lain) diblokir sementara.
 * In-memory => untuk multi-instance gateway pindahkan state ke Redis.
 */
class DenyTracker {
  constructor({ threshold = 25, windowMs = 5 * 60_000, blockMs = 15 * 60_000 } = {}) {
    this.threshold = threshold;
    this.windowMs = windowMs;
    this.blockMs = blockMs;
    this.entries = new Map();
    setInterval(() => this.sweep(), 60_000).unref();
  }

  record(userId) {
    const now = Date.now();
    const entry = this.entries.get(userId) || { hits: [], blockedUntil: 0 };
    entry.hits = entry.hits.filter((t) => now - t < this.windowMs);
    entry.hits.push(now);
    if (entry.hits.length >= this.threshold) {
      entry.blockedUntil = now + this.blockMs;
      entry.hits = [];
      console.warn(JSON.stringify({ level: 'warn', event: 'BOLA_PROBING_SUSPECTED', userId, blockedForMs: this.blockMs }));
    }
    this.entries.set(userId, entry);
  }

  // detik tersisa jika sedang diblokir, 0 jika tidak
  blockedFor(userId) {
    const entry = this.entries.get(userId);
    if (!entry) return 0;
    const remaining = entry.blockedUntil - Date.now();
    return remaining > 0 ? Math.ceil(remaining / 1000) : 0;
  }

  sweep() {
    const now = Date.now();
    for (const [id, e] of this.entries) {
      if (e.blockedUntil < now && e.hits.every((t) => now - t >= this.windowMs)) this.entries.delete(id);
    }
  }
}

module.exports = { DenyTracker };
