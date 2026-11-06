/**
 * DecodeLabs — Industrial Training Kit / Batch 2026
 * Project 3: Secure Authentication System
 * ---------------------------------------------------------------
 * Goal : Protect your API routes using modern security standards.
 *       Hash passwords before saving · generate a JWT on login ·
 *       keep a protected route that refuses anonymous callers.
 *
 * Storage: a small file-backed user store (persistence without a
 * database — Project 2 already owns that territory).
 */

require('./src/load-env');

const path = require('path');
const express = require('express');

const requestLog = require('./src/middleware/request-log');
const authRoutes = require('./src/routes/auth.routes');
const vaultRoutes = require('./src/routes/vault.routes');

const { ensureSeed } = require('./src/data/user.store');

const app = express();
const PORT = Number(process.env.PORT) || 5103;

app.disable('x-powered-by');
app.use(express.json({ limit: '48kb' }));
app.use(requestLog);
app.use(express.static(path.join(__dirname, 'public'), { extensions: ['html'] }));

app.use('/api/auth', authRoutes);
app.use('/api/vault', vaultRoutes);

app.use(require('./src/middleware/not-found'));
app.use(require('./src/middleware/error-handler'));

ensureSeed();

app.listen(PORT, () => {
  console.log('');
  console.log('  DecodeLabs · Project 3 · Secure Authentication System');
  console.log(`  Server    : http://localhost:${PORT}`);
  console.log(`  Protected : http://localhost:${PORT}/api/vault/profile`);
  console.log(`  Token TTL : ${process.env.JWT_EXPIRES_IN || '30m'}`);
  console.log('');
});

module.exports = app;
