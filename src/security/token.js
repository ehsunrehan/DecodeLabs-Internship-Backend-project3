/**
 * JSON Web Tokens.
 *
 *  sign()   → HS256 signature over { sub, email, role, iat, exp }
 *  verify() → returns a typed reason instead of a thrown library error
 *  revoke() → in-memory denylist so "logout" really means something
 *             for the remaining lifetime of the token.
 */

const jwt = require('jsonwebtoken');

const SECRET = process.env.JWT_SECRET || 'decodelabs-dev-secret';
const TTL = process.env.JWT_EXPIRES_IN || '30m';
const ISSUER = process.env.JWT_ISSUER || 'decodelabs.auth';

/** token string → expiry timestamp (ms) */
const denylist = new Map();

function sign(user, { remember = false } = {}) {
  const expiresIn = remember ? '7d' : TTL;

  const token = jwt.sign(
    {
      sub: user.id,
      email: user.email,
      name: user.name,
      role: user.role
    },
    SECRET,
    {
      expiresIn,
      issuer: ISSUER,
      audience: 'decodelabs.web'
    }
  );

  return { token, expiresIn };
}

/**
 * @returns {{ valid: boolean, payload?: object, reason?: string }}
 */
function verify(token) {
  try {
    const payload = jwt.verify(token, SECRET, { issuer: ISSUER, audience: 'decodelabs.web' });
    if (denylist.has(token)) return { valid: false, reason: 'TOKEN_REVOKED' };
    return { valid: true, payload };
  } catch (error) {
    if (error.name === 'TokenExpiredError') return { valid: false, reason: 'TOKEN_EXPIRED' };
    if (error.name === 'NotBeforeError') return { valid: false, reason: 'TOKEN_NOT_ACTIVE' };
    return { valid: false, reason: 'TOKEN_INVALID' };
  }
}

function revoke(token, payload) {
  const ttlMs = payload && payload.exp ? payload.exp * 1000 - Date.now() : 30 * 60 * 1000;
  denylist.set(token, Date.now() + Math.max(ttlMs, 0));
  sweep();
}

function sweep() {
  const now = Date.now();
  denylist.forEach((expiry, token) => {
    if (expiry <= now) denylist.delete(token);
  });
}

/** Decoded view of a token without throwing — used by /api/auth/inspect. */
function inspect(token) {
  const [header, payload] = String(token).split('.');
  const decode = (segment) => {
    try {
      return JSON.parse(Buffer.from(segment || '', 'base64url').toString('utf8'));
    } catch (_) {
      return null;
    }
  };

  return {
    header: decode(header),
    payload: decode(payload),
    signaturePresent: Boolean(payload !== undefined && String(token).split('.').length === 3)
  };
}

module.exports = { sign, verify, revoke, inspect, TTL };
