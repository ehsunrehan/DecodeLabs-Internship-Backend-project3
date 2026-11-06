/**
 * /api/auth — registration, sign-in, sign-out, refresh, current session.
 *
 *   POST /register   hash + store, then hand back a token → 201
 *   POST /login      verify hash → JWT → 200   (rate limited)
 *   POST /logout     revoke the presented token → 200
 *   POST /refresh    rotate a still-valid token → 200
 *   GET  /me         who am I? (protected)
 */

const express = require('express');
const store = require('../data/user.store');
const { comparePassword } = require('../security/password');
const token = require('../security/token');
const limiter = require('../security/rate-limit');
const { validateRegister, validateLogin } = require('../validation/auth.validator');
const { requireAuth } = require('../middleware/auth');
const ApiError = require('../errors/api-error');

const router = express.Router();

function expiresInMs(ttl) {
  const match = /^(\d+)([smhd])$/.exec(String(ttl));
  if (!match) return 30 * 60 * 1000;
  const units = { s: 1000, m: 60000, h: 3600000, d: 86400000 };
  return Number(match[1]) * units[match[2]];
}

/* ------------------------------------------------------------------ */
/*  POST /api/auth/register                                            */
/* ------------------------------------------------------------------ */
router.post('/register', async (req, res, next) => {
  try {
    const payload = validateRegister(req.body);

    if (store.findByEmail(payload.email)) {
      throw ApiError.conflict('That email is already registered — try signing in instead.', [
        { field: 'email', problem: 'Already exists in the user store.' }
      ]);
    }

    // note: role is never read from the request — nobody self-assigns "admin"
    const user = await store.create({ ...payload, role: 'user' });
    const signed = token.sign(user);

    res.status(201).json({
      ok: true,
      data: {
        token: signed.token,
        tokenType: 'Bearer',
        expiresIn: signed.expiresIn,
        expiresAt: new Date(Date.now() + expiresInMs(signed.expiresIn)).toISOString(),
        user
      },
      meta: {
        timestamp: new Date().toISOString(),
        message: 'Account created — password stored as a bcrypt hash, never in plain text.'
      }
    });
  } catch (error) {
    next(error);
  }
});

/* ------------------------------------------------------------------ */
/*  POST /api/auth/login                                                */
/* ------------------------------------------------------------------ */
router.post('/login', async (req, res, next) => {
  try {
    const { email, password, remember } = validateLogin(req.body);

    const key = `${email}:${req.ip}`;
    const gate = limiter.check(key);
    if (gate.blocked) {
      const error = new ApiError(
        429,
        'TOO_MANY_ATTEMPTS',
        `Too many failed attempts. Try again in ${gate.retryAfterSeconds} seconds.`,
        [{ field: 'rate-limit', problem: `${limiter.MAX} attempts per ${limiter.WINDOW_MS / 60000} minutes.` }]
      );
      error.retryAfterSeconds = gate.retryAfterSeconds;
      throw error;
    }

    const user = store.findByEmail(email);

    // one message for "unknown email" and "wrong password" on purpose —
    // an attacker learns nothing about which addresses exist
    const ok = user ? await comparePassword(password, user.passwordHash) : false;
    if (!ok) {
      const result = limiter.hit(key);
      const error = new ApiError(
        401,
        'INVALID_CREDENTIALS',
        'Email or password is incorrect.',
        [{ field: 'password', problem: `Attempt ${result.remaining} of ${limiter.MAX} before the lockout.` }]
      );
      error.retryAfterSeconds = result.retryAfterSeconds;
      throw error;
    }

    limiter.reset(key);
    store.markLogin(user.id);
    const signed = token.sign(user, { remember });

    res.json({
      ok: true,
      data: {
        token: signed.token,
        tokenType: 'Bearer',
        expiresIn: signed.expiresIn,
        expiresAt: new Date(Date.now() + expiresInMs(signed.expiresIn)).toISOString(),
        user: store.toPublic(user)
      },
      meta: { timestamp: new Date().toISOString(), message: 'Signature verified. Session opened.' }
    });
  } catch (error) {
    next(error);
  }
});

/* ------------------------------------------------------------------ */
/*  GET /api/auth/me  (protected)                                      */
/* ------------------------------------------------------------------ */
router.get('/me', requireAuth, (req, res, next) => {
  try {
    const user = store.findById(req.auth.sub);
    if (!user) throw ApiError.notFound('The account behind this token no longer exists.');

    res.json({
      ok: true,
      data: {
        user: store.toPublic(user),
        claims: {
          sub: req.auth.sub,
          email: req.auth.email,
          role: req.auth.role,
          iss: req.auth.iss,
          aud: req.auth.aud,
          iat: new Date(req.auth.iat * 1000).toISOString(),
          exp: new Date(req.auth.exp * 1000).toISOString()
        }
      },
      meta: { timestamp: new Date().toISOString(), protected: true }
    });
  } catch (error) {
    next(error);
  }
});

/* ------------------------------------------------------------------ */
/*  POST /api/auth/refresh  (protected)                                */
/* ------------------------------------------------------------------ */
router.post('/refresh', requireAuth, (req, res, next) => {
  try {
    const user = store.findById(req.auth.sub);
    if (!user) throw ApiError.notFound('The account behind this token no longer exists.');

    const signed = token.sign(user);

    res.json({
      ok: true,
      data: {
        token: signed.token,
        tokenType: 'Bearer',
        expiresIn: signed.expiresIn,
        expiresAt: new Date(Date.now() + expiresInMs(signed.expiresIn)).toISOString()
      },
      meta: { timestamp: new Date().toISOString(), message: 'Rotated. The old token stays valid until it expires.' }
    });
  } catch (error) {
    next(error);
  }
});

/* ------------------------------------------------------------------ */
/*  POST /api/auth/logout  (protected)                                 */
/* ------------------------------------------------------------------ */
router.post('/logout', requireAuth, (req, res, next) => {
  try {
    token.revoke(req.auth.token, req.auth);

    res.json({
      ok: true,
      data: { revoked: true, subject: req.auth.sub },
      meta: {
        timestamp: new Date().toISOString(),
        message: 'Token added to the denylist — it will be refused until its own expiry.'
      }
    });
  } catch (error) {
    next(error);
  }
});

/* ------------------------------------------------------------------ */
/*  GET /api/auth/inspect?token=…  (read-only decoder, no secret)      */
/* ------------------------------------------------------------------ */
router.get('/inspect', (req, res) => {
  const raw = String(req.query.token || '');
  const parts = raw.split('.');

  res.json({
    ok: true,
    data: {
      structure: { segments: parts.length, expected: 3, wellFormed: parts.length === 3 },
      ...(parts.length === 3 ? token.inspect(raw) : {}),
      note: 'A JWT is only base64 — anyone can read the claims. The signature is what stops them from editing them.'
    },
    meta: { timestamp: new Date().toISOString() }
  });
});

module.exports = router;
