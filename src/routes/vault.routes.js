/**
 * /api/vault — the routes a bare visitor cannot open.
 *
 *   GET /guard        protected — the demonstration route
 *   GET /profile      protected — the caller's own account + claims
 *   GET /notes        protected — sample records behind the token
 *   GET /admin        protected AND role=admin → 403 for everyone else
 */

const express = require('express');
const store = require('../data/user.store');
const { requireAuth, requireRole } = require('../middleware/auth');
const ApiError = require('../errors/api-error');

const router = express.Router();

const NOTES = [
  {
    id: 'note_01',
    title: 'Signing key rotation',
    body: 'The HS256 secret in .env is rotated every quarter; tokens signed with the old key are refused, not merged.',
    clearance: 'member'
  },
  {
    id: 'note_02',
    title: 'Password storage rule',
    body: 'bcrypt with a per-user salt. The plain password never touches the file store, the log, or the response body.',
    clearance: 'member'
  },
  {
    id: 'note_03',
    title: 'Perimeter audit — batch 2026',
    body: 'Protected routes answered 401 for 100% of anonymous calls during the November drill.',
    clearance: 'admin'
  }
];

/* protected demonstration route -------------------------------------- */
router.get('/guard', requireAuth, (req, res) => {
  res.json({
    ok: true,
    data: {
      message: 'Perimeter crossed. This payload only exists behind a valid signature.',
      reachedAt: new Date().toISOString(),
      presentedBy: { id: req.auth.sub, email: req.auth.email, role: req.auth.role },
      expiresInMinutes: Math.max(0, Math.round((req.auth.exp * 1000 - Date.now()) / 60000))
    },
    meta: { timestamp: new Date().toISOString(), protected: true }
  });
});

/* the caller's own profile -------------------------------------------- */
router.get('/profile', requireAuth, (req, res, next) => {
  try {
    const user = store.findById(req.auth.sub);
    if (!user) throw ApiError.notFound('The account behind this token no longer exists.');

    res.json({
      ok: true,
      data: {
        user: store.toPublic(user),
        session: {
          subject: req.auth.sub,
          role: req.auth.role,
          issuedAt: new Date(req.auth.iat * 1000).toISOString(),
          expiresAt: new Date(req.auth.exp * 1000).toISOString(),
          secondsLeft: Math.max(0, Math.round(req.auth.exp - Date.now() / 1000)),
          revoked: false
        }
      },
      meta: { timestamp: new Date().toISOString(), protected: true }
    });
  } catch (error) {
    next(error);
  }
});

/* sample records that need a token ------------------------------------ */
router.get('/notes', requireAuth, (req, res) => {
  const visible =
    req.auth.role === 'admin' ? NOTES : NOTES.filter((note) => note.clearance === 'member');

  res.json({
    ok: true,
    data: {
      items: visible,
      hidden: NOTES.length - visible.length,
      viewerRole: req.auth.role
    },
    meta: { timestamp: new Date().toISOString(), protected: true }
  });
});

/* admin only ------------------------------------------------------------ */
router.get('/admin', requireAuth, requireRole('admin'), (req, res) => {
  const accounts = store.all();

  res.json({
    ok: true,
    data: {
      message: 'Administrator corridor.',
      accounts: accounts.map((user) => ({
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
        lastLoginAt: user.lastLoginAt,
        passwordChangedAt: user.passwordChangedAt
      })),
      security: {
        hashing: `bcrypt · ${Number(process.env.BCRYPT_ROUNDS) || 10} rounds`,
        algorithm: 'HS256',
        tokenTtl: process.env.JWT_EXPIRES_IN || '30m',
        storedSecrets: 'password hashes only — plain passwords are never written'
      }
    },
    meta: { timestamp: new Date().toISOString(), protected: true, role: 'admin' }
  });
});

module.exports = router;
