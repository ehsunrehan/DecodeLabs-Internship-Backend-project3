/**
 * The two guards that make a route "protected":
 *
 *   requireAuth   → 401 unless a valid Bearer token is presented
 *   requireRole() → 403 when the token is valid but lacks the role
 */

const { verify } = require('../security/token');
const ApiError = require('../errors/api-error');

function bearerFrom(req) {
  const header = req.headers.authorization || '';
  if (!header) return null;
  const [scheme, value] = header.split(' ');
  if (!scheme || scheme.toLowerCase() !== 'bearer' || !value) return null;
  return value.trim();
}

function requireAuth(req, _res, next) {
  const token = bearerFrom(req);

  if (!token) {
    return next(
      new ApiError(401, 'MISSING_TOKEN', 'This route needs a Bearer token in the Authorization header.', [
        { field: 'Authorization', problem: 'Expected: Authorization: Bearer <token>' }
      ])
    );
  }

  const result = verify(token);
  if (!result.valid) {
    const messages = {
      TOKEN_EXPIRED: 'The token has expired — sign in again.',
      TOKEN_REVOKED: 'This token was revoked by a logout call.',
      TOKEN_INVALID: 'The signature could not be verified.'
    };
    return next(new ApiError(401, result.reason, messages[result.reason] || 'Invalid token.'));
  }

  req.auth = { token, ...result.payload };
  next();
}

function requireRole(role) {
  return (req, _res, next) => {
    if (!req.auth) return next(new ApiError(401, 'MISSING_TOKEN', 'Authenticate first.'));
    if (req.auth.role !== role) {
      return next(
        new ApiError(403, 'INSUFFICIENT_ROLE', `Role "${req.auth.role}" may not enter — "${role}" required.`, [
          { field: 'role', problem: `Token carries role=${req.auth.role}, route demands role=${role}.` }
        ])
      );
    }
    next();
  };
}

module.exports = { requireAuth, requireRole, bearerFrom };
