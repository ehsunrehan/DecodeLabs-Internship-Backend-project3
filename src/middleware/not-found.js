module.exports = function notFound(req, res) {
  res.status(404).json({
    ok: false,
    error: {
      code: 'NOT_FOUND',
      message: `No route matches ${req.method} ${req.originalUrl}.`,
      hint: 'POST /api/auth/register · POST /api/auth/login · GET /api/vault/profile'
    },
    meta: { timestamp: new Date().toISOString(), method: req.method, path: req.originalUrl }
  });
};
