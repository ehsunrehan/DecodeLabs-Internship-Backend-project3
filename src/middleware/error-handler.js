module.exports = function errorHandler(error, req, res, _next) {
  const isBadJson = error instanceof SyntaxError && typeof error.status === 'number';
  const status = isBadJson ? 400 : error.status || error.statusCode || 500;

  let code = error.code || 'INTERNAL_ERROR';
  let message = error.message;

  if (isBadJson) {
    code = 'MALFORMED_JSON';
    message = 'Request body is not valid JSON.';
  } else if (status === 500) {
    code = 'INTERNAL_ERROR';
    message = 'Unexpected server error.';
    console.error('[500]', error);
  }

  res.status(status).json({
    ok: false,
    error: {
      code,
      message,
      ...(error.details ? { details: error.details } : {}),
      ...(error.retryAfterSeconds ? { retryAfterSeconds: error.retryAfterSeconds } : {})
    },
    meta: { timestamp: new Date().toISOString(), method: req.method, path: req.originalUrl }
  });
};
