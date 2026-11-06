module.exports = function requestLog(req, res, next) {
  const startedAt = process.hrtime.bigint();
  res.on('finish', () => {
    const ms = Number(process.hrtime.bigint() - startedAt) / 1e6;
    const code = res.statusCode;
    const mark = code >= 500 ? '✗' : code >= 400 ? '!' : '✓';
    console.log(
      `${new Date().toISOString().slice(11, 23)} ${mark} ${req.method.padEnd(6)}${req.originalUrl.padEnd(40)}${code}  ${ms.toFixed(1)} ms`
    );
  });
  next();
};
