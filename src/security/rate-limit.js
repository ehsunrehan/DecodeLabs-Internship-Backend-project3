/**
 * Login attempt limiter — protects against password guessing.
 * Eight failed attempts per e-mail inside a 10-minute window → 429.
 * A successful sign-in clears the counter immediately.
 */

const MAX = Number(process.env.LOGIN_MAX_ATTEMPTS) || 8;
const WINDOW_MS = Number(process.env.LOGIN_WINDOW_MS) || 10 * 60 * 1000;

const attempts = new Map(); // key → { count, resetAt }

function sweep() {
  const now = Date.now();
  attempts.forEach((entry, key) => {
    if (entry.resetAt <= now) attempts.delete(key);
  });
}

function check(key) {
  sweep();
  const entry = attempts.get(key);
  if (!entry) return { blocked: false, remaining: MAX };
  return {
    blocked: entry.count >= MAX,
    remaining: Math.max(0, MAX - entry.count),
    retryAfterSeconds: Math.ceil((entry.resetAt - Date.now()) / 1000)
  };
}

function hit(key) {
  const now = Date.now();
  const entry = attempts.get(key) || { count: 0, resetAt: now + WINDOW_MS };
  entry.count += 1;
  if (entry.resetAt <= now) entry.resetAt = now + WINDOW_MS;
  attempts.set(key, entry);
  return {
    blocked: entry.count >= MAX,
    remaining: Math.max(0, MAX - entry.count),
    retryAfterSeconds: Math.ceil((entry.resetAt - now) / 1000)
  };
}

function reset(key) {
  attempts.delete(key);
}

module.exports = { check, hit, reset, MAX, WINDOW_MS };
