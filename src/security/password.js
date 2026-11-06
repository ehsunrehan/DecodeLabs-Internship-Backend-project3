/**
 * Password rules + bcrypt wrappers.
 * The strength rules are checked BEFORE hashing so a weak password
 * never reaches the store, and hashing always uses a per-user salt.
 */

const bcrypt = require('bcryptjs');

const ROUNDS = Number(process.env.BCRYPT_ROUNDS) || 10;

const COMMON = ['password', '12345678', 'qwerty123', 'decodelabs', 'letmein', 'iloveyou', 'welcome1'];

function strengthIssues(password) {
  const issues = [];
  const value = String(password || '');

  if (value.length < 8) issues.push('At least 8 characters.');
  if (!/[a-z]/.test(value)) issues.push('One lowercase letter.');
  if (!/[A-Z]/.test(value)) issues.push('One uppercase letter.');
  if (!/[0-9]/.test(value)) issues.push('One digit.');
  if (!/[^A-Za-z0-9]/.test(value)) issues.push('One symbol (!@#…).');
  if (COMMON.includes(value.toLowerCase())) issues.push('This password is far too common.');

  return issues;
}

function score(password) {
  const value = String(password || '');
  let points = 0;
  if (value.length >= 8) points += 25;
  if (value.length >= 12) points += 15;
  if (value.length >= 16) points += 10;
  if (/[a-z]/.test(value) && /[A-Z]/.test(value)) points += 15;
  if (/[0-9]/.test(value)) points += 10;
  if (/[^A-Za-z0-9]/.test(value)) points += 15;
  if (COMMON.includes(value.toLowerCase())) points = 5;
  return Math.min(100, points);
}

async function hashPassword(plain) {
  return bcrypt.hash(String(plain), ROUNDS);
}

async function comparePassword(plain, hash) {
  return bcrypt.compare(String(plain), hash);
}

module.exports = { hashPassword, comparePassword, strengthIssues, score, ROUNDS };
