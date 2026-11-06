/**
 * File-backed user store for Project 3.
 *
 * Deliberately simple: an authentication system should be readable at
 * a glance. Passwords are NEVER written in plain text — only bcrypt
 * hashes produced by src/security/password.js.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { hashPassword } = require('../security/password');

const FILE = path.join(__dirname, '..', '..', 'data', 'users.json');

let users = [];

function read() {
  try {
    if (fs.existsSync(FILE)) {
      users = JSON.parse(fs.readFileSync(FILE, 'utf8'));
      return;
    }
  } catch (error) {
    console.error('[store] users.json could not be parsed, starting fresh:', error.message);
  }
  users = [];
}

function write() {
  fs.mkdirSync(path.dirname(FILE), { recursive: true });
  const tmp = `${FILE}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(users, null, 2), 'utf8');
  fs.renameSync(tmp, FILE);
}

function toPublic(user) {
  const { passwordHash, ...safe } = user;
  return safe;
}

const findByEmail = (email) =>
  users.find((u) => u.email === String(email || '').trim().toLowerCase()) || null;

const findById = (id) => users.find((u) => u.id === id) || null;

async function create({ name, email, password, role = 'user' }) {
  const now = new Date().toISOString();
  const user = {
    id: `usr_${crypto.randomBytes(6).toString('hex')}`,
    name: String(name).trim(),
    email: String(email).trim().toLowerCase(),
    passwordHash: await hashPassword(password),
    role,
    passwordChangedAt: now,
    lastLoginAt: null,
    createdAt: now
  };
  users.push(user);
  write();
  return toPublic(user);
}

function markLogin(id) {
  const user = findById(id);
  if (!user) return;
  user.lastLoginAt = new Date().toISOString();
  write();
}

async function changePassword(id, newPassword) {
  const user = findById(id);
  if (!user) return null;
  user.passwordHash = await hashPassword(newPassword);
  user.passwordChangedAt = new Date().toISOString();
  write();
  return toPublic(user);
}

function all() {
  return users.map(toPublic);
}

/**
 * Two accounts on first run so the interface is never empty:
 * an administrator and a regular member of the batch.
 */
async function ensureSeed() {
  read();
  if (users.length) return;

  await create({
    name: 'Aarav Mehta',
    email: 'admin@decodelabs.tech',
    password: 'Decode@2026',
    role: 'admin'
  });

  await create({
    name: 'Ishita Raghavan',
    email: 'user@decodelabs.tech',
    password: 'Batch@2026',
    role: 'user'
  });

  console.log('  ✓ Seeded data/users.json with an admin and a user account.');
}

module.exports = { ensureSeed, findByEmail, findById, create, markLogin, changePassword, all, toPublic };
