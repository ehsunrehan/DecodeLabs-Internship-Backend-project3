const ApiError = require('../errors/api-error');
const { strengthIssues } = require('../security/password');

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function assertObject(body) {
  if (!isPlainObject(body)) {
    throw ApiError.badRequest('Request body must be a JSON object.', [
      { field: 'body', problem: `Expected an object, received ${body === null ? 'null' : typeof body}.` }
    ]);
  }
}

function validateRegister(body) {
  assertObject(body);
  const details = [];
  const out = {};

  const name = typeof body.name === 'string' ? body.name.trim() : '';
  if (!name) details.push({ field: 'name', problem: 'Required — how should we address you?' });
  else if (name.length < 2) details.push({ field: 'name', problem: 'Too short — minimum 2 characters.' });
  else if (name.length > 80) details.push({ field: 'name', problem: 'Too long — maximum 80 characters.' });
  else out.name = name;

  const email = typeof body.email === 'string' ? body.email.trim().toLowerCase() : '';
  if (!email) details.push({ field: 'email', problem: 'Required.' });
  else if (!EMAIL_RE.test(email)) details.push({ field: 'email', problem: `"${email}" is not a valid address.` });
  else out.email = email;

  const password = typeof body.password === 'string' ? body.password : '';
  const issues = strengthIssues(password);
  if (issues.length) {
    details.push({
      field: 'password',
      problem: `Choose a stronger password — still missing: ${issues.join(' ')}`
    });
  } else {
    out.password = password;
  }

  if (Object.keys(body).some((key) => !['name', 'email', 'password'].includes(key))) {
    details.push({
      field: Object.keys(body).filter((key) => !['name', 'email', 'password'].includes(key)).join(', '),
      problem: 'Unknown field(s). Registration accepts: name, email, password.'
    });
  }

  if (details.length) throw ApiError.badRequest('Registration did not pass validation.', details);
  return out;
}

function validateLogin(body) {
  assertObject(body);
  const details = [];

  const email = typeof body.email === 'string' ? body.email.trim().toLowerCase() : '';
  const password = typeof body.password === 'string' ? body.password : '';

  if (!email) details.push({ field: 'email', problem: 'Required.' });
  if (!password) details.push({ field: 'password', problem: 'Required.' });

  if (details.length) throw ApiError.badRequest('Sign-in needs both fields.', details);

  return { email, password, remember: Boolean(body.remember) };
}

module.exports = { validateRegister, validateLogin };
