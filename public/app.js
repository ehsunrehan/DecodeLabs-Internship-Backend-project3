/* =============================================================
   DecodeLabs · Project 03 — Secure Authentication System
   Perimeter interface: issues tokens, decodes them, and calls
   protected routes with and without them.
   ============================================================= */

const store = {
  token: sessionStorage.getItem('dl_p3_token') || '',
  user: JSON.parse(sessionStorage.getItem('dl_p3_user') || 'null'),
  expiresAt: sessionStorage.getItem('dl_p3_exp') || '',
  mode: 'login'
};

/* ── helpers ───────────────────────────────────────────── */

const $ = (s) => document.querySelector(s);

function escapeHtml(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function toast(message) {
  const el = $('#toast');
  el.textContent = message;
  el.classList.add('is-visible');
  clearTimeout(el._t);
  el._t = setTimeout(() => el.classList.remove('is-visible'), 2600);
}

function colorJson(text) {
  return escapeHtml(text).replace(
    /("(?:\\.|[^"\\])*")(\s*:)?|(-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)|\b(true|false)\b|\b(null)\b|([{}\[\],])/g,
    (m, str, colon, num, bool, nul, punc) => {
      if (str) return colon ? `<span class="j-key">${str}</span><span class="j-dot">${colon}</span>` : `<span class="j-str">${str}</span>`;
      if (num) return `<span class="j-num">${num}</span>`;
      if (bool) return `<span class="j-bool">${bool}</span>`;
      if (nul) return `<span class="j-null">${nul}</span>`;
      if (punc) return `<span class="j-dot">${punc}</span>`;
      return m;
    }
  );
}

async function call(path, { method = 'GET', body, naked = false } = {}) {
  const headers = {};
  if (body) headers['Content-Type'] = 'application/json';
  if (!naked && store.token) headers.Authorization = `Bearer ${store.token}`;

  const started = performance.now();
  const response = await fetch(path, { method, headers, body: body ? JSON.stringify(body) : undefined });
  const raw = await response.text();
  const ms = (performance.now() - started).toFixed(0);

  let parsed = null;
  try {
    parsed = JSON.parse(raw);
  } catch (_) {
    /* keep raw */
  }

  return { status: response.status, raw, parsed, ms };
}

/* ── server lamp ───────────────────────────────────────── */

async function probe() {
  try {
    const res = await fetch('/api/vault/guard');
    $('#lamp').className = res.status === 401 || res.status === 200 ? 'lamp is-up' : 'lamp is-down';
    $('#serverState').textContent = res.status === 401 ? 'server up · perimeter closed' : 'server up';
    return true;
  } catch (_) {
    $('#lamp').className = 'lamp is-down';
    $('#serverState').textContent = 'server unreachable';
    return false;
  }
}

/* ── session ───────────────────────────────────────────── */

function persist() {
  if (store.token) {
    sessionStorage.setItem('dl_p3_token', store.token);
    sessionStorage.setItem('dl_p3_user', JSON.stringify(store.user));
    sessionStorage.setItem('dl_p3_exp', store.expiresAt);
  } else {
    sessionStorage.removeItem('dl_p3_token');
    sessionStorage.removeItem('dl_p3_user');
    sessionStorage.removeItem('dl_p3_exp');
  }
}

function paintToken() {
  const out = $('#tokenOut');
  const copy = $('#btnCopyToken');
  const clear = $('#btnClearToken');
  const zoneTag = $('#zoneTag');
  const sessionBar = $('#sessionBar');

  if (!store.token) {
    out.innerHTML = '<span class="token__empty">No token issued yet.<br />Sign in to open the perimeter.</span>';
    copy.disabled = true;
    clear.disabled = true;
    zoneTag.textContent = 'no token';
    zoneTag.className = 'panel__tag';
    sessionBar.hidden = true;
    $('#identityTag').textContent = 'signed out';
    $('#identityTag').className = 'panel__tag';
    $('#expiryRow').hidden = true;
    renderClaims(null);
    setCallsEnabled(false);
    return;
  }

  const [head, payload, sig] = store.token.split('.');
  out.innerHTML =
    `<span class="t-head">${head}</span><span class="t-dot">.</span>` +
    `<span class="t-payload">${payload}</span><span class="t-dot">.</span>` +
    `<span class="t-sig">${sig}</span>`;

  copy.disabled = false;
  clear.disabled = false;
  zoneTag.textContent = 'token held';
  zoneTag.className = 'panel__tag is-live';
  sessionBar.hidden = false;

  $('#identityTag').textContent = 'signed in';
  $('#identityTag').className = 'panel__tag is-live';
  $('#expiryRow').hidden = false;

  const roleChip = $('#roleChip');
  roleChip.textContent = store.user?.role || 'user';
  roleChip.className = 'rolechip' + (store.user?.role === 'admin' ? ' is-admin' : '');
  $('#whoAmI').textContent = store.user ? `${store.user.email} · ${store.user.name}` : '—';

  renderClaims(decodePayload(store.token));
  setCallsEnabled(true);
  tickExpiry();
}

function decodePayload(token) {
  try {
    const segment = token.split('.')[1];
    return JSON.parse(atob(segment.replace(/-/g, '+').replace(/_/g, '/')));
  } catch (_) {
    return null;
  }
}

function renderClaims(claims) {
  const table = $('#claimsTable tbody');
  if (!claims) {
    table.innerHTML = '<tr class="is-empty"><td>—</td><td>claims appear after sign-in</td></tr>';
    return;
  }

  const rows = [
    ['sub', claims.sub],
    ['email', claims.email],
    ['name', claims.name],
    ['role', claims.role],
    ['iss', claims.iss],
    ['aud', claims.aud],
    ['iat', claims.iat ? new Date(claims.iat * 1000).toLocaleTimeString('en-GB') : '—'],
    ['exp', claims.exp ? new Date(claims.exp * 1000).toLocaleTimeString('en-GB') : '—']
  ];

  table.innerHTML = rows
    .map(
      ([key, value]) =>
        `<tr><td>${escapeHtml(key)}</td><td class="${key === 'role' ? 'v-role' : ''}">${escapeHtml(value)}</td></tr>`
    )
    .join('');
}

let expiryTimer = null;

function tickExpiry() {
  clearInterval(expiryTimer);

  const fill = $('#expiryFill');
  const text = $('#expiryText');

  const update = () => {
    if (!store.expiresAt) return;
    const exp = new Date(store.expiresAt).getTime();
    const claims = decodePayload(store.token);
    const issued = claims && claims.iat ? claims.iat * 1000 : exp - 30 * 60 * 1000;
    const total = Math.max(1, exp - issued);
    const left = Math.max(0, exp - Date.now());
    const ratio = (left / total) * 100;

    fill.style.width = `${ratio}%`;
    fill.className = ratio < 15 ? 'is-danger' : ratio < 45 ? 'is-warn' : '';

    if (left <= 0) {
      text.textContent = 'expired';
      clearInterval(expiryTimer);
      return;
    }

    const minutes = Math.floor(left / 60000);
    const seconds = Math.floor((left % 60000) / 1000);
    text.textContent = `${minutes}m ${String(seconds).padStart(2, '0')}s left`;
  };

  update();
  expiryTimer = setInterval(update, 1000);
}

function setCallsEnabled(on) {
  document.querySelectorAll('.call:not([data-naked])').forEach((button) => {
    button.disabled = !on;
  });
}

function openSession({ token, user, expiresAt }) {
  store.token = token;
  store.user = user;
  store.expiresAt = expiresAt;
  persist();
  paintToken();
}

function endSession(message) {
  store.token = '';
  store.user = null;
  store.expiresAt = '';
  persist();
  paintToken();
  if (message) toast(message);
}

/* ── tabs + form ───────────────────────────────────────── */

function setMode(mode) {
  store.mode = mode;
  const isRegister = mode === 'register';

  $('#tabLogin').classList.toggle('is-active', !isRegister);
  $('#tabRegister').classList.toggle('is-active', isRegister);
  $('#fieldName').hidden = !isRegister;
  $('#strength').hidden = !isRegister;
  $('#rememberRow').hidden = isRegister;
  $('#btnAuth').textContent = isRegister ? 'Create account' : 'Sign in';
  $('#alert').hidden = true;
  authForm.password.autocomplete = isRegister ? 'new-password' : 'current-password';
}

$('#tabLogin').addEventListener('click', () => setMode('login'));
$('#tabRegister').addEventListener('click', () => setMode('register'));

$('#btnPeek').addEventListener('click', (event) => {
  const input = authForm.password;
  const showing = input.type === 'text';
  input.type = showing ? 'password' : 'text';
  event.currentTarget.textContent = showing ? 'show' : 'hide';
});

/* password strength (mirrors the server rules) ---------------- */
const RULES = [
  { label: '8+ chars', test: (v) => v.length >= 8 },
  { label: 'A-Z', test: (v) => /[A-Z]/.test(v) },
  { label: 'a-z', test: (v) => /[a-z]/.test(v) },
  { label: '0-9', test: (v) => /[0-9]/.test(v) },
  { label: 'symbol', test: (v) => /[^A-Za-z0-9]/.test(v) }
];

function paintStrength() {
  const value = authForm.password.value;
  let met = 0;
  RULES.forEach((rule) => {
    if (rule.test(value)) met += 1;
  });

  const extra = value.length >= 12 ? 12 : value.length >= 10 ? 8 : 0;
  const percent = value ? Math.min(100, Math.round((met / RULES.length) * 88 + extra)) : 0;

  $('#strengthFill').style.width = `${percent}%`;
  $('#strengthFill').style.background =
    percent < 40 ? 'var(--red)' : percent < 75 ? 'var(--gold)' : 'var(--mint)';
  $('#strengthScore').textContent = `${percent}%`;
  $('#strengthWord').textContent =
    percent < 40 ? 'too weak' : percent < 65 ? 'acceptable' : percent < 90 ? 'strong' : 'excellent';

  $('#strengthRules').innerHTML = RULES.map(
    (rule) => `<li class="${rule.test(value) ? 'is-met' : ''}">${rule.label}</li>`
  ).join('');
}

authForm.password.addEventListener('input', () => {
  if (store.mode === 'register') paintStrength();
});

/* demo rows --------------------------------------------------- */
document.querySelectorAll('.demo__row').forEach((row) => {
  row.addEventListener('click', () => {
    setMode('login');
    authForm.email.value = row.dataset.email;
    authForm.password.value = row.dataset.pass;
    authForm.password.type = 'password';
    $('#btnPeek').textContent = 'show';
    $('#alert').hidden = true;
    toast('Credentials filled — press Sign in');
  });
});

/* submit ------------------------------------------------------ */
function showAlert(message, kind = 'is-error', list = []) {
  const alert = $('#alert');
  alert.className = `alert ${kind}`;
  alert.innerHTML =
    escapeHtml(message) + (list.length ? `<ul>${list.map((item) => `<li>${escapeHtml(item)}</li>`).join('')}</ul>` : '');
  alert.hidden = false;
}

$('#authForm').addEventListener('submit', async (event) => {
  event.preventDefault();
  $('#alert').hidden = true;

  const isRegister = store.mode === 'register';
  const payload = {
    email: authForm.email.value.trim(),
    password: authForm.password.value
  };
  if (isRegister) payload.name = authForm.name.value.trim();
  if (!isRegister) payload.remember = authForm.remember.checked;

  const button = $('#btnAuth');
  button.disabled = true;
  button.textContent = isRegister ? 'Hashing…' : 'Verifying…';

  const result = await call(isRegister ? '/api/auth/register' : '/api/auth/login', {
    method: 'POST',
    body: payload
  });

  button.disabled = false;
  button.textContent = isRegister ? 'Create account' : 'Sign in';

  if (result.status >= 200 && result.status < 300) {
    openSession({
      token: result.parsed.data.token,
      user: result.parsed.data.user,
      expiresAt: result.parsed.data.expiresAt
    });
    authForm.password.value = '';
    showAlert(isRegister ? 'Account created. Password stored as a bcrypt hash.' : 'Signed in. Token issued.', 'is-ok');
    toast(isRegister ? 'Account created — token issued' : `Welcome back, ${result.parsed.data.user.name}`);
    log('POST', isRegister ? '/api/auth/register' : '/api/auth/login', result.status, result.ms);
    return;
  }

  const error = result.parsed?.error || { message: 'Request failed.', details: [] };
  showAlert(error.message, 'is-error', (error.details || []).map((d) => `${d.field}: ${d.problem}`));
  log('POST', isRegister ? '/api/auth/register' : '/api/auth/login', result.status, result.ms);
});

/* ── protected calls ───────────────────────────────────── */

document.querySelectorAll('.call').forEach((button) => {
  button.addEventListener('click', async () => {
    const naked = button.dataset.naked === '1';
    button.disabled = true;

    const result = await call(button.dataset.url, { naked });

    button.disabled = false;
    if (naked) button.disabled = false;

    const out = $('#response');
    out.innerHTML = colorJson(result.raw || '(empty response)');
    out.className =
      'response ' + (result.status < 300 ? 'is-ok' : result.status < 500 ? 'is-warn' : 'is-bad');

    log('GET', button.dataset.url, result.status, result.ms);

    if (result.status === 401 && !naked && store.token) {
      endSession('Token rejected — session closed');
      showAlert('The server refused the token. It may have expired or been revoked.', 'is-error');
    }
  });
});

/* ── request log ───────────────────────────────────────── */

const logEntries = [];

function log(method, path, status, ms) {
  logEntries.unshift({
    time: new Date().toLocaleTimeString('en-GB'),
    method,
    path,
    status,
    ms
  });
  if (logEntries.length > 30) logEntries.pop();
  paintLog();
}

function paintLog() {
  const list = $('#logList');
  if (!logEntries.length) {
    list.innerHTML = '<li class="log__empty">Nothing called yet.</li>';
    return;
  }

  list.innerHTML = logEntries
    .map((entry) => {
      const cls = entry.status < 300 ? 'ok' : entry.status < 500 ? 'warn' : 'bad';
      return `<li>
        <span class="log__time">${entry.time}</span>
        <span class="log__method">${entry.method}</span>
        <span>${escapeHtml(entry.path)}</span>
        <span class="log__code ${cls}">${entry.status} · ${entry.ms} ms</span>
      </li>`;
    })
    .join('');
}

$('#btnClearLog').addEventListener('click', () => {
  logEntries.length = 0;
  paintLog();
});

/* ── toolbar ───────────────────────────────────────────── */

$('#btnCopyToken').addEventListener('click', async () => {
  try {
    await navigator.clipboard.writeText(store.token);
    toast('Token copied to clipboard');
  } catch (_) {
    toast('Clipboard blocked by the browser');
  }
});

$('#btnClearToken').addEventListener('click', () => {
  endSession('Local token discarded (server still trusts it until expiry)');
});

$('#btnLogout').addEventListener('click', async () => {
  if (!store.token) return;
  const result = await call('/api/auth/logout', { method: 'POST' });
  endSession(result.status === 200 ? 'Signed out — token revoked on the server' : 'Local session closed');
  showAlert('Token revoked: the server will refuse it from now on.', 'is-ok');
});

/* ── boot ───────────────────────────────────────────────── */

paintToken();
setMode('login');
probe();
setInterval(probe, 20000);

(async () => {
  if (!store.token) return;
  const result = await call('/api/auth/me');
  if (result.status === 200) {
    store.user = result.parsed.data.user;
    persist();
    paintToken();
    log('GET', '/api/auth/me', result.status, result.ms);
  } else {
    endSession();
  }
})();
