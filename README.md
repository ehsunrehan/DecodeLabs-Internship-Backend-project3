# Project 03 — Secure Authentication System

**DecodeLabs · Industrial Training Kit · Batch 2026 · Backend Development**

> **Goal:** Protect your API routes using modern security standards.
> **Key requirements:** hash user passwords before saving · generate a JWT on login · create a "protected route" that requires a token.
> **Key skills:** cryptography basics, JWT, middleware logic.

---

## 1. What is in here

A complete authentication flow: registration and sign-in with **bcrypt** hashing, **JSON Web Tokens** signed with HS256, and middleware guards that answer `401` for anonymous callers and `403` for wrong roles. Users are stored in `data/users.json` — password **hashes only**.

| PDF requirement | Where it lives |
| --- | --- |
| Hash passwords before saving | `src/security/password.js` (bcrypt, 10 rounds, per-user salt) |
| Generate a JWT on login | `POST /api/auth/login` → `src/security/token.js` |
| Protected route requiring a token | `GET /api/vault/guard` + `src/middleware/auth.js` (`requireAuth`) |
| *(suggested in the PDF)* role-based access | `GET /api/vault/admin` + `requireRole('admin')` → `403` for users |
| *(suggested in the PDF)* token expiration | 30 min default, `7d` with "remember me" |

**Additions (they strengthen the project, nothing is broken by them):**

- **Token denylist on logout** — a revoked token is refused before its expiry
- **Token rotation** — `POST /api/auth/refresh`
- **Login rate limiting** — 8 failed attempts per e-mail / IP per 10 minutes → `429`
- **Password strength rules** checked *before* hashing, with a matching meter in the UI
- **Identical failure message** for unknown e-mail and wrong password (no account enumeration)
- `GET /api/auth/inspect?token=…` — read-only decoder for the three JWT segments
- Admin-only corridor listing accounts + the active security settings
- Seeded demo accounts so the interface works on the very first run

---

## 2. Requirements

- **Node.js 18+**
- No database — the store is a JSON file (`data/users.json`, created on first run)
- Dependencies: `express`, `bcryptjs`, `jsonwebtoken` (installed by `npm install`)

## 3. Execute it

Open a terminal in **this folder** (`Project3-Secure-Authentication-System`).

```bash
# 1) install dependencies (first time only)
npm install

# 2) start the server
npm start
```

Expected output:

```
DecodeLabs · Project 3 · Secure Authentication System
Server    : http://localhost:5103
Protected : http://localhost:5103/api/vault/profile
Token TTL : 30m
✓ Seeded data/users.json with an admin and a user account.
```

**Open the interface:** <http://localhost:5103>

Stop with `Ctrl + C`.

### Demo accounts (seeded automatically)

| Role | Email | Password |
| --- | --- | --- |
| admin | `admin@decodelabs.tech` | `Decode@2026` |
| user | `user@decodelabs.tech` | `Batch@2026` |

Click a demo row in the UI to fill the form.

### Configuration (`.env`)

| Key | Default | Meaning |
| --- | --- | --- |
| `PORT` | `5103` | HTTP port |
| `JWT_SECRET` | dev value | **change this** before any real deployment |
| `JWT_EXPIRES_IN` | `30m` | access-token lifetime |
| `BCRYPT_ROUNDS` | `10` | hashing cost |
| `LOGIN_MAX_ATTEMPTS` | `8` | failures allowed per window |
| `LOGIN_WINDOW_MS` | `600000` | lockout window (10 min) |

To reset the user store: stop the server and delete `data/users.json` — it re-seeds on the next boot.

---

## 4. Routes

| Method | Path | Guard | Purpose |
| --- | --- | --- | --- |
| `POST` | `/api/auth/register` | — | create account → `201` + token (role is forced to `user`) |
| `POST` | `/api/auth/login` | rate limit | verify hash → token → `200` |
| `POST` | `/api/auth/logout` | token | revoke the presented token → `200` |
| `POST` | `/api/auth/refresh` | token | rotate the token → `200` |
| `GET` | `/api/auth/me` | token | current user + full claim set |
| `GET` | `/api/auth/inspect` | — | decode a token without verifying it |
| `GET` | `/api/vault/guard` | token | the demonstration route |
| `GET` | `/api/vault/profile` | token | own account + session countdown |
| `GET` | `/api/vault/notes` | token | sample records, filtered by role |
| `GET` | `/api/vault/admin` | token + **admin** | accounts + security summary |

### Examples

```bash
# register
curl -X POST -H "Content-Type: application/json" \
     -d '{"name":"Kabir Sethi","email":"kabir@example.com","password":"Str0ng!Pass"}' \
     http://localhost:5103/api/auth/register

# sign in (replace with your own credentials)
curl -X POST -H "Content-Type: application/json" \
     -d '{"email":"user@decodelabs.tech","password":"Batch@2026"}' \
     http://localhost:5103/api/auth/login

# call a protected route
curl -H "Authorization: Bearer <token>" http://localhost:5103/api/vault/guard

# same route with no token → 401 MISSING_TOKEN
curl http://localhost:5103/api/vault/guard

# a user calling the admin route → 403 INSUFFICIENT_ROLE
curl -H "Authorization: Bearer <user-token>" http://localhost:5103/api/vault/admin
```

### Failure vocabulary

`400` validation · `401 MISSING_TOKEN / TOKEN_EXPIRED / TOKEN_REVOKED / TOKEN_INVALID / INVALID_CREDENTIALS` · `403 INSUFFICIENT_ROLE` · `409 EMAIL_TAKEN` · `429 TOO_MANY_ATTEMPTS` · `500` unexpected

---

## 5. Project structure

```
Project3-Secure-Authentication-System/
├─ server.js
├─ .env                          # JWT secret, TTL, bcrypt cost, rate limits
├─ package.json
├─ README.md
├─ data/
│  └─ users.json                 # created on first run (hashes only)
├─ src/
│  ├─ load-env.js
│  ├─ data/user.store.js         # file store + seeding
│  ├─ errors/api-error.js
│  ├─ middleware/
│  │  ├─ auth.js                 # requireAuth · requireRole
│  │  ├─ request-log.js
│  │  ├─ not-found.js
│  │  └─ error-handler.js
│  ├─ routes/
│  │  ├─ auth.routes.js          # register · login · logout · refresh · me
│  │  └─ vault.routes.js         # protected + admin routes
│  ├─ security/
│  │  ├─ password.js             # bcrypt + strength rules
│  │  ├─ token.js                # sign · verify · revoke · inspect
│  │  └─ rate-limit.js           # failed-login lockout
│  └─ validation/auth.validator.js
└─ public/                       # "The Perimeter" interface
   ├─ index.html
   ├─ styles.css
   └─ app.js
```

## 6. Interface

**"The Perimeter"** — a dark instrument panel. Left: sign-in / registration with a live strength meter and one-click demo credentials. Right: the issued token shown as three coloured segments, its decoded claims, a live expiry bar, protected-route buttons (including a "token stripped" button that must return `401`), and a request log.

---

*DecodeLabs · Greater Lucknow, India · www.decodelabs.tech*
