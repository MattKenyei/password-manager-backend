# Password Manager

> Zero-knowledge password manager with end-to-end encryption.
> The server never sees your master password or your decrypted data.

A self-hosted alternative to 1Password/Bitwarden. Built as a learning project:
Go backend, Vue 3 + TypeScript frontend, real cryptographic guarantees.

**Repos:** [backend](.) · [frontend](https://github.com/MattKenyei/password-manager-frontend)
**API reference:** [docs/API.md](docs/API.md)
**Live demo:** https://password-manager-6y7.pages.dev (register a test account — data is E2E encrypted, server can't read it)

## Features

- **Zero-knowledge** — master password and all plaintext stay on the client
- **End-to-end encryption** — Argon2id key derivation, AES-256-GCM
- **Multi-device sync** — offline-first, conflict-aware, revision-based
- **Real-time notifications** — WebSocket push between devices
- **JWT auth** — short-lived access tokens + refresh rotation with reuse detection
- **Rate limiting** — Redis sliding window on auth endpoints
- **Audit log** — async per-user event history
- **Device management** — list, revoke, per-device revocation
- **CORS** — same API serves web, extension, desktop and mobile clients
- **Cross-platform** — Web, Desktop (Tauri), Browser extension (Chrome MV3), Mobile (Capacitor Android) from one codebase

## Status

| Component                               | Status |
| --------------------------------------- | ------ |
| Auth (register, login, refresh, logout) | ✅     |
| Devices (list, revoke)                  | ✅     |
| Sync (push, pull, conflicts)            | ✅     |
| WebSocket notifications                 | ✅     |
| Rate limiting (Redis)                   | ✅     |
| Audit log                               | ✅     |
| CORS                                    | ✅     |
| Frontend (Vue 3 + TS)                   | ✅     |
| Desktop (Tauri)                         | ✅     |
| Browser extension (Chrome MV3)          | ✅     |
| Mobile (Capacitor Android)              | ✅     |
| iOS                                     | 📋     |
| Autofill (iOS/Android)                  | 📋     |

## Architecture

```
       Web ─┐
   Desktop ─┤
 Extension ─┼──HTTPS (ciphertext) + WS──▶ Go Backend ──▶ Postgres
    Mobile ─┘                                  │
                                          └──▶ Redis (rate limit)
```

Server responsibilities:

- Authenticate users (Argon2id-derived verifier, hashed with SHA-256)
- Store encrypted item blobs
- Provide revision-ordered sync
- Notify devices of changes
- Rate limit auth endpoints
- Write audit events

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for details.

## Security model

**Server never has access to:**

- Master password
- Derived keys (`master_key`, `account_key`, `item_key`)
- Decrypted items

**Server stores:**

- Auth verifier: `SHA-256(auth_key)`, where `auth_key = Argon2id(master_password, auth_salt)` on the client
- Encrypted blobs (`items.encrypted_blob`) — AES-256-GCM ciphertext
- `wrapped_account_key` — `account_key` encrypted with `master_key` (server can't decrypt)
- Refresh tokens — hashed with SHA-256
- Metadata: email, device names, timestamps

**Client-side crypto:**

- `master_key = Argon2id(master_password, enc_salt)`
- `account_key` — random 32 bytes, wrapped with `master_key`
- Each item encrypted with `HKDF(account_key, item_id)` + AES-256-GCM

See [docs/SECURITY.md](docs/SECURITY.md) for threat model.

## Tech stack

**Backend:**

- **Go 1.27** — main language
- **pgx/v5** — Postgres driver with native API
- **net/http** with Go 1.22+ routing patterns
- **goose** — SQL migrations
- **golang-jwt/jwt/v5** — JWT
- **coder/websocket** — WebSocket
- **Redis** — rate limiting
- **slog** — structured logging

**Frontend** (see [frontend repo](https://github.com/MattKenyei/password-manager-frontend)):

- **Vue 3** (Composition API) + **TypeScript**
- **Pinia** — state
- **Vue Router**
- **Axios**
- **Tailwind CSS** v4 + **SCSS**
- **WebCrypto** — AES-256-GCM, HKDF
- **hash-wasm** — Argon2id in Web Worker
- **Dexie** — IndexedDB wrapper
- **Tauri v2** — desktop
- **CRXJS** — browser extension
- **Capacitor** — Android app

**Infrastructure (dev):**

- **PostgreSQL 17** (Docker)
- **Redis 7** (Docker)

**Infrastructure (prod):**

- **Render** — Go backend (Docker, free tier)
- **Neon** — PostgreSQL (free tier, scale-to-zero)
- **Upstash** — Redis (free tier, TLS)
- **Cloudflare Pages** — web frontend

## Project structure

```
.
├── cmd/
│   └── server/           # HTTP server entry point
├── internal/
│   ├── api/
│   │   ├── auth/         # /auth/*
│   │   ├── devices/      # /devices/*
│   │   ├── sync/         # /sync
│   │   ├── audit/        # /audit
│   │   ├── middleware/   # RequireAuth, RateLimit, CORS
│   │   └── httputil/     # JSON responses, error format
│   ├── audit/            # Async audit logger
│   ├── config/           # env-based config
│   ├── crypto/           # SHA-256 hashing (server-side verifier only)
│   ├── ctxkey/           # typed context keys
│   ├── domain/           # business entities
│   ├── ratelimit/        # Redis sliding window
│   ├── storage/          # Postgres + Redis repositories
│   ├── token/            # JWT issuance/parsing
│   └── ws/               # WebSocket hub and clients
├── migrations/           # SQL migrations (goose)
├── scripts/              # dev helpers (curl scripts)
├── docs/                 # architecture, API, security docs
├── docker-compose.yml
├── Dockerfile            # production image
└── .env.example
```

## Getting started (dev)

### Prerequisites

- **Go 1.27+** — [download](https://go.dev/dl/)
- **Docker Desktop** — [download](https://www.docker.com/products/docker-desktop/)
- **Git Bash** (Windows) or any Unix shell
- **goose** — `go install github.com/pressly/goose/v3/cmd/goose@latest`
- **air** (optional, for hot reload) — `go install github.com/air-verse/air@latest`

### Setup

```bash
git clone git@github.com:MattKenyei/password-manager-backend.git
cd password-manager-backend

cp .env.example .env
# Edit .env — set JWT_SECRET to a random 48-byte base64 string:
#   head -c 48 /dev/urandom | base64 -w 0

docker compose up -d
docker compose ps

export GOOSE_DRIVER=postgres
export GOOSE_DBSTRING="postgres://pm_user:pm_password@localhost:5434/password_manager?sslmode=disable"
goose -dir ./migrations up

go mod download
air
```

**Note:** Postgres is exposed on port **5434** (not the default 5432) to coexist with a local Postgres installation. If you don't have one locally, change it in `docker-compose.yml` to `5432:5432`.

### Verify

```bash
curl http://localhost:8080/health
# {"status":"ok"}
```

### Test registration flow

```bash
bash scripts/register.sh
# → {"id":"...","email":"...","created_at":"..."}
```

## Deploy (prod)

Backend runs on **Render** (Docker, free tier), with **Neon** (Postgres) and **Upstash** (Redis).

### 1. Postgres (Neon)

1. Create project at [neon.tech](https://neon.tech)
2. Copy connection string: `postgresql://user:pass@ep-xxx.neon.tech/neondb?sslmode=require`
3. Apply migrations once, from your machine:

```bash
export GOOSE_DRIVER=postgres
export GOOSE_DBSTRING="postgresql://user:pass@ep-xxx.neon.tech/neondb?sslmode=require"
goose -dir ./migrations up
```

### 2. Redis (Upstash)

1. Create a Regional database at [upstash.com](https://upstash.com)
2. Copy **UPSTASH_REDIS_TLS_URL** (`rediss://...`)

### 3. Web Service (Render)

1. New → **Web Service**, connect this repo, branch `dev`
2. Runtime: **Docker**
3. Instance type: **Free**
4. Environment variables:

```
JWT_SECRET=<48 bytes, base64>
POSTGRES_HOST=ep-xxx.neon.tech
POSTGRES_PORT=5432
POSTGRES_USER=user
POSTGRES_PASSWORD=pass
POSTGRES_DB=neondb
POSTGRES_SSLMODE=require
REDIS_URL=rediss://default:xxx@eu1-xxx.upstash.io:6379
SERVER_ADDR=:10000
```

Render sets `$PORT=10000`; `SERVER_ADDR` overrides it explicitly. Free tier sleeps after 15 min idle — use [cron-job.org](https://cron-job.org) to ping `/health` every 10 min.

### 4. Verify

```bash
curl https://<your-service>.onrender.com/health
# {"status":"ok"}
```

Then run `goose up` against Neon (one-time, as shown above). The `users.auth_verifier` column must exist — otherwise registrations return `500`.

## API

Full reference: **[docs/API.md](docs/API.md)**.

### Public endpoints

```
GET    /health                  # health check
POST   /auth/register           # create account
POST   /auth/login/start        # get salts for key derivation
POST   /auth/login/finish       # exchange auth_key for tokens
POST   /auth/refresh            # rotate refresh token
POST   /auth/logout             # revoke current session
GET    /ws?token=<access>       # WebSocket for real-time sync
```

### Authenticated endpoints

All require `Authorization: Bearer <access_token>`.

```
GET    /devices                 # list user's devices
DELETE /devices/{id}            # revoke device
POST   /sync                    # push local changes
GET    /sync?since=N            # pull changes since revision N
GET    /audit                   # recent audit events
```

### CORS

Allowed origins (see `internal/api/middleware/cors.go`):

- `http://localhost:5173` — web dev
- `http://localhost:5174` — extension dev
- `https://localhost` — Capacitor Android
- `capacitor://localhost` — Capacitor iOS
- `chrome-extension://*` — browser extension
- `*.pages.dev` — Cloudflare Pages
- `*.trycloudflare.com` — cloudflared dev tunnel

### Rate limits

Per-IP, sliding window via Redis:

- `/auth/login/*` — 10/min
- `/auth/register` — 30/min

Returns `429` with `Retry-After: 60`.

## Development workflow

**Branching model:**

- `main` — stable releases only
- `dev` — integration branch
- `feature/<name>` — one branch per task, merged into `dev` via PR

**Commits:** [Conventional Commits](https://www.conventionalcommits.org/)

```
feat: add POST /auth/register with validation
fix: handle nil pointer in sync handler
chore: bump pgx to v5.7.1
docs: describe refresh rotation in ARCHITECTURE
```

**Pull requests:** always into `dev`, squash-merge, delete branch after.

## Roadmap

- [x] Backend MVP (auth, devices, sync, WS)
- [x] Rate limiting (Redis sliding window)
- [x] Audit log
- [x] CORS middleware
- [x] Production deploy (Render + Neon + Upstash)
- [x] Frontend (Vue 3 + TS)
- [x] Desktop app (Tauri)
- [x] Browser extension (Chrome MV3, standalone)
- [x] Mobile app (Capacitor Android, biometric unlock)
- [x] TOTP (2FA codes in vault items)
- [x] Import/export (encrypted backup + plaintext JSON/CSV)
- [ ] iOS build
- [ ] Autofill (iOS Credential Provider, Android AutofillService)
- [ ] OPAQUE login (removes hashed verifier from server)
- [ ] `account_key` rotation on device compromise
- [ ] WebAuthn / passkeys
- [ ] OAuth login (Google, Telegram)
- [ ] Sharing (envelope encryption)

## License

MIT — see [LICENSE](LICENSE).

## Acknowledgments

Built as a learning project to study Go, cryptography, and sync protocols.
