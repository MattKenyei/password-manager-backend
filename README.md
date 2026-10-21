# Password Manager

> Zero-knowledge password manager with end-to-end encryption.
> The server never sees your master password or your decrypted data.

A self-hosted alternative to 1Password/Bitwarden. Built as a learning project:
Go backend, Vue 3 + TypeScript frontend, real cryptographic guarantees.

## Features

- **Zero-knowledge** — master password and all plaintext stay on the client
- **End-to-end encryption** — Argon2id key derivation, XChaCha20-Poly1305 / AES-256-GCM
- **Multi-device sync** — offline-first, conflict-aware, revision-based
- **Real-time notifications** — WebSocket push between devices
- **JWT auth** — short-lived access tokens + refresh rotation
- **Device management** — list, revoke, per-device revocation
- **Cross-platform** — Web, Desktop (Tauri), Mobile (Capacitor) from one codebase

## Status

🚧 **Backend MVP complete, frontend in progress.**

| Component                               | Status |
| --------------------------------------- | ------ |
| Auth (register, login, refresh, logout) | ✅     |
| Devices (list, revoke)                  | ✅     |
| Sync (push, pull, conflicts)            | ✅     |
| WebSocket notifications                 | ✅     |
| Frontend (Vue 3 + TS)                   | 🚧     |
| Desktop (Tauri)                         | 📋     |
| Mobile (Capacitor)                      | 📋     |
| Autofill (iOS/Android)                  | 📋     |

## Architecture

```
┌──────────────┐  ┌──────────────┐  ┌──────────────┐
│   Desktop    │  │    Web       │  │   Mobile     │
│   (Tauri)    │  │ (Vue 3 + TS) │  │ (Capacitor)  │
└──────┬───────┘  └──────┬───────┘  └──────┬───────┘
       │                 │                  │
       │  HTTPS (ciphertext only) + WS     │
       └─────────────────┼──────────────────┘
                         │
                  ┌──────▼───────┐
                  │  Go Backend  │
                  └──────┬───────┘
                         │
              ┌──────────┴──────────┐
         ┌────▼────┐          ┌─────▼──────┐
         │Postgres │          │   Redis    │
         └─────────┘          └────────────┘
```

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for details.

## Security model

**Server never has access to:**

- Master password
- Derived keys (`master_key`, `account_key`)
- Decrypted items

**Server stores:**

- Password hash for authentication (`Argon2id(auth_key)`)
- Encrypted blobs (`encrypted_blob` in `items`)
- Metadata: email, device names, timestamps

**Client-side crypto:**

- `master_key = Argon2id(master_password, enc_salt)`
- `account_key` — random 32 bytes, wrapped with `master_key`
- Each item encrypted with `HKDF(account_key, item_id)`

See [docs/SECURITY.md](docs/SECURITY.md) for threat model.

## Tech stack

**Backend:**

- **Go 1.27** — main language
- **pgx/v5** — Postgres driver with native API
- **net/http** with Go 1.22+ routing patterns
- **goose** — SQL migrations
- **golang-jwt/jwt/v5** — JWT
- **coder/websocket** — WebSocket
- **slog** — structured logging

**Frontend:** _(in progress)_

- **Vue 3** (Composition API) + **TypeScript**
- **Pinia** — state
- **Vue Router**
- **Axios**
- **Tailwind CSS** + **SCSS**
- **libsodium-wrappers** — XChaCha20-Poly1305
- **argon2-browser** — Argon2id in Web Worker
- **Dexie** — IndexedDB wrapper (web) / **@capacitor-community/sqlite** (mobile)

**Infrastructure:**

- **PostgreSQL 17** (Docker)
- **Redis 7** (Docker)

## Project structure

```
.
├── cmd/
│   └── server/           # HTTP server entry point
├── internal/
│   ├── api/              # HTTP handlers, middleware, DTOs
│   │   ├── auth/
│   │   ├── devices/
│   │   ├── sync/
│   │   └── httputil/
│   ├── config/           # env-based config
│   ├── crypto/           # hashing, key derivation
│   ├── ctxkey/           # typed context keys
│   ├── domain/           # business entities
│   ├── storage/          # Postgres repositories
│   ├── token/            # JWT issuance/parsing
│   └── ws/               # WebSocket hub and clients
├── migrations/           # SQL migrations (goose)
├── scripts/              # dev helpers (curl scripts)
├── docs/                 # architecture, API, security docs
├── docker-compose.yml
└── .env.example
```

## Getting started

### Prerequisites

- **Go 1.27+** — [download](https://go.dev/dl/)
- **Docker Desktop** — [download](https://www.docker.com/products/docker-desktop/)
- **Git Bash** (Windows) or any Unix shell
- **goose** — `go install github.com/pressly/goose/v3/cmd/goose@latest`
- **air** (optional, for hot reload) — `go install github.com/air-verse/air@latest`

### Setup

```bash
# 1. Clone
git clone git@github.com:MattKenyei/password-manager-backend.git
cd password-manager-backend

# 2. Configure environment
cp .env.example .env
# Edit .env — set JWT_SECRET to a random 48-byte base64 string:
#   head -c 48 /dev/urandom | base64 -w 0

# 3. Start Postgres and Redis
docker compose up -d
docker compose ps  # both should be "healthy"

# 4. Apply migrations
export GOOSE_DRIVER=postgres
export GOOSE_DBSTRING="postgres://pm_user:pm_password@localhost:5434/password_manager?sslmode=disable"
goose -dir ./migrations up

# 5. Install Go dependencies
go mod download

# 6. Run
go run ./cmd/server
# or, with hot reload:
air
```

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

## API

Full reference: [docs/API.md](docs/API.md).

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
```

## Development workflow

**Branching model:**

- `main` — stable releases only
- `develop` — integration branch
- `feature/<name>` — one branch per task, merged into `develop` via PR

**Commits:** [Conventional Commits](https://www.conventionalcommits.org/)

```
feat: add POST /auth/register with validation
fix: handle nil pointer in sync handler
chore: bump pgx to v5.7.1
docs: describe refresh rotation in ARCHITECTURE
```

**Pull requests:** always into `develop`, squash-merge, delete branch after.

## Roadmap

- [x] Backend MVP (auth, devices, sync, WS)
- [ ] Frontend (Vue 3 + TS)
  - [ ] Crypto layer (Argon2 worker, WebCrypto wrappers)
  - [ ] Platform abstractions (SecureStorage, LocalDB)
  - [ ] Unlock flow (register, login, biometric)
  - [ ] Vault UI (list, item, editor)
  - [ ] Sync cycle (Dexie + push/pull + WS)
- [ ] Desktop app (Tauri)
- [ ] Mobile app (Capacitor)
- [ ] Autofill (iOS Credential Provider, Android AutofillService)
- [ ] Browser extension
- [ ] 2FA (TOTP, WebAuthn)
- [ ] Sharing (envelope encryption)
- [ ] Import from 1Password / Bitwarden / KeePass

## License

MIT — see [LICENSE](LICENSE).

## Acknowledgments

Built as a learning project to study Go, cryptography, and sync protocols.
