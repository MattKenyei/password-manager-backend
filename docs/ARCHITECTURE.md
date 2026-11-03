# Architecture

> Deep dive into the design decisions behind Password Manager.

## Contents

1. [Cryptographic model](#cryptographic-model)
2. [Backend layers](#backend-layers)
3. [Data model](#data-model)
4. [Sync protocol](#sync-protocol)
5. [Real-time notifications](#real-time-notifications)
6. [Multi-device enrollment](#multi-device-enrollment)
7. [Key rotation](#key-rotation)

---

## Cryptographic model

### Key derivation chain

```
master_password
      │
      ├─ Argon2id(auth_salt)  ──▶  auth_key (32 B)
      │                                │
      │                                └─ SHA-256 ──▶ auth_verifier (server-side)
      │
      └─ Argon2id(enc_salt)   ──▶  master_key (32 B)
                                       │
                                       └─ AES-256-GCM unwrap
                                              │
                                              ▼
                                     account_key (32 B, random)
                                              │
                                     HKDF-SHA256(account_key, "pm-item:" + id)
                                              │
                                              ▼
                                       item_key (32 B)
                                              │
                                     AES-256-GCM encrypt
                                              │
                                              ▼
                                     encrypted_blob
```

### What lives where

| Secret            | Stored on client                             | Stored on server                             |
| ----------------- | -------------------------------------------- | -------------------------------------------- |
| `master_password` | Never persisted                              | Never                                        |
| `master_key`      | In-memory during session                     | Never                                        |
| `account_key`     | In-memory; optionally wrapped in OS keychain | `wrapped_account_key` (server can't decrypt) |
| `item_key`        | Never persisted — derived on demand          | Never                                        |
| `auth_key`        | Derived on login                             | `SHA-256(auth_key)` as `auth_verifier`       |
| `refresh_token`   | OS keychain / localStorage / chrome.storage  | `SHA-256(raw)` in `refresh_tokens`           |

### Argon2id parameters

```
memory  = 64 MiB
time    = 3
threads = 1
output  = 32 bytes
```

**Chosen for mobile compatibility.** Higher parameters would be better on desktop but break the "same salts across devices" invariant — mobile would need minutes to derive. 64 MiB / t=3 takes ~300–800 ms on a mid-range phone, ~150 ms on desktop.

Parameters are **fixed at registration** and stored in `users.kdf_params`. Changing them later requires a key-rotation flow (see §7).

### Encryption

- **Algorithm:** AES-256-GCM (WebCrypto native).
- **Nonce:** 12 bytes, random per encryption via `crypto.getRandomValues`. **Never reused** — this is critical for GCM security.
- **Blob format:** `version(1) || nonce(12) || ciphertext || tag(16)`.
- **Version byte:** allows format migration without DB schema changes.

Why AES-GCM, not XChaCha20-Poly1305:

- Native WebCrypto — no WASM libsodium (~300 KB saved).
- XChaCha20's bigger nonce is safer against collision, but our per-item keys have tiny data volume — collision probability is negligible.
- On modern CPUs with AES-NI, AES-GCM is faster than ChaCha20.

### Anti-enumeration

- `POST /auth/login/start` returns **fake salts** for unknown emails — attacker can't probe.
- `POST /auth/login/finish` returns the same `401 invalid_credentials` for unknown email and wrong password.
- `auth_key` comparison uses `crypto/subtle.ConstantTimeCompare` — no timing leak.

---

## Backend layers

```
cmd/server/main.go       ← composition root: builds everything by hand
      │
      ▼
internal/api/*           ← HTTP handlers, DTOs, middleware
      │
      ▼
internal/domain/         ← business entities, no HTTP/no SQL
      │
      ▼
internal/storage/        ← Postgres + Redis repositories
      │
      ▼
internal/crypto/         ← SHA-256 verifier only (server has no encryption keys)
```

### Dependency injection

Manual, via constructors. No DI framework.

```go
pool         := storage.NewPostgres(ctx, cfg.Postgres.DSN())
redis        := storage.NewRedis(ctx, cfg.Redis.Addr, ...)
userRepo     := storage.NewUserRepository(pool)
deviceRepo   := storage.NewDeviceRepository(pool)
refreshRepo  := storage.NewRefreshTokenRepository(pool)
itemRepo     := storage.NewItemRepository(pool)
issuer       := token.NewIssuer(cfg.JWT.Secret, cfg.JWT.AccessTTL)
auditLogger  := audit.NewLogger(pool, 1000, logger)
authHandler  := auth.NewHandler(userRepo, deviceRepo, refreshRepo, issuer, cfg, auditLogger, logger)
```

**Why not a DI framework:** explicit tree in `main()` is readable, fast, and debuggable. Nothing hides behind reflection or runtime magic.

### Repository pattern

Each storage type (`UserRepository`, `ItemRepository`, etc.) is a struct with a `*pgxpool.Pool` and methods that execute SQL. No ORM. Every query is explicit, every field scan is explicit.

**Why no ORM:**

- Go community prefers explicit SQL.
- A sync engine with `SELECT FOR UPDATE` and per-item version checks is _easier_ to reason about in raw SQL.
- No hidden N+1 queries. If something is slow — `EXPLAIN` shows exactly what.

### Why `internal/`

Go's `internal/` prevents importing these packages from outside the module. Everything under `internal/` is a private implementation detail. Only `cmd/server` is a public entry point.

---

## Data model

### `users`

```sql
CREATE TABLE users (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email                 CITEXT NOT NULL UNIQUE,
    auth_verifier         BYTEA NOT NULL,        -- SHA-256(auth_key)
    auth_salt             BYTEA NOT NULL,        -- for login/start
    enc_salt              BYTEA NOT NULL,        -- for master_key derivation
    kdf_params            JSONB NOT NULL,        -- {algo, memoryKiB, iterations, parallelism}
    wrapped_account_key   BYTEA NOT NULL,        -- AES-GCM(master_key, account_key)
    key_generation        INT NOT NULL DEFAULT 1,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

**`CITEXT`** for case-insensitive email — `user@example.com` and `User@Example.Com` are the same account. No `LOWER(email)` in every query.

**`TIMESTAMPTZ`** everywhere — never `TIMESTAMP`. Stores UTC, converts on read. No "is this local time or UTC?" ambiguity.

**`key_generation`** — reserved for future `account_key` rotation (§7). Currently always `1`.

### `devices`

```sql
CREATE TABLE devices (
    id           UUID PRIMARY KEY,                    -- client-generated UUID v4
    user_id      UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name         TEXT NOT NULL,                       -- "MacBook Pro Matt"
    platform     TEXT NOT NULL,                       -- web | desktop | ios | android | extension
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at   TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_devices_user_id ON devices(user_id) WHERE revoked_at IS NULL;
```

**Client-generated UUID** — the device id is generated on first launch and reused for all logins. Server upserts by `id`, not by name. Renaming a device doesn't create a duplicate.

**Partial index** (`WHERE revoked_at IS NULL`) — only active devices are queried; revoked ones don't bloat the index.

### `refresh_tokens`

```sql
CREATE TABLE refresh_tokens (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id   UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    token_hash  BYTEA NOT NULL,      -- SHA-256(raw)
    expires_at  TIMESTAMPTZ NOT NULL,
    used_at     TIMESTAMPTZ,         -- set on rotation
    revoked_at  TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX idx_refresh_tokens_hash ON refresh_tokens(token_hash);
```

**Hash only** — a DB leak doesn't expose usable tokens.

**`used_at` vs `revoked_at`:**

- `used_at` — set on successful rotation (old token exchanged for new).
- `revoked_at` — set on logout, device revocation, or reuse detection.

**Reuse detection:** if a token with non-null `used_at` is presented, that means it was already exchanged — either a replay attack, or a client race. Both cases trigger `RevokeDeviceTokens(device_id)` — all tokens for that device are marked revoked.

### `items`

```sql
CREATE TABLE items (
    id               UUID NOT NULL,                    -- client-generated
    user_id          UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    encrypted_blob   BYTEA NOT NULL,                   -- AES-256-GCM
    version          BIGINT NOT NULL DEFAULT 1,        -- per-item, for optimistic locking
    global_revision  BIGINT NOT NULL DEFAULT 0,        -- per-user, for pull cursor
    deleted          BOOLEAN NOT NULL DEFAULT FALSE,   -- tombstone
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, id)
);

CREATE INDEX idx_items_user_global_rev ON items(user_id, global_revision);
```

**Composite PK `(user_id, id)`** — forces every query to filter by `user_id`. Prevents accidental cross-tenant leaks. UUID collision across users is a non-issue.

**`version` vs `global_revision`:**

- `version` — per-item counter, incremented on every change. Used for optimistic locking (`base_version` in push).
- `global_revision` — per-user counter. Used as the pull cursor (`since=N`).

**Tombstones** — deleted items stay in the DB with `deleted=true`. If we hard-deleted, a stale client could resurrect the item on its next push. See §4 for details.

### `user_revisions`

```sql
CREATE TABLE user_revisions (
    user_id          UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    current_revision BIGINT NOT NULL DEFAULT 0
);
```

Per-user monotonic counter. Locked with `SELECT FOR UPDATE` during push to serialize concurrent pushes from different devices. See §4.

### `audit_logs`

```sql
CREATE TABLE audit_logs (
    id          BIGSERIAL PRIMARY KEY,
    user_id     UUID REFERENCES users(id) ON DELETE SET NULL,
    device_id   UUID,
    event_type  TEXT NOT NULL,
    result      TEXT NOT NULL,
    ip          TEXT,
    user_agent  TEXT,
    metadata    JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_audit_logs_user_time ON audit_logs(user_id, created_at DESC);
CREATE INDEX idx_audit_logs_event_time ON audit_logs(event_type, created_at DESC);
```

**`ON DELETE SET NULL`** for `user_id` — deleting a user shouldn't delete audit history (security incident forensics).

### `goose_db_version`

Managed by `goose` — tracks applied migrations. Never touch manually.

---

## Sync protocol

### State on the client

```
last_server_revision: 42
pending_changes: [
  { id, encrypted_blob, base_version, deleted }
]
items: { id → { encrypted_blob, version, deleted } }   // Dexie / IndexedDB
```

### Push (`POST /sync`)

```
1. Begin transaction
2. INSERT INTO user_revisions (user_id, current_revision) VALUES ($1, 0)
     ON CONFLICT (user_id) DO NOTHING
3. SELECT current_revision FROM user_revisions WHERE user_id = $1 FOR UPDATE
   ← this serializes all concurrent pushes for the same user
4. For each change:
     SELECT version FROM items WHERE user_id = $1 AND id = $2
     if exists and base_version != version   → conflict
     else                                    → apply (INSERT or UPDATE)
                                                version += 1
                                                global_revision = ++current_revision
5. UPDATE user_revisions SET current_revision = <final>
6. COMMIT
7. Broadcast WS notification to other devices of this user
```

**Why `SELECT FOR UPDATE`:** without it, two parallel pushes could read `current_revision = 10`, both compute `11`, and produce two items with identical `global_revision`. A pull with `since=10` would then return both — but the client would record `new_revision=11` and miss one on the next sync. `FOR UPDATE` serializes: the second transaction reads `11`, writes `12`.

### Pull (`GET /sync?since=N`)

```
1. SELECT current_revision FROM user_revisions WHERE user_id = $1
2. if since >= current_revision → return empty + current_revision
3. SELECT ... FROM items
   WHERE user_id = $1
     AND global_revision > $since
     AND global_revision <= current_revision
   ORDER BY global_revision
4. Return items + current_revision
```

**Reading `current_revision` before querying items is critical.** If we read items first, a concurrent push could land between the two queries — the client would get items up to revision X but be told `new_revision = X+1`, and miss the last change forever.

**Upper bound `<= current_revision`** — ensures items written during the pull don't sneak in with a revision the client didn't record.

### Conflict resolution

The server doesn't resolve conflicts — it reports them:

```json
{
  "applied": ["uuid1"],
  "conflicts": [{ "id": "uuid2", "server_version": 5 }],
  "new_revision": 43
}
```

**Client-side resolution** (reference implementation in the frontend):

1. Decrypt the local copy of the conflicting item.
2. Append `" (conflict)"` to its title.
3. Assign a **new UUID**, encrypt, push with `base_version: 0`.
4. Clear the old item's pending change — the pull will overwrite it with the server version.
5. User sees two entries and merges manually.

**Why not Last-Write-Wins:** for a password manager, silently discarding one side of a conflict is unacceptable. Losing a password is worse than seeing a duplicate.

### Tombstones

Deleted items stay in `items` with `deleted=true`. Not physically deleted.

**Why:** if we hard-deleted, a stale client (offline, has the item) would push an update for it. `PushChanges` would find no row, treat it as a new item, and resurrect it. Tombstone + `version` check prevents this — the stale client's `base_version` won't match.

**Cleanup:** not implemented. Would require tracking the minimum acknowledged revision across all of a user's devices. See §7 (Key rotation) for related long-term data cleanup.

### Idempotency

The push protocol is **not idempotent** — a replayed request will hit conflicts because `base_version` no longer matches.

**Client rule:** never retry a push after a network error. Instead, next time `triggerSync` runs, it will find `pending_changes` intact and retry them as a fresh push (with the same `base_version`, which is still correct because the first attempt never landed).

**Why not idempotency keys:** they'd add a table, TTL, and cleanup. The current approach — "if in doubt, drop the pending change back into the queue" — is simpler and correct for our case.

### Why client-generated UUIDs

Item IDs are generated on the client (`crypto.randomUUID()`) **before** the server sees them.

- **Offline creation:** user creates an item with no network — it gets a permanent ID immediately.
- **References:** the ID is stable across sync, so any local references (open editor, URL deep-link) don't break.
- **Server never has to return the new ID** — the client already knows it.

Collision probability for UUID v4 across all users of a single deployment: negligible.

---

## Real-time notifications

### Hub pattern

```
                     ┌────────────────────────────┐
                     │  Hub (mutex + map)         │
                     │  userID → set[*Client]     │
                     └──────────┬─────────────────┘
                                │
       ┌────────────────────────┼──────────────────────┐
       ▼                        ▼                      ▼
   ┌────────┐              ┌────────┐            ┌────────┐
   │Client A│              │Client B│            │Client C│
   │read+wr │              │read+wr │            │read+wr │
   └────────┘              └────────┘            └────────┘
```

`ws.Hub` holds `map[uuid.UUID]map[*Client]struct{}` — clients grouped by `user_id`. All access is guarded by `sync.RWMutex`.

**`BroadcastSync(userID, exceptDeviceID, revision)`** — sends `{"type":"sync","revision":N}` to all of a user's clients **except** the one that triggered the push. Non-blocking: if a client's send buffer is full, the message is dropped. The client will pick it up on the next pull.

### Two goroutines per connection

```
writePump  ──▶  socket  ──▶  network
    ▲
    │ c.send (buffered chan)
    │
readPump   ◀──  socket  ◀──  network
```

**WebSocket doesn't allow concurrent writes.** All writes go through a single `writePump` goroutine that drains `c.send`. Broadcasts push to `c.send` without blocking.

**`readPump` exists even though clients send nothing.** If we don't read, the TCP receive buffer fills, and we can't detect disconnects — the connection sits in the Hub, receiving broadcasts forever.

### Heartbeat

- Server pings every 30 s.
- If pong isn't received within 10 s, `conn.Ping(ctx)` returns an error → connection is closed → `Hub.unregister`.
- Prevents half-open TCP connections from being counted as active indefinitely.

### Backpressure

- Each client has a `chan []byte` of size 32.
- If the buffer is full, `BroadcastSync` drops the message (logged).
- **Safe for our use case** — a dropped notification means one less pull trigger. The client will still pull on the next app focus, WS reconnect, or 60-second periodic check.

### Multi-instance scaling

Current implementation is **single-instance** — all WebSocket connections live in one process's memory.

To scale horizontally:

1. Add Redis Pub/Sub. `BroadcastSync` publishes to `user:{id}` channel.
2. Each replica subscribes to all channels of its connected users.
3. Replicas relay published messages to their local Hub clients.

This is a small change — `BroadcastSync` gets a new implementation, the rest of the code stays. Not implemented yet, because the whole system runs on a single instance.

---

## Multi-device enrollment

### Current state (implemented)

Any device becomes "trusted" by successfully authenticating:

1. User enters `email` + `master_password` on the new device.
2. Client derives `auth_key` and `master_key` locally.
3. `POST /auth/login/start` → gets salts.
4. `POST /auth/login/finish` → gets tokens + `wrapped_account_key`.
5. Client unwraps `account_key` with `master_key`.
6. Device is registered in `devices` table on first successful login.

**Pros:** works with just the master password — no other device needed.
**Cons:** the master password must be entered on the new (potentially untrusted) device.

### Planned: QR-based enrollment

For a better UX on adding a second device without re-entering the master password:

```
Device A (trusted)          Server              Device B (new)
     │                        │                      │
     │ POST /devices/enroll/start                    │
     │───────────────────────▶│                      │
     │  { enroll_token, TTL }  │                      │
     │◀───────────────────────│                      │
     │                        │                      │
     │  Show QR: { token,     │                      │
     │    account_key_encrypted_for_B }              │
     │                        │                      │
     │                        │  Scan QR             │
     │                        │◀─────────────────────│
     │                        │                      │
     │                        │  POST /devices/enroll/finish
     │                        │  { token }           │
     │                        │◀─────────────────────│
     │                        │  { access, refresh } │
     │                        │─────────────────────▶│
```

**Key exchange:** Device B generates an ephemeral X25519 keypair, sends the public key to A (via a small discovery channel — same LAN, or through the server in a `pending` state). A encrypts `account_key` with B's public key and packs it into the QR. B decrypts with its private key.

**Status:** planned, not implemented. Would be the natural next step after mobile support, when "adding a phone" becomes a common operation.

---

## Key rotation

### Why rotation is needed

E2E encryption has a fundamental trade-off: if a device is compromised **while unlocked**, the attacker gains `account_key`. Once they have it, they can decrypt everything they've already pulled — and any future pull too.

Revoking refresh tokens (via `DELETE /devices/{id}`) stops future API access, but doesn't help if the attacker already downloaded the encrypted blobs.

**The only fix is to change `account_key`** — re-encrypt all items under the new key, and give the attacker's old `account_key` ciphertext that no longer decrypts.

### Planned flow

```
1. POST /auth/rotate-key/start
     → server sets key_generation = current + 1
     → returns: nothing sensitive, just confirms the rotation is prepared
     → revokes all refresh tokens for the compromised device

2. Client (on the still-trusted device):
     - generates new_account_key (32 B random)
     - for each item:  decrypt with old item_key, re-encrypt with new item_key
     - for each trusted device D:  wrap new_account_key with D.master_key
     - POST /auth/rotate-key/finish {
         new_wrapped_account_key,        // for this device
         rewrapped_keys_for_other_devices: [{device_id, blob}, ...],
         reencrypted_items: [...]
       }
     → server stores new blobs, deletes old ones, bumps key_generation

3. Other trusted devices on next pull:
     - see new key_generation in their session record
     - fetch the new wrapped_account_key
     - unwrap, replace in-memory account_key
```

### Complications

- **Transactional:** re-encryption must succeed for all items, or none. Otherwise you have a vault where some items decrypt with the old key, some with the new.
- **Offline devices:** a device that hasn't synced since rotation still has the old key. Its next pull gets a `key_generation_mismatch` error → forced re-login with master password → gets new wrapped key.
- **`kdf_params` changes:** same mechanism, but re-derives `master_key` too. More expensive.

**Status:** planned, not implemented. Schema (`users.key_generation`) is prepared.

### Simpler alternative (implemented today)

Today, if you suspect a device is compromised:

1. `DELETE /devices/{id}` — revokes all refresh tokens for that device.
2. Manually re-login on all other trusted devices.

**Limitation:** the attacker already has `account_key`. Rotation is the only way to invalidate it.

**User guidance:** the roadmap plans to add an in-app warning — "if you think a device was compromised, change your master password and re-import your vault."

---

## Out of scope

The following are explicitly deferred:

- **Horizontal scaling of WebSocket** (Redis Pub/Sub)
- **Rate limiting on item sync** (only auth endpoints have rate limits today)
- **Pruning of tombstones** (requires min-acknowledged-revision tracking)
- **Server-side search** (search is client-side, on decrypted items — no server-side index of plaintext)
- **Sharing** (needs envelope encryption with per-recipient keypairs)
- **Audit log retention policy** (currently append-only forever)
- **OPAQUE login** (removes `auth_verifier` from server entirely — see [RFC 9807](https://datatracker.ietf.org/doc/rfc9807/))
