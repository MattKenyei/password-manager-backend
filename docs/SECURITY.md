# Security

## Threat model

**Adversaries we defend against:**

1. **Server compromise.** Attacker gains full access to Postgres and Redis.
   - Master passwords: not stored, cannot be recovered.
   - Derived keys: not stored.
   - Encrypted items: useless without `account_key`.
   - Auth keys: hashed (SHA-256), cannot be reversed.
   - Refresh tokens: hashed, cannot be used.

2. **Network attacker (MITM).**
   - Defended by TLS + certificate pinning on mobile.
   - Even with TLS broken, attacker sees only ciphertext and `auth_key`
     (not master password).

3. **Database leak.** Same as server compromise.

4. **Stolen device (offline).**
   - `account_key` in SecureStorage (Keychain/Keystore), gated by biometrics.
   - Encrypted local DB.
   - Server-side revocation kills future sessions.

**Adversaries we do NOT defend against:**

1. **Malicious server with prior data.** If attacker controls the server
   **and** has captured traffic when the user unlocked, they could serve
   modified data or attempt to force re-keying. Out of scope for MVP.

2. **Compromised client device (malware).** If attacker has code execution
   on the client while vault is unlocked, all bets are off.

3. **XSS on web client.** Mitigated by strict CSP (to be added), but
   ultimately client-side code execution defeats all encryption.

## Cryptographic primitives

| Purpose                          | Algorithm                 | Parameters                           |
| -------------------------------- | ------------------------- | ------------------------------------ |
| Master password → master_key     | Argon2id                  | memory=64 MiB, time=3, parallelism=1 |
| master_key → wrapped_account_key | AES-256-GCM               | random 12-byte nonce                 |
| account_key → item_key           | HKDF-SHA256               | info = item_id                       |
| Item encryption                  | WebCrypto AES-256-GCM     | random 12-byte nonce                 |
| Auth verifier                    | SHA-256(auth_key)         | —                                    |
| Refresh tokens                   | crypto/rand(32) → SHA-256 | —                                    |
| JWT signing                      | HMAC-SHA256               | 32+ byte secret                      |

## Key handling

**In memory (client):**

- `master_password` — never persisted
- `master_key` — never persisted, derived on unlock
- `account_key` — only in JS memory during session, cleared on lock

**At rest (client):**

- `wrapped_account_key_biometric` — encrypted by OS keychain
  (iOS: `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`,
  Android: EncryptedSharedPreferences with StrongBox if available)
- Encrypted items in local DB (Dexie/SQLite)

**At rest (server):**

- `auth_verifier` = SHA-256(auth_key)
- `wrapped_account_key` (encrypted by `master_key`, server cannot decrypt)
- `refresh_tokens.token_hash` = SHA-256(raw)
- Encrypted item blobs

## Known limitations

- **No OPAQUE yet.** Login uses `Argon2id(password) → auth_key → SHA-256`.
  A future iteration will adopt OPAQUE (RFC 9807), removing even the
  hashed verifier from the server.

- **No rate limiting yet.** MVP accepts unlimited requests.
  Production deployment requires per-IP and per-email throttling on
  `/auth/*` endpoints.

- **Refresh rotation without grace period.** Network failures during refresh
  may cause a false-positive reuse detection. Production should add a
  short grace window (5-10 seconds).

- **WebSocket token in URL.** Access tokens appear in server access logs.
  Production should use short-lived one-time tickets via
  `POST /auth/ws-ticket`.

- **Origin: \* on WebSocket.** Vulnerable to CSWSH if cookies are ever
  introduced. Production must whitelist origins.

- **No rate limiting on WebSocket handshake.** Mass connection attempts
  from one IP are not throttled.

- **Certificate pinning on mobile not yet implemented.**
