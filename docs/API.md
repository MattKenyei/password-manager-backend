# API Reference

Base URL: `http://localhost:8080` (dev) / `https://api.example.com` (prod)

## Authentication

Protected endpoints require:

```
Authorization: Bearer <access_token>
```

Access tokens are JWTs (HS256) with 15-minute TTL. Refresh tokens are
opaque 32-byte values (base64-encoded) with 30-day TTL and rotation.

## Error format

All errors return JSON:

```json
{
  "error": "validation_failed",
  "message": "one or more fields are invalid",
  "fields": {
    "email": "required"
  }
}
```

- `error` — machine-readable code (snake_case)
- `message` — human-readable description
- `fields` — optional, per-field validation errors

## Common status codes

| Code | Meaning                                               |
| ---- | ----------------------------------------------------- |
| 200  | Success                                               |
| 201  | Created                                               |
| 204  | No Content (success, no body)                         |
| 400  | Validation error                                      |
| 401  | Unauthorized (missing/invalid token, bad credentials) |
| 404  | Not found                                             |
| 409  | Conflict (e.g., email exists)                         |
| 429  | Too many requests (rate limited)                      |
| 500  | Internal error                                        |

## Health

### `GET /health`

No auth. Returns service status.

```json
{ "status": "ok" }
```

Returns `503` if Postgres is down.

## Auth

### `POST /auth/register`

Create a new account.

**Request:**

```json
{
  "email": "user@example.com",
  "auth_key": "<base64, 32 bytes>",
  "auth_salt": "<base64, 16-64 bytes>",
  "enc_salt": "<base64, 16-64 bytes>",
  "kdf_params": "<base64 JSON>",
  "wrapped_account_key": "<base64, ≥73 bytes>"
}
```

**Response 201:**

```json
{
  "id": "uuid",
  "email": "user@example.com",
  "created_at": "2026-10-21T12:00:00Z"
}
```

**Errors:** `400` validation, `409` email exists.

### `POST /auth/login/start`

Get salts and KDF params for key derivation. Returns fake salts for
unknown emails (anti-enumeration).

**Request:**

```json
{ "email": "user@example.com" }
```

**Response 200:**

```json
{
  "auth_salt": "<base64>",
  "enc_salt": "<base64>",
  "kdf_params": "<base64 JSON>"
}
```

### `POST /auth/login/finish`

Verify `auth_key` and issue tokens.

**Request:**

```json
{
  "email": "user@example.com",
  "auth_key": "<base64, 32 bytes>",
  "device_id": "uuid",
  "device_name": "iPhone 15 Matt",
  "device_platform": "ios"
}
```

**Response 200:**

```json
{
  "access_token": "<jwt>",
  "refresh_token": "<base64, 32 bytes>",
  "expires_in": 900,
  "wrapped_account_key": "<base64>"
}
```

**Errors:** `401 invalid_credentials` (same for unknown email and wrong password).

### `POST /auth/refresh`

Exchange refresh token for new pair. Rotation with reuse detection:
reusing an already-used token revokes all tokens for the device.

**Request:**

```json
{ "refresh_token": "<base64>" }
```

**Response 200:**

```json
{
  "access_token": "<jwt>",
  "refresh_token": "<base64>",
  "expires_in": 900
}
```

**Errors:** `401 invalid_refresh_token`.

### `POST /auth/logout`

Revoke current session. Idempotent — always returns `204`.

**Request:**

```json
{ "refresh_token": "<base64>" }
```

**Response 204:** no body.

## Devices

### `GET /devices`

List active devices for the current user.

**Response 200:**

```json
[
  {
    "id": "uuid",
    "name": "MacBook Pro Matt",
    "platform": "desktop",
    "last_seen_at": "2026-10-21T12:00:00Z",
    "created_at": "2026-10-20T10:00:00Z"
  }
]
```

### `DELETE /devices/{id}`

Revoke a device and all its refresh tokens.

**Response 204:** no body.

**Errors:** `404 device_not_found`.

## Sync

### `POST /sync`

Push local changes to the server. Applies changes with matching
`base_version`; returns conflicts for stale versions.

**Request:**

```json
{
  "changes": [
    {
      "id": "uuid",
      "encrypted_blob": "<base64>",
      "base_version": 0,
      "deleted": false
    }
  ]
}
```

Limits: 500 changes per request, 64 KB per blob, no duplicate IDs.

**Response 200:**

```json
{
  "applied": ["uuid1", "uuid2"],
  "conflicts": [{ "id": "uuid3", "server_version": 5 }],
  "new_revision": 42
}
```

**Errors:** `400` validation, `401` unauthorized.

### `GET /sync?since=N`

Pull all items changed after revision `N`.

**Query params:**

- `since` — integer, default `0`

**Response 200:**

```json
{
  "items": [
    {
      "id": "uuid",
      "encrypted_blob": "<base64>",
      "version": 3,
      "deleted": false
    }
  ],
  "new_revision": 42
}
```

## WebSocket

### `GET /ws?token=<access_token>`

Real-time sync notifications.

**Message from server:**

```json
{ "type": "sync", "revision": 42 }
```

Client should trigger `GET /sync?since=<last_revision>` on receipt.
Sender's own device is excluded from broadcast.

**Ping/pong:** server pings every 30 seconds. Client must respond (automatic
per WebSocket protocol).

**Close codes:**

- `1000` — normal closure (server shutting down or client disconnected)
- `1008` — policy violation (invalid token)
