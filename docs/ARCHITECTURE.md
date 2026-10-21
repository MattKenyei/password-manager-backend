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

## Cryptographic model

_TODO: describe Argon2id derivation, master_key → account_key → item_key chain, encryption scheme (XChaCha20-Poly1305 with per-item nonce), key wrapping._

## Backend layers

_TODO: describe the layered structure — cmd → api → domain/storage/crypto. Dependency injection via constructors. Why no ORM._

## Data model

_TODO: describe tables — users, devices, refresh_tokens, items, user_revisions. Why UUIDs, why CITEXT, why TIMESTAMPTZ, why tombstones._

## Sync protocol

_TODO: describe push/pull flow, monotonic revisions, optimistic locking via base_version, conflict detection and resolution, why client-generated UUIDs, idempotency considerations._

## Real-time notifications

_TODO: describe WebSocket hub pattern, two-goroutine-per-connection, ping/pong heartbeat, drop-on-full backpressure, multi-instance scaling via Redis Pub/Sub._

## Multi-device enrollment

_TODO: describe QR-based enrollment, ephemeral X25519 key exchange, the trust relationship between devices._

## Key rotation

_TODO: describe account_key rotation on device compromise, re-encryption of all items, distribution of new wrapped keys to trusted devices._
