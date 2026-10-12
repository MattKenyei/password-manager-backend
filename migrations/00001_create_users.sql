-- +goose Up
-- +goose StatementBegin
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "citext";

CREATE TABLE users (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email                 CITEXT NOT NULL UNIQUE,
    opaque_registration   BYTEA NOT NULL,
    auth_salt             BYTEA NOT NULL,
    enc_salt              BYTEA NOT NULL,
    kdf_params            JSONB NOT NULL,
    wrapped_account_key   BYTEA NOT NULL,
    key_generation        INT NOT NULL DEFAULT 1,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS users;
-- +goose StatementEnd