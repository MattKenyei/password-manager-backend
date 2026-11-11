-- +goose Up
-- +goose StatementBegin
CREATE TABLE wrapped_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    kind TEXT NOT NULL CHECK (kind IN ('master', 'recovery', 'passkey')),
    credential_id BYTEA,
    wrapped_blob BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(user_id, kind, credential_id)
);

CREATE INDEX idx_wrapped_keys_user ON wrapped_keys(user_id);

INSERT INTO wrapped_keys (user_id, kind, wrapped_blob)
SELECT id, 'master', wrapped_account_key FROM users WHERE wrapped_account_key IS NOT NULL;

ALTER TABLE users DROP COLUMN wrapped_account_key;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE users ADD COLUMN wrapped_account_key BYTEA;
UPDATE users u SET wrapped_account_key = (
    SELECT wrapped_blob FROM wrapped_keys w WHERE w.user_id = u.id AND w.kind = 'master'
);
DROP TABLE wrapped_keys;
-- +goose StatementEnd