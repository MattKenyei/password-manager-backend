-- +goose Up
-- +goose StatementBegin
CREATE TABLE items (
    id               UUID NOT NULL,
    user_id          UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    encrypted_blob   BYTEA NOT NULL,
    version          BIGINT NOT NULL DEFAULT 1,
    global_revision  BIGINT NOT NULL DEFAULT 0,
    deleted          BOOLEAN NOT NULL DEFAULT FALSE,
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, id)
);

CREATE INDEX idx_items_user_global_rev ON items(user_id, global_revision);

CREATE TABLE user_revisions (
    user_id          UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    current_revision BIGINT NOT NULL DEFAULT 0
);

INSERT INTO user_revisions (user_id, current_revision)
SELECT id, 0 FROM users
ON CONFLICT (user_id) DO NOTHING;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS user_revisions;
DROP TABLE IF EXISTS items;
-- +goose StatementEnd