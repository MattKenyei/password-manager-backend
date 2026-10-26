-- +goose Up
-- +goose StatementBegin
CREATE TABLE audit_logs (
    id           BIGSERIAL PRIMARY KEY,
    user_id      UUID REFERENCES users(id) ON DELETE SET NULL,
    device_id    UUID,
    event_type   TEXT NOT NULL,
    result       TEXT NOT NULL,
    ip           TEXT,
    user_agent   TEXT,
    metadata     JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_audit_logs_user_time ON audit_logs(user_id, created_at DESC);
CREATE INDEX idx_audit_logs_event_time ON audit_logs(event_type, created_at DESC);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS audit_logs;
-- +goose StatementEnd