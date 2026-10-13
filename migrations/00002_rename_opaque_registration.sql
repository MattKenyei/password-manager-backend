-- +goose Up
-- +goose StatementBegin
ALTER TABLE users RENAME COLUMN opaque_registration TO auth_verifier;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE users RENAME COLUMN auth_verifier TO opaque_registration;
-- +goose StatementEnd