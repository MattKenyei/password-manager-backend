package testutil

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type seedUser struct {
	ID    uuid.UUID
	Email string
}

func SeedUser(t *testing.T, pool *pgxpool.Pool, email string) seedUser {
	t.Helper()
	id := uuid.New()

	tx, err := pool.Begin(context.Background())
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	defer tx.Rollback(context.Background())

	_, err = tx.Exec(context.Background(), `
		INSERT INTO users (id, email, auth_verifier, auth_salt, enc_salt, kdf_params)
		VALUES ($1, $2, $3, $4, $5, $6)
	`, id, email,
		[]byte{0x01},
		[]byte{0x02, 0x03, 0x04, 0x05},
		[]byte{0x06, 0x07, 0x08, 0x09},
		[]byte(`{"algo":"argon2id"}`),
	)
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}

	_, err = tx.Exec(context.Background(), `
		INSERT INTO wrapped_keys (user_id, kind, wrapped_blob)
		VALUES ($1, 'master', $2)
	`, id, bytes.Repeat([]byte{0xFF}, 80))
	if err != nil {
		t.Fatalf("seed wrapped key: %v", err)
	}

	_, err = tx.Exec(context.Background(), `
		INSERT INTO user_revisions (user_id, current_revision) VALUES ($1, 0)
	`, id)
	if err != nil {
		t.Fatalf("seed user_revisions: %v", err)
	}

	if err := tx.Commit(context.Background()); err != nil {
		t.Fatalf("commit: %v", err)
	}

	return seedUser{ID: id, Email: email}
}

func SeedDevice(t *testing.T, pool *pgxpool.Pool, userID uuid.UUID, name string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	_, err := pool.Exec(context.Background(),
		`INSERT INTO devices (id, user_id, name, platform) VALUES ($1, $2, $3, $4)`,
		id, userID, name, "test")
	if err != nil {
		t.Fatalf("seed device: %v", err)
	}
	return id
}

func SeedRefreshToken(
	t *testing.T,
	pool *pgxpool.Pool,
	userID, deviceID uuid.UUID,
	tokenHash []byte,
	expiresAt time.Time,
) uuid.UUID {
	t.Helper()
	id := uuid.New()
	_, err := pool.Exec(context.Background(), `
		INSERT INTO refresh_tokens (id, user_id, device_id, token_hash, expires_at)
		VALUES ($1, $2, $3, $4, $5)
	`, id, userID, deviceID, tokenHash, expiresAt)
	if err != nil {
		t.Fatalf("seed refresh token: %v", err)
	}
	return id
}
