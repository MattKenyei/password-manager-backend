package testutil

import (
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

	_, err := pool.Exec(context.Background(), `
		INSERT INTO users (id, email, auth_verifier, auth_salt, enc_salt, kdf_params, wrapped_account_key)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`, id, email,
		[]byte{0x01},
		[]byte{0x02, 0x03, 0x04, 0x05},
		[]byte{0x06, 0x07, 0x08, 0x09},
		[]byte(`{"algo":"argon2id"}`),
		[]byte("wrapped"),
	)
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}

	_, err = pool.Exec(context.Background(),
		`INSERT INTO user_revisions (user_id, current_revision) VALUES ($1, 0)`, id)
	if err != nil {
		t.Fatalf("seed user_revisions: %v", err)
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
