package testutil

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pressly/goose/v3"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
)

func applyMigrations(dsn string) error {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return err
	}
	defer db.Close()

	if err := goose.SetDialect("postgres"); err != nil {
		return err
	}
	goose.SetLogger(goose.NopLogger())

	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		return errors.New("cannot resolve runtime caller")
	}
	migrationsDir := filepath.Join(filepath.Dir(currentFile), "..", "..", "migrations")

	return goose.Up(db, migrationsDir)
}

func StartPostgres() (*pgxpool.Pool, func(), error) {
	ctx := context.Background()

	ctr, err := postgres.Run(ctx,
		"postgres:17-alpine",
		postgres.WithDatabase("test"),
		postgres.WithUsername("test"),
		postgres.WithPassword("test"),
		postgres.BasicWaitStrategies(),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("start postgres container: %w", err)
	}

	cleanupContainer := func() { _ = testcontainers.TerminateContainer(ctr) }

	dsn, err := ctr.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		cleanupContainer()
		return nil, nil, fmt.Errorf("get dsn: %w", err)
	}

	if err := applyMigrations(dsn); err != nil {
		cleanupContainer()
		return nil, nil, fmt.Errorf("apply migrations: %w", err)
	}

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		cleanupContainer()
		return nil, nil, fmt.Errorf("connect pool: %w", err)
	}

	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
		pool.Close()
		cleanupContainer()
		return nil, nil, fmt.Errorf("ping postgres: %w", err)
	}

	return pool, func() {
		pool.Close()
		cleanupContainer()
	}, nil
}

func TruncateAll(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), `TRUNCATE TABLE users CASCADE`); err != nil {
		t.Fatalf("truncate: %v", err)
	}
}

func SeedUserWithPassword(t *testing.T, pool *pgxpool.Pool, email string, authKey []byte) uuid.UUID {
	t.Helper()

	if len(authKey) != 32 {
		t.Fatalf("authKey must be 32 bytes, got %d", len(authKey))
	}

	sum := sha256.Sum256(authKey)
	id := uuid.New()

	_, err := pool.Exec(context.Background(), `
		INSERT INTO users (id, email, auth_verifier, auth_salt, enc_salt, kdf_params, wrapped_account_key)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`, id, email,
		sum[:],
		[]byte{0x02, 0x03, 0x04, 0x05},
		[]byte{0x06, 0x07, 0x08, 0x09},
		[]byte(`{"algo":"argon2id"}`),
		bytes.Repeat([]byte{0xFF}, 80),
	)
	if err != nil {
		t.Fatalf("seed user with password: %v", err)
	}

	return id
}
