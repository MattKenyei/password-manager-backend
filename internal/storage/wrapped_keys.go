package storage

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type WrappedKey struct {
	ID           uuid.UUID
	UserID       uuid.UUID
	Kind         string
	CredentialID []byte
	WrappedBlob  []byte
}

type WrappedKeyRepository struct {
	pool *pgxpool.Pool
}

func NewWrappedKeyRepository(pool *pgxpool.Pool) *WrappedKeyRepository {
	return &WrappedKeyRepository{pool: pool}
}

func (r *WrappedKeyRepository) CreateMany(ctx context.Context, keys []WrappedKey) error {
	for _, k := range keys {
		_, err := r.pool.Exec(ctx,
			`INSERT INTO wrapped_keys (user_id, kind, credential_id, wrapped_blob)
			 VALUES ($1, $2, $3, $4)
			 ON CONFLICT (user_id, kind, credential_id) DO UPDATE
			 SET wrapped_blob = EXCLUDED.wrapped_blob`,
			k.UserID, k.Kind, k.CredentialID, k.WrappedBlob,
		)
		if err != nil {
			return fmt.Errorf("insert wrapped key: %w", err)
		}
	}
	return nil
}

func (r *WrappedKeyRepository) ListByUser(ctx context.Context, userID uuid.UUID) ([]WrappedKey, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT id, user_id, kind, credential_id, wrapped_blob FROM wrapped_keys WHERE user_id = $1 ORDER BY created_at`, userID)
	if err != nil {
		return nil, fmt.Errorf("list wrapped keys: %w", err)
	}
	defer rows.Close()

	var out []WrappedKey
	for rows.Next() {
		var k WrappedKey
		if err := rows.Scan(&k.ID, &k.UserID, &k.Kind, &k.CredentialID, &k.WrappedBlob); err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

func (r *WrappedKeyRepository) DeleteByKind(ctx context.Context, userID uuid.UUID, kind string) error {
	_, err := r.pool.Exec(ctx, `DELETE FROM wrapped_keys WHERE user_id = $1 AND kind = $2`, userID, kind)
	return err
}
