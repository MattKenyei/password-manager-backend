package storage

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type DeviceRepository struct {
	pool *pgxpool.Pool
}

func NewDeviceRepository(pool *pgxpool.Pool) *DeviceRepository {
	return &DeviceRepository{pool: pool}
}

func (r *DeviceRepository) Upsert(ctx context.Context, id, UserID uuid.UUID, name, platform string) error {
	const query = `
		INSERT INTO devices (id, user_id, name, platform)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (id) DO UPDATE
		SET name = EXCLUDED.name,
			platform = EXCLUDED.platform,
			last_seen_at = NOW()
	`
	_, err := r.pool.Exec(ctx, query, id, UserID, name, platform)
	if err != nil {
		return fmt.Errorf("upset device: %w", err)
	}
	return nil
}
