package storage

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Device struct {
	ID         uuid.UUID
	UserID     uuid.UUID
	Name       string
	Platform   string
	LastSeenAt time.Time
	CreatedAt  time.Time
}

type DeviceRepository struct {
	pool *pgxpool.Pool
}

var ErrDeviceNotFound = errors.New("device not found")

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

func (r *DeviceRepository) ListByUser(ctx context.Context, userID uuid.UUID) ([]Device, error) {
	const query = `
		SELECT id, user_id, name, platform, last_seen_at, created_at
		FROM devices
		WHERE user_id = $1 AND revoked_at IS NULL
		ORDER BY last_seen_at DESC
	`
	rows, err := r.pool.Query(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("list devices: %w", err)
	}
	defer rows.Close()

	var devices []Device
	for rows.Next() {
		var d Device
		if err := rows.Scan(&d.ID, &d.UserID, &d.Name, &d.Platform, &d.LastSeenAt, &d.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan device: %w", err)
		}
		devices = append(devices, d)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate device: %w", err)
	}
	return devices, nil
}

func (r *DeviceRepository) Revoke(ctx context.Context, userID, deviceID uuid.UUID) error {
	const query = `
		UPDATE devices
		SET revoked_at = NOW()
		WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL
	`
	tag, err := r.pool.Exec(ctx, query, deviceID, userID)
	if err != nil {
		return fmt.Errorf("revoke device: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrDeviceNotFound
	}
	return nil
}
