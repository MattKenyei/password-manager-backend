package storage

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var ErrRefreshTokenInvalid = errors.New("refresh token invalid")

type RefreshTokenRepository struct {
	pool *pgxpool.Pool
}

func NewRefreshTokenRepository(pool *pgxpool.Pool) *RefreshTokenRepository {
	return &RefreshTokenRepository{pool: pool}
}

type RefreshToken struct {
	ID        uuid.UUID
	UserID    uuid.UUID
	DeviceID  uuid.UUID
	TokenHash []byte
	ExpiresAt time.Time
	UsedAt    *time.Time
	RevokedAt *time.Time
}

func (r *RefreshTokenRepository) Create(ctx context.Context, userID, deviceID uuid.UUID, tokenHash []byte, expiresAt time.Time) error {
	const query = `
		INSERT INTO refresh_tokens (user_id, device_id, token_hash, expires_at)
		VALUES ($1, $2, $3, $4)
	`
	_, err := r.pool.Exec(ctx, query, userID, deviceID, tokenHash, expiresAt)
	if err != nil {
		return fmt.Errorf("insert refresh token: %w", err)
	}
	return nil
}

func (r *RefreshTokenRepository) FindByHash(ctx context.Context, hash []byte) (*RefreshToken, error) {
	const query = `
		SELECT id, user_id, device_id, token_hash, expires_at, used_at, revoked_at
		FROM refresh_tokens
		WHERE token_hash = $1
		  AND revoked_at IS NULL
		  AND used_at IS NULL
		  AND expires_at > NOW()
	`
	var t RefreshToken
	err := r.pool.QueryRow(ctx, query, hash).Scan(
		&t.ID, &t.UserID, &t.DeviceID, &t.TokenHash, &t.ExpiresAt, &t.UsedAt, &t.RevokedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrRefreshTokenInvalid
		}
		return nil, fmt.Errorf("find refresh token: %w", err)
	}
	return &t, nil
}

func (r *RefreshTokenRepository) FindByHashUnsafely(ctx context.Context, hash []byte) (*RefreshToken, error) {
	const query = `
		SELECT id, user_id, device_id, token_hash, expires_at, used_at, revoked_at
		FROM refresh_tokens
		WHERE token_hash = $1
	`
	var t RefreshToken
	err := r.pool.QueryRow(ctx, query, hash).Scan(
		&t.ID, &t.UserID, &t.DeviceID, &t.TokenHash, &t.ExpiresAt, &t.UsedAt, &t.RevokedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrRefreshTokenInvalid
		}
		return nil, fmt.Errorf("find refresh token: %w", err)
	}
	return &t, nil
}

func (r *RefreshTokenRepository) MarkUsed(ctx context.Context, id uuid.UUID) error {
	const query = `UPDATE refresh_tokens SET used_at = NOW() WHERE id = $1`
	_, err := r.pool.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("mark token used: %w", err)
	}
	return nil
}

func (r *RefreshTokenRepository) RevokeDeviceTokens(ctx context.Context, deviceID uuid.UUID) error {
	const query = `
		UPDATE refresh_tokens
		SET revoked_at = NOW()
		WHERE device_id = $1 AND revoked_at IS NULL
	`
	_, err := r.pool.Exec(ctx, query, deviceID)
	if err != nil {
		return fmt.Errorf("revoke device tokens: %w", err)
	}
	return nil
}
