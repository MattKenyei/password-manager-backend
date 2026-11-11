package storage

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/MattKenyei/password-manager-backend/internal/domain"
)

var (
	ErrEmailExists  = errors.New("email already exists")
	ErrUserNotFound = errors.New("user not found")
)

type UserRepository struct {
	pool *pgxpool.Pool
}

func NewUserRepository(pool *pgxpool.Pool) *UserRepository {
	return &UserRepository{pool: pool}
}

func (r *UserRepository) Create(ctx context.Context, u *domain.User) error {
	const query = `
		INSERT INTO users (
			email, auth_verifier, auth_salt, enc_salt, kdf_params, wrapped_account_key
		)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id, key_generation, created_at, updated_at
	`

	err := r.pool.QueryRow(
		ctx, query,
		u.Email, u.AuthVerifier, u.AuthSalt, u.EncSalt, u.KDFParams, u.WrappedAccountKey,
	).Scan(&u.ID, &u.KeyGeneration, &u.CreatedAt, &u.UpdatedAt)
	if err != nil {
		if isUniqueViolation(err) {
			return ErrEmailExists
		}
		return fmt.Errorf("insert user: %w", err)
	}

	return nil
}

func (r *UserRepository) FindByEmail(ctx context.Context, email string) (*domain.User, error) {
	const query = `
		SELECT id, email, auth_verifier, auth_salt, enc_salt, kdf_params,
		       wrapped_account_key, key_generation, created_at, updated_at
		FROM users
		WHERE email = $1
	`
	var u domain.User

	err := r.pool.QueryRow(ctx, query, email).Scan(
		&u.ID, &u.Email, &u.AuthVerifier, &u.AuthSalt, &u.EncSalt, &u.KDFParams, &u.WrappedAccountKey, &u.KeyGeneration, &u.CreatedAt, &u.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("find user by email: %w", err)
	}
	return &u, nil
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

func (r *UserRepository) UpdateAuthVerifier(ctx context.Context, userID uuid.UUID, verifier []byte) error {
	tag, err := r.pool.Exec(ctx,
		`UPDATE users SET auth_verifier = $1, updated_at = NOW() WHERE id = $2`, verifier, userID)
	if err != nil {
		return fmt.Errorf("update auth verifier: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrUserNotFound
	}
	return nil
}

func (r *UserRepository) RevokeAllRefreshTokens(ctx context.Context, userID uuid.UUID) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE refresh_tokens SET revoked_at = NOW() WHERE user_id = $1 AND revoked_at IS NULL`, userID)
	return err
}
