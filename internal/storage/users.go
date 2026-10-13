package storage

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/MattKenyei/password-manager-backend/internal/domain"
)

var ErrEmailExists = errors.New("email already exists")

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

	err := r.pool.QueryRow(ctx, query,
		u.Email, u.AuthVerifier, u.AuthSalt, u.EncSalt, u.KDFParams, u.WrappedAccountKey,
	).Scan(&u.ID, &u.KeyGeneration, &u.CreatedAt, &u.UpdatedAt)

	if err != nil {
		// Проверяем, не уникальный ли ключ нарушен.
		// pgx умеет распознавать constraint violations.
		if isUniqueViolation(err) {
			return ErrEmailExists
		}
		return fmt.Errorf("insert user: %w", err)
	}

	return nil
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}