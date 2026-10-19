package storage

import (
	"context"
	"errors"
	"fmt"

	"github.com/MattKenyei/password-manager-backend/internal/domain"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type ItemRepository struct {
	pool *pgxpool.Pool
}

func NewItemRepository(pool *pgxpool.Pool) *ItemRepository {
	return &ItemRepository{pool: pool}
}

func (r *ItemRepository) PushChanges(ctx context.Context, userID uuid.UUID, changes []domain.Change) (*domain.PushResult, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}

	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx,
		`INSERT INTO user_revisions (user_id, current_revision)
		 VALUES ($1, 0)
		 ON CONFLICT (user_id) DO NOTHING`, userID); err != nil {
		return nil, fmt.Errorf("ensure user_revisions: %w", err)
	}

	var currentRev int64
	if err := tx.QueryRow(ctx,
		`SELECT current_revision FROM user_revisions WHERE user_id = $1 FOR UPDATE`,
		userID).Scan(&currentRev); err != nil {
		return nil, fmt.Errorf("lock user_revisions: %w", err)
	}

	result := &domain.PushResult{
		Applied:   make([]uuid.UUID, 0, len(changes)),
		Conflicts: make([]domain.Conflict, 0),
	}

	for _, c := range changes {
		var serverVersion int64

		err := tx.QueryRow(ctx,
			`SELECT version FROM items WHERE user_id = $1 AND id = $2`,
			userID, c.ID).Scan(&serverVersion)
		var exists bool
		switch {
		case err == nil:
			exists = true
		case errors.Is(err, pgx.ErrNoRows):
			exists = false
			serverVersion = 0
		default:
			return nil, fmt.Errorf("select item version: %w", err)
		}

		if c.BaseVersion != serverVersion {
			result.Conflicts = append(result.Conflicts, domain.Conflict{
				ID:            c.ID,
				ServerVersion: serverVersion,
			})
			continue
		}

		newVersion := serverVersion + 1
		currentRev++
		if exists {
			if _, err := tx.Exec(ctx,
				`UPDATE items
				 SET encrypted_blob = $1,
				     version = $2,
				     global_revision = $3,
				     deleted = $4,
				     updated_at = NOW()
				 WHERE user_id = $5 AND id = $6`,
				c.EncryptedBlob, newVersion, currentRev, c.Deleted, userID, c.ID); err != nil {
				return nil, fmt.Errorf("update item: %w", err)
			}
		} else {
			if _, err := tx.Exec(ctx,
				`INSERT INTO items (id, user_id, encrypted_blob, version, global_revision, deleted)
				 VALUES ($1, $2, $3, $4, $5, $6)`,
				c.ID, userID, c.EncryptedBlob, newVersion, currentRev, c.Deleted); err != nil {
				return nil, fmt.Errorf("insert item: %w", err)
			}
		}
		result.Applied = append(result.Applied, c.ID)
	}

	if _, err := tx.Exec(ctx,
		`UPDATE user_revisions SET current_revision = $1 WHERE user_id = $2`,
		currentRev, userID); err != nil {
		return nil, fmt.Errorf("bump user revision: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit: %w", err)
	}

	result.NewRevision = currentRev
	return result, nil
}

func (r *ItemRepository) GetChangesSince(ctx context.Context, userID uuid.UUID, since int64) ([]domain.Item, int64, error) {
	var serverRev int64
	err := r.pool.QueryRow(ctx,
		`SELECT COALESCE(current_revision, 0) FROM user_revisions WHERE user_id = $1`,
		userID).Scan(&serverRev)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return []domain.Item{}, 0, nil
		}
		return nil, 0, fmt.Errorf("read current revision: %w", err)
	}

	if since >= serverRev {
		return []domain.Item{}, serverRev, nil
	}

	rows, err := r.pool.Query(ctx,
		`SELECT id, user_id, encrypted_blob, version, global_revision, deleted, updated_at, created_at
		 FROM items
		 WHERE user_id = $1 AND global_revision > $2 AND global_revision <= $3
		 ORDER BY global_revision`,
		userID, since, serverRev)
	if err != nil {
		return nil, 0, fmt.Errorf("query items: %w", err)
	}
	defer rows.Close()

	var items []domain.Item
	for rows.Next() {
		var it domain.Item

		if err := rows.Scan(
			&it.ID, &it.UserID, &it.EncryptedBlob, &it.Version,
			&it.GlobalRevision, &it.Deleted, &it.UpdatedAt, &it.CreatedAt,
		); err != nil {
			return nil, 0, fmt.Errorf("scanItem: %w", err)
		}
		items = append(items, it)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("iterate items: %w", err)
	}

	if items == nil {
		items = []domain.Item{}
	}

	return items, serverRev, nil
}
