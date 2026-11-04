package storage_test

import (
	"sync"
	"testing"

	"github.com/google/uuid"

	"github.com/MattKenyei/password-manager-backend/internal/domain"
	"github.com/MattKenyei/password-manager-backend/internal/storage"
	"github.com/MattKenyei/password-manager-backend/internal/testutil"
)

func TestPushChanges_CreateNewItem(t *testing.T) {
	pool := setupTest(t)
	repo := storage.NewItemRepository(pool)
	user := testutil.SeedUser(t, pool, "create@example.com")

	itemID := uuid.New()
	blob := []byte("encrypted-blob-v1")

	result, err := repo.PushChanges(testCtx, user.ID, []domain.Change{
		{ID: itemID, EncryptedBlob: blob, BaseVersion: 0},
	})
	if err != nil {
		t.Fatalf("push: %v", err)
	}

	if len(result.Applied) != 1 || result.Applied[0] != itemID {
		t.Fatalf("applied: %+v", result.Applied)
	}
	if len(result.Conflicts) != 0 {
		t.Fatalf("unexpected conflicts: %+v", result.Conflicts)
	}
	if result.NewRevision != 1 {
		t.Fatalf("new_revision: want 1, got %d", result.NewRevision)
	}

	var version, globalRev int64
	var deleted bool
	if err := pool.QueryRow(testCtx,
		`SELECT version, global_revision, deleted FROM items WHERE user_id = $1 AND id = $2`,
		user.ID, itemID,
	).Scan(&version, &globalRev, &deleted); err != nil {
		t.Fatalf("query item: %v", err)
	}
	if version != 1 {
		t.Errorf("version: want 1, got %d", version)
	}
	if globalRev != 1 {
		t.Errorf("global_revision: want 1, got %d", globalRev)
	}
	if deleted {
		t.Error("deleted should be false")
	}
}

func TestPushChanges_UpdateExistingItem(t *testing.T) {
	pool := setupTest(t)
	repo := storage.NewItemRepository(pool)
	user := testutil.SeedUser(t, pool, "update@example.com")
	itemID := uuid.New()

	_, err := repo.PushChanges(testCtx, user.ID, []domain.Change{
		{ID: itemID, EncryptedBlob: []byte("v1"), BaseVersion: 0},
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	result, err := repo.PushChanges(testCtx, user.ID, []domain.Change{
		{ID: itemID, EncryptedBlob: []byte("v2"), BaseVersion: 1},
	})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if len(result.Applied) != 1 {
		t.Fatalf("applied: want 1, got %d", len(result.Applied))
	}

	var version int64
	if err := pool.QueryRow(testCtx,
		`SELECT version FROM items WHERE user_id = $1 AND id = $2`,
		user.ID, itemID,
	).Scan(&version); err != nil {
		t.Fatalf("query: %v", err)
	}
	if version != 2 {
		t.Errorf("version: want 2, got %d", version)
	}
}

func TestPushChanges_ConflictStaleVersion(t *testing.T) {
	pool := setupTest(t)
	repo := storage.NewItemRepository(pool)
	user := testutil.SeedUser(t, pool, "conflict@example.com")
	itemID := uuid.New()

	_, err := repo.PushChanges(testCtx, user.ID, []domain.Change{
		{ID: itemID, EncryptedBlob: []byte("v1"), BaseVersion: 0},
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	_, err = repo.PushChanges(testCtx, user.ID, []domain.Change{
		{ID: itemID, EncryptedBlob: []byte("v2"), BaseVersion: 1},
	})
	if err != nil {
		t.Fatalf("update: %v", err)
	}

	result, err := repo.PushChanges(testCtx, user.ID, []domain.Change{
		{ID: itemID, EncryptedBlob: []byte("stale"), BaseVersion: 1},
	})
	if err != nil {
		t.Fatalf("push: %v", err)
	}
	if len(result.Applied) != 0 {
		t.Fatalf("applied: want 0, got %d", len(result.Applied))
	}
	if len(result.Conflicts) != 1 {
		t.Fatalf("conflicts: want 1, got %d", len(result.Conflicts))
	}
	if result.Conflicts[0].ServerVersion != 2 {
		t.Errorf("server_version: want 2, got %d", result.Conflicts[0].ServerVersion)
	}

	var version int64
	var blob []byte
	if err := pool.QueryRow(testCtx,
		`SELECT version, encrypted_blob FROM items WHERE user_id = $1 AND id = $2`,
		user.ID, itemID,
	).Scan(&version, &blob); err != nil {
		t.Fatalf("query: %v", err)
	}
	if version != 2 {
		t.Errorf("version changed! want 2, got %d", version)
	}
	if string(blob) != "v2" {
		t.Errorf("blob changed! want v2, got %s", blob)
	}
}

func TestPushChanges_BatchPartialSuccess(t *testing.T) {
	pool := setupTest(t)
	repo := storage.NewItemRepository(pool)
	user := testutil.SeedUser(t, pool, "batch@example.com")

	existingID := uuid.New()
	newID := uuid.New()

	_, _ = repo.PushChanges(testCtx, user.ID, []domain.Change{
		{ID: existingID, EncryptedBlob: []byte("v1"), BaseVersion: 0},
	})
	_, _ = repo.PushChanges(testCtx, user.ID, []domain.Change{
		{ID: existingID, EncryptedBlob: []byte("v2"), BaseVersion: 1},
	})

	result, err := repo.PushChanges(testCtx, user.ID, []domain.Change{
		{ID: existingID, EncryptedBlob: []byte("v3"), BaseVersion: 2},
		{ID: newID, EncryptedBlob: []byte("new"), BaseVersion: 0},
		{ID: existingID, EncryptedBlob: []byte("stale"), BaseVersion: 1},
	})
	if err != nil {
		t.Fatalf("push: %v", err)
	}

	if len(result.Applied) != 2 {
		t.Errorf("applied: want 2, got %d", len(result.Applied))
	}
	if len(result.Conflicts) != 1 {
		t.Errorf("conflicts: want 1, got %d", len(result.Conflicts))
	}
	if result.NewRevision != 4 {
		t.Errorf("new_revision: want 4, got %d", result.NewRevision)
	}
}

func TestPushChanges_ConcurrentDistinctRevisions(t *testing.T) {
	pool := setupTest(t)
	repo := storage.NewItemRepository(pool)
	user := testutil.SeedUser(t, pool, "concurrent@example.com")

	const N = 5
	start := make(chan struct{})
	var wg sync.WaitGroup

	type res struct {
		revision int64
		err      error
	}
	results := make(chan res, N)

	for i := 0; i < N; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			id := uuid.New()
			r, err := repo.PushChanges(testCtx, user.ID, []domain.Change{
				{ID: id, EncryptedBlob: []byte("blob"), BaseVersion: 0},
			})
			if err != nil {
				results <- res{err: err}
				return
			}
			results <- res{revision: r.NewRevision}
		}()
	}

	close(start)
	wg.Wait()
	close(results)

	seen := map[int64]bool{}
	for r := range results {
		if r.err != nil {
			t.Fatalf("push error: %v", r.err)
		}
		if seen[r.revision] {
			t.Fatalf("duplicate revision %d — SELECT FOR UPDATE is broken", r.revision)
		}
		seen[r.revision] = true
	}

	var current int64
	if err := pool.QueryRow(testCtx,
		`SELECT current_revision FROM user_revisions WHERE user_id = $1`, user.ID,
	).Scan(&current); err != nil {
		t.Fatalf("query current: %v", err)
	}
	if current != N {
		t.Errorf("current_revision: want %d, got %d (lost updates?)", N, current)
	}

	rows, err := pool.Query(testCtx,
		`SELECT global_revision FROM items WHERE user_id = $1`, user.ID)
	if err != nil {
		t.Fatalf("query items: %v", err)
	}
	defer rows.Close()

	globalRevs := map[int64]bool{}
	count := 0
	for rows.Next() {
		var gr int64
		if err := rows.Scan(&gr); err != nil {
			t.Fatalf("scan: %v", err)
		}
		if globalRevs[gr] {
			t.Fatalf("duplicate global_revision %d in DB", gr)
		}
		globalRevs[gr] = true
		count++
	}
	if count != N {
		t.Errorf("expected %d items, got %d", N, count)
	}
}

func TestGetChangesSince(t *testing.T) {
	pool := setupTest(t)
	repo := storage.NewItemRepository(pool)
	user := testutil.SeedUser(t, pool, "pull@example.com")

	id1, id2 := uuid.New(), uuid.New()
	_, _ = repo.PushChanges(testCtx, user.ID, []domain.Change{
		{ID: id1, EncryptedBlob: []byte("a"), BaseVersion: 0},
	})
	_, _ = repo.PushChanges(testCtx, user.ID, []domain.Change{
		{ID: id2, EncryptedBlob: []byte("b"), BaseVersion: 0},
	})

	items, rev, err := repo.GetChangesSince(testCtx, user.ID, 0)
	if err != nil {
		t.Fatalf("since 0: %v", err)
	}
	if len(items) != 2 || rev != 2 {
		t.Errorf("since 0: want 2 items, rev 2, got %d/%d", len(items), rev)
	}

	items, rev, err = repo.GetChangesSince(testCtx, user.ID, 1)
	if err != nil {
		t.Fatalf("since 1: %v", err)
	}
	if len(items) != 1 || items[0].ID != id2 {
		t.Errorf("since 1: want only id2")
	}

	items, rev, err = repo.GetChangesSince(testCtx, user.ID, 2)
	if err != nil {
		t.Fatalf("since 2: %v", err)
	}
	if len(items) != 0 {
		t.Errorf("since 2: want empty, got %d", len(items))
	}
	if rev != 2 {
		t.Errorf("since 2: revision want 2, got %d", rev)
	}
}
