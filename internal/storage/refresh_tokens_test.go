package storage_test

import (
	"errors"
	"testing"
	"time"

	"github.com/MattKenyei/password-manager-backend/internal/storage"
	"github.com/MattKenyei/password-manager-backend/internal/testutil"
)

func TestRefreshToken_CreateAndFind(t *testing.T) {
	pool := setupTest(t)
	repo := storage.NewRefreshTokenRepository(pool)
	user := testutil.SeedUser(t, pool, "rt-create@example.com")
	deviceID := testutil.SeedDevice(t, pool, user.ID, "dev-1")

	hash := []byte("hash-32-bytes-long!!!!!!!!!!!!!!!")
	expires := time.Now().Add(24 * time.Hour)

	if err := repo.Create(testCtx, user.ID, deviceID, hash, expires); err != nil {
		t.Fatalf("create: %v", err)
	}

	tok, err := repo.FindByHash(testCtx, hash)
	if err != nil {
		t.Fatalf("find: %v", err)
	}
	if tok.UserID != user.ID {
		t.Error("user_id mismatch")
	}
	if tok.DeviceID != deviceID {
		t.Error("device_id mismatch")
	}
	if tok.UsedAt != nil {
		t.Error("used_at should be nil")
	}
}

func TestRefreshToken_Rotation(t *testing.T) {
	pool := setupTest(t)
	repo := storage.NewRefreshTokenRepository(pool)
	user := testutil.SeedUser(t, pool, "rt-rotate@example.com")
	deviceID := testutil.SeedDevice(t, pool, user.ID, "dev-1")

	hash := []byte("hash-32-bytes-long!!!!!!!!!!!!!!!")
	_ = repo.Create(testCtx, user.ID, deviceID, hash, time.Now().Add(time.Hour))

	tok, _ := repo.FindByHash(testCtx, hash)
	if err := repo.MarkUsed(testCtx, tok.ID); err != nil {
		t.Fatalf("mark used: %v", err)
	}

	_, err := repo.FindByHash(testCtx, hash)
	if !errors.Is(err, storage.ErrRefreshTokenInvalid) {
		t.Errorf("expected ErrRefreshTokenInvalid, got %v", err)
	}

	unsafe, err := repo.FindByHashUnsafely(testCtx, hash)
	if err != nil {
		t.Fatalf("find unsafely: %v", err)
	}
	if unsafe.UsedAt == nil {
		t.Error("used_at should be set")
	}
}

func TestRefreshToken_RevokeDeviceTokens(t *testing.T) {
	pool := setupTest(t)
	repo := storage.NewRefreshTokenRepository(pool)
	user := testutil.SeedUser(t, pool, "rt-revoke@example.com")
	deviceID := testutil.SeedDevice(t, pool, user.ID, "dev-1")

	h1 := []byte("hash-one-32-bytes-long!!!!!!!!!!!")
	h2 := []byte("hash-two-32-bytes-long!!!!!!!!!!!")
	_ = repo.Create(testCtx, user.ID, deviceID, h1, time.Now().Add(time.Hour))
	_ = repo.Create(testCtx, user.ID, deviceID, h2, time.Now().Add(time.Hour))

	if err := repo.RevokeDeviceTokens(testCtx, deviceID); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	for _, h := range [][]byte{h1, h2} {
		if _, err := repo.FindByHash(testCtx, h); !errors.Is(err, storage.ErrRefreshTokenInvalid) {
			t.Errorf("revoked token still valid: %v", err)
		}
	}
}

func TestRefreshToken_Expired(t *testing.T) {
	pool := setupTest(t)
	repo := storage.NewRefreshTokenRepository(pool)
	user := testutil.SeedUser(t, pool, "rt-expire@example.com")
	deviceID := testutil.SeedDevice(t, pool, user.ID, "dev-1")

	hash := []byte("hash-expired-32-bytes-long!!!!!!!!")
	_ = repo.Create(testCtx, user.ID, deviceID, hash, time.Now().Add(-time.Hour))

	_, err := repo.FindByHash(testCtx, hash)
	if !errors.Is(err, storage.ErrRefreshTokenInvalid) {
		t.Errorf("expected ErrRefreshTokenInvalid for expired, got %v", err)
	}
}
