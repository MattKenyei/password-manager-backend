package auth_test

import (
	"flag"
	"io"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/MattKenyei/password-manager-backend/internal/config"
	"github.com/MattKenyei/password-manager-backend/internal/testutil"
)

var (
	testPool *pgxpool.Pool
	testCfg  *config.Config
	testLog  *slog.Logger
)

func TestMain(m *testing.M) {
	flag.Parse()

	testCfg = &config.Config{
		JWT: config.JWTConfig{
			Secret:     []byte("test-secret-at-least-32-bytes-long!!"),
			AccessTTL:  time.Minute,
			RefreshTTL: time.Hour,
		},
	}
	testLog = slog.New(slog.NewTextHandler(io.Discard, nil))

	if testing.Short() {
		os.Exit(m.Run())
	}

	pool, cleanup, err := testutil.StartPostgres()
	if err != nil {
		println("failed to start postgres:", err.Error())
		os.Exit(1)
	}
	testPool = pool

	code := m.Run()
	cleanup()
	os.Exit(code)
}

func setupTest(t *testing.T) *pgxpool.Pool {
	t.Helper()
	if testPool == nil {
		t.Skip("integration test — skipped in -short mode")
	}
	testutil.TruncateAll(t, testPool)
	return testPool
}
