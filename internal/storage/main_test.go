package storage_test

import (
	"context"
	"flag"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/MattKenyei/password-manager-backend/internal/testutil"
)

var (
	testPool *pgxpool.Pool
	testCtx  = context.Background()
)

func TestMain(m *testing.M) {
	flag.Parse()

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
