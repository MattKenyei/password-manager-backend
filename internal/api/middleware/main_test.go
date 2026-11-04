package middleware_test

import (
	"flag"
	"io"
	"log/slog"
	"os"
	"testing"

	goredis "github.com/redis/go-redis/v9"

	"github.com/MattKenyei/password-manager-backend/internal/testutil"
)

var (
	testRedis *goredis.Client
	testLog   *slog.Logger
)

func TestMain(m *testing.M) {
	flag.Parse()

	testLog = slog.New(slog.NewTextHandler(io.Discard, nil))

	if testing.Short() {
		os.Exit(m.Run())
	}

	client, cleanup, err := testutil.StartRedis()
	if err != nil {
		println("failed to start redis:", err.Error())
		os.Exit(1)
	}
	testRedis = client

	code := m.Run()
	cleanup()
	os.Exit(code)
}

func setupTest(t *testing.T) *goredis.Client {
	t.Helper()
	if testRedis == nil {
		t.Skip("integration test — skipped in -short mode")
	}
	if err := testutil.FlushRedis(testRedis); err != nil {
		t.Fatalf("flush redis: %v", err)
	}
	return testRedis
}
