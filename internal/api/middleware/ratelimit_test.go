package middleware_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/MattKenyei/password-manager-backend/internal/api/middleware"
	"github.com/MattKenyei/password-manager-backend/internal/ratelimit"
)

func TestRateLimit_SlidingWindow(t *testing.T) {
	rdb := setupTest(t)
	limiter := ratelimit.New(rdb, "test-endpoint", 3, 200*time.Millisecond)

	handler := middleware.RateLimit(limiter, testLog, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	srv := httptest.NewServer(handler)
	defer srv.Close()

	for i := 0; i < 3; i++ {
		resp, err := http.Get(srv.URL)
		if err != nil {
			t.Fatalf("request %d: %v", i+1, err)
		}
		resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatalf("request %d: want 200, got %d", i+1, resp.StatusCode)
		}
	}

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("4th request: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != 429 {
		t.Fatalf("4th request: want 429, got %d", resp.StatusCode)
	}
	if resp.Header.Get("Retry-After") == "" {
		t.Error("missing Retry-After header")
	}

	time.Sleep(250 * time.Millisecond)

	resp, err = http.Get(srv.URL)
	if err != nil {
		t.Fatalf("after window: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("after window: want 200, got %d", resp.StatusCode)
	}
}

func TestRateLimit_PerPrefixIsolation(t *testing.T) {
	rdb := setupTest(t)

	loginLimiter := ratelimit.New(rdb, "login", 2, time.Minute)
	registerLimiter := ratelimit.New(rdb, "register", 2, time.Minute)

	ctx := t.Context()

	for i := 0; i < 2; i++ {
		ok, err := loginLimiter.Allow(ctx, "127.0.0.1")
		if err != nil || !ok {
			t.Fatalf("login %d: ok=%v err=%v", i, ok, err)
		}
	}
	ok, _ := loginLimiter.Allow(ctx, "127.0.0.1")
	if ok {
		t.Fatal("login bucket should be exhausted")
	}

	ok, err := registerLimiter.Allow(ctx, "127.0.0.1")
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if !ok {
		t.Fatal("register bucket should be independent from login")
	}
}
