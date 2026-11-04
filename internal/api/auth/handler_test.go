package auth_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	crand "crypto/rand"

	"github.com/MattKenyei/password-manager-backend/internal/api/auth"
	"github.com/MattKenyei/password-manager-backend/internal/domain"
	"github.com/MattKenyei/password-manager-backend/internal/storage"
	"github.com/MattKenyei/password-manager-backend/internal/testutil"
	"github.com/MattKenyei/password-manager-backend/internal/token"
)

type testServer struct {
	url         string
	pool        *storage.UserRepository
	userRepo    *storage.UserRepository
	refreshRepo *storage.RefreshTokenRepository
}

func setupServer(t *testing.T) *testServer {
	t.Helper()
	pool := setupTest(t)

	userRepo := storage.NewUserRepository(pool)
	deviceRepo := storage.NewDeviceRepository(pool)
	refreshRepo := storage.NewRefreshTokenRepository(pool)
	issuer := token.NewIssuer(testCfg.JWT.Secret, testCfg.JWT.AccessTTL)

	h := auth.NewHandler(userRepo, deviceRepo, refreshRepo, issuer, testCfg, nil, testLog)

	mux := http.NewServeMux()
	mux.HandleFunc("POST /auth/register", h.Register)
	mux.HandleFunc("POST /auth/login/start", h.LoginStart)
	mux.HandleFunc("POST /auth/login/finish", h.LoginFinish)
	mux.HandleFunc("POST /auth/refresh", h.Refresh)
	mux.HandleFunc("POST /auth/logout", h.Logout)

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	return &testServer{url: srv.URL, userRepo: userRepo, refreshRepo: refreshRepo}
}

func postJSON(t *testing.T, url string, body any) (*http.Response, []byte) {
	t.Helper()
	raw, _ := json.Marshal(body)
	resp, err := http.Post(url, "application/json", bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp, out
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := crand.Read(b); err != nil {
		panic(err)
	}
	return b
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func validRegisterPayload(email string, authKey []byte) map[string]any {
	return map[string]any{
		"email":               email,
		"auth_key":            b64(authKey),
		"auth_salt":           b64(randBytes(16)),
		"enc_salt":            b64(randBytes(16)),
		"kdf_params":          b64([]byte(`{"algo":"argon2id"}`)),
		"wrapped_account_key": b64(bytes.Repeat([]byte{0xFF}, 80)),
	}
}

func TestRegister_Success(t *testing.T) {
	ts := setupServer(t)

	payload := validRegisterPayload("new@example.com", randBytes(32))
	resp, body := postJSON(t, ts.url+"/auth/register", payload)

	if resp.StatusCode != 201 {
		t.Fatalf("status: want 201, got %d. body: %s", resp.StatusCode, body)
	}

	var out map[string]any
	_ = json.Unmarshal(body, &out)

	if out["email"] != "new@example.com" {
		t.Errorf("email mismatch: %v", out["email"])
	}
	if _, ok := out["id"]; !ok {
		t.Error("missing id in response")
	}

	user, err := ts.userRepo.FindByEmail(t.Context(), "new@example.com")
	if err != nil {
		t.Fatalf("find: %v", err)
	}
	if len(user.AuthVerifier) != 32 {
		t.Errorf("auth_verifier length: want 32, got %d", len(user.AuthVerifier))
	}
}

func TestRegister_DuplicateEmail(t *testing.T) {
	ts := setupServer(t)

	payload := validRegisterPayload("dup@example.com", randBytes(32))
	resp, _ := postJSON(t, ts.url+"/auth/register", payload)
	if resp.StatusCode != 201 {
		t.Fatalf("first register: %d", resp.StatusCode)
	}

	resp, body := postJSON(t, ts.url+"/auth/register", payload)
	if resp.StatusCode != 409 {
		t.Fatalf("want 409, got %d. body: %s", resp.StatusCode, body)
	}

	var errBody map[string]any
	_ = json.Unmarshal(body, &errBody)
	if errBody["error"] != "email_exists" {
		t.Errorf("error: want email_exists, got %v", errBody["error"])
	}
}

func TestRegister_ValidationErrors(t *testing.T) {
	ts := setupServer(t)

	resp, body := postJSON(t, ts.url+"/auth/register", map[string]any{})

	if resp.StatusCode != 400 {
		t.Fatalf("want 400, got %d", resp.StatusCode)
	}

	var errBody map[string]any
	_ = json.Unmarshal(body, &errBody)

	fields, ok := errBody["fields"].(map[string]any)
	if !ok {
		t.Fatalf("missing fields: %s", body)
	}

	for _, key := range []string{"email", "auth_key", "auth_salt", "enc_salt", "kdf_params", "wrapped_account_key"} {
		if _, ok := fields[key]; !ok {
			t.Errorf("missing field error for %q", key)
		}
	}
}

func TestLoginStart_KnownEmail(t *testing.T) {
	ts := setupServer(t)

	authKey := randBytes(32)
	_ = testutil.SeedUserWithPassword(t, testPool, "known@example.com", authKey)

	resp, body := postJSON(t, ts.url+"/auth/login/start", map[string]any{
		"email": "known@example.com",
	})

	if resp.StatusCode != 200 {
		t.Fatalf("status: want 200, got %d. body: %s", resp.StatusCode, body)
	}

	var out map[string]string
	_ = json.Unmarshal(body, &out)

	authSalt, _ := base64.StdEncoding.DecodeString(out["auth_salt"])
	if len(authSalt) == 0 {
		t.Fatal("auth_salt empty")
	}
	if !bytes.Equal(authSalt, []byte{0x02, 0x03, 0x04, 0x05}) {
		t.Errorf("auth_salt mismatch: %x", authSalt)
	}
}

func TestLoginStart_UnknownEmail_AntiEnumeration(t *testing.T) {
	ts := setupServer(t)

	resp, body := postJSON(t, ts.url+"/auth/login/start", map[string]any{
		"email": "nonexistent@example.com",
	})

	if resp.StatusCode != 200 {
		t.Fatalf("anti-enumeration broken: got %d, want 200. body: %s", resp.StatusCode, body)
	}

	var out map[string]string
	_ = json.Unmarshal(body, &out)

	if out["auth_salt"] == "" || out["enc_salt"] == "" {
		t.Error("fake salts missing")
	}

	authSalt, _ := base64.StdEncoding.DecodeString(out["auth_salt"])
	if len(authSalt) != 16 {
		t.Errorf("fake auth_salt length: want 16, got %d", len(authSalt))
	}
}

func loginFinishPayload(email string, authKey []byte, deviceID uuid.UUID) map[string]any {
	return map[string]any{
		"email":           email,
		"auth_key":        b64(authKey),
		"device_id":       deviceID.String(),
		"device_name":     "test-device",
		"device_platform": "test",
	}
}

func TestLoginFinish_Success(t *testing.T) {
	ts := setupServer(t)

	authKey := randBytes(32)
	_ = testutil.SeedUserWithPassword(t, testPool, "login@example.com", authKey)
	deviceID := uuid.New()

	resp, body := postJSON(t, ts.url+"/auth/login/finish",
		loginFinishPayload("login@example.com", authKey, deviceID))

	if resp.StatusCode != 200 {
		t.Fatalf("status: want 200, got %d. body: %s", resp.StatusCode, body)
	}

	var out map[string]any
	_ = json.Unmarshal(body, &out)

	for _, k := range []string{"access_token", "refresh_token", "wrapped_account_key"} {
		if _, ok := out[k]; !ok {
			t.Errorf("missing %q in response", k)
		}
	}
	if out["expires_in"].(float64) <= 0 {
		t.Errorf("expires_in: want > 0, got %v", out["expires_in"])
	}
}

func TestLoginFinish_WrongPassword(t *testing.T) {
	ts := setupServer(t)

	correctKey := randBytes(32)
	wrongKey := randBytes(32)

	if bytes.Equal(correctKey, wrongKey) {
		t.Fatal("randBytes returned identical output twice — crypto/rand broken?")
	}

	_ = testutil.SeedUserWithPassword(t, testPool, "wrongpw@example.com", correctKey)

	resp, body := postJSON(t, ts.url+"/auth/login/finish",
		loginFinishPayload("wrongpw@example.com", wrongKey, uuid.New()))

	if resp.StatusCode != 401 {
		t.Fatalf("want 401, got %d. body: %s", resp.StatusCode, body)
	}

	var errBody map[string]any
	_ = json.Unmarshal(body, &errBody)
	if errBody["error"] != "invalid_credentials" {
		t.Errorf("error: want invalid_credentials, got %v", errBody["error"])
	}
}

func TestLoginFinish_UnknownEmail_SameAsWrongPassword(t *testing.T) {
	ts := setupServer(t)

	resp, body := postJSON(t, ts.url+"/auth/login/finish",
		loginFinishPayload("ghost@example.com", randBytes(32), uuid.New()))

	if resp.StatusCode != 401 {
		t.Fatalf("want 401, got %d", resp.StatusCode)
	}

	var errBody map[string]any
	_ = json.Unmarshal(body, &errBody)
	if errBody["error"] != "invalid_credentials" {
		t.Errorf("unknown email leaked: got %v, want invalid_credentials", errBody["error"])
	}
}

func seedLoginAndGetTokens(t *testing.T, ts *testServer, email string) (authKey []byte, refreshToken string) {
	t.Helper()
	authKey = randBytes(32)
	_ = testutil.SeedUserWithPassword(t, testPool, email, authKey)

	resp, body := postJSON(t, ts.url+"/auth/login/finish",
		loginFinishPayload(email, authKey, uuid.New()))
	if resp.StatusCode != 200 {
		t.Fatalf("login: %d %s", resp.StatusCode, body)
	}

	var out map[string]any
	_ = json.Unmarshal(body, &out)
	return authKey, out["refresh_token"].(string)
}

func TestRefresh_Rotation(t *testing.T) {
	ts := setupServer(t)

	_, oldRefresh := seedLoginAndGetTokens(t, ts, "rotate@example.com")

	resp, body := postJSON(t, ts.url+"/auth/refresh", map[string]any{
		"refresh_token": oldRefresh,
	})
	if resp.StatusCode != 200 {
		t.Fatalf("first refresh: %d %s", resp.StatusCode, body)
	}

	var out map[string]any
	_ = json.Unmarshal(body, &out)
	newRefresh := out["refresh_token"].(string)

	if newRefresh == oldRefresh {
		t.Fatal("refresh token was not rotated")
	}

	resp, _ = postJSON(t, ts.url+"/auth/refresh", map[string]any{
		"refresh_token": oldRefresh,
	})
	if resp.StatusCode != 401 {
		t.Fatalf("old token still works: %d", resp.StatusCode)
	}
}

func TestRefresh_ReuseDetection(t *testing.T) {
	ts := setupServer(t)

	_, oldRefresh := seedLoginAndGetTokens(t, ts, "reuse@example.com")

	resp, body := postJSON(t, ts.url+"/auth/refresh", map[string]any{
		"refresh_token": oldRefresh,
	})
	if resp.StatusCode != 200 {
		t.Fatalf("rotate: %d %s", resp.StatusCode, body)
	}
	var rotated map[string]any
	_ = json.Unmarshal(body, &rotated)
	newRefresh := rotated["refresh_token"].(string)

	resp, _ = postJSON(t, ts.url+"/auth/refresh", map[string]any{
		"refresh_token": oldRefresh,
	})
	if resp.StatusCode != 401 {
		t.Fatalf("reuse should be 401, got %d", resp.StatusCode)
	}

	resp, _ = postJSON(t, ts.url+"/auth/refresh", map[string]any{
		"refresh_token": newRefresh,
	})
	if resp.StatusCode != 401 {
		t.Fatalf("after reuse detection, new token should be 401, got %d", resp.StatusCode)
	}
}

func TestLogout_Idempotent(t *testing.T) {
	ts := setupServer(t)

	_, refresh := seedLoginAndGetTokens(t, ts, "logout@example.com")

	for i := 0; i < 3; i++ {
		resp, _ := postJSON(t, ts.url+"/auth/logout", map[string]any{
			"refresh_token": refresh,
		})
		if resp.StatusCode != 204 {
			t.Fatalf("logout #%d: want 204, got %d", i+1, resp.StatusCode)
		}
	}
}

var (
	_ = time.Second
	_ = domain.User{}
)
