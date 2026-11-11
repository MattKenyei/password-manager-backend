package auth_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/google/uuid"

	"github.com/MattKenyei/password-manager-backend/internal/testutil"
)

func TestRecoverStart_KnownEmail_ReturnsRecoveryBlob(t *testing.T) {
	ts := setupServer(t)

	authKey := randBytes(32)
	_ = testutil.SeedUserWithRecovery(t, testPool, "recover@example.com", authKey)

	resp, body := postJSON(t, ts.url+"/auth/recover/start", map[string]any{
		"email": "recover@example.com",
	})

	if resp.StatusCode != 200 {
		t.Fatalf("status: want 200, got %d. body: %s", resp.StatusCode, body)
	}

	var out map[string]string
	_ = json.Unmarshal(body, &out)

	blob, err := base64.StdEncoding.DecodeString(out["wrapped_recovery_blob"])
	if err != nil {
		t.Fatalf("decode blob: %v", err)
	}
	if len(blob) != 80 || !bytes.Equal(blob, bytes.Repeat([]byte{0xAA}, 80)) {
		t.Errorf("recovery blob mismatch: len=%d", len(blob))
	}
}

func TestRecoverStart_UnknownEmail_AntiEnumeration(t *testing.T) {
	ts := setupServer(t)

	resp, body := postJSON(t, ts.url+"/auth/recover/start", map[string]any{
		"email": "ghost@example.com",
	})

	if resp.StatusCode != 200 {
		t.Fatalf("anti-enumeration broken: got %d, want 200. body: %s", resp.StatusCode, body)
	}

	var out map[string]string
	_ = json.Unmarshal(body, &out)
	blob, err := base64.StdEncoding.DecodeString(out["wrapped_recovery_blob"])
	if err != nil {
		t.Fatalf("decode blob: %v", err)
	}
	if len(blob) == 0 {
		t.Error("fake recovery blob missing")
	}
}

func TestRecoverStart_NoRecoveryConfigured_FakeBlob(t *testing.T) {
	ts := setupServer(t)

	_ = testutil.SeedUserWithPassword(t, testPool, "norecovery@example.com", randBytes(32))

	resp, body := postJSON(t, ts.url+"/auth/recover/start", map[string]any{
		"email": "norecovery@example.com",
	})

	if resp.StatusCode != 200 {
		t.Fatalf("want 200, got %d. body: %s", resp.StatusCode, body)
	}

	var out map[string]string
	_ = json.Unmarshal(body, &out)
	blob, _ := base64.StdEncoding.DecodeString(out["wrapped_recovery_blob"])
	if len(blob) == 0 {
		t.Error("fake blob missing for user without recovery")
	}
}

func TestRecoverFinish_Success(t *testing.T) {
	ts := setupServer(t)

	email := "recover-finish@example.com"
	_ = testutil.SeedUserWithRecovery(t, testPool, email, randBytes(32))

	newAuthKey := randBytes(32)
	newMasterBlob := bytes.Repeat([]byte{0x11}, 80)
	newRecoveryBlob := bytes.Repeat([]byte{0x22}, 80)

	resp, body := postJSON(t, ts.url+"/auth/recover/finish", map[string]any{
		"email":        email,
		"new_auth_key": b64(newAuthKey),
		"new_wrapped_keys": []map[string]any{
			{"kind": "master", "wrapped_blob": b64(newMasterBlob)},
			{"kind": "recovery", "wrapped_blob": b64(newRecoveryBlob)},
		},
	})

	if resp.StatusCode != 204 {
		t.Fatalf("status: want 204, got %d. body: %s", resp.StatusCode, body)
	}

	deviceID := uuid.New()
	resp, body = postJSON(t, ts.url+"/auth/login/finish",
		loginFinishPayload(email, newAuthKey, deviceID))
	if resp.StatusCode != 200 {
		t.Fatalf("login with new key failed: %d. body: %s", resp.StatusCode, body)
	}

	user, _ := ts.userRepo.FindByEmail(t.Context(), email)
	keys, _ := ts.wrappedRepo.ListByUser(t.Context(), user.ID)
	if len(keys) != 2 {
		t.Fatalf("expected 2 keys after recovery, got %d", len(keys))
	}
	for _, k := range keys {
		if k.Kind == "master" && !bytes.Equal(k.WrappedBlob, newMasterBlob) {
			t.Error("master blob was not replaced")
		}
		if k.Kind == "recovery" && !bytes.Equal(k.WrappedBlob, newRecoveryBlob) {
			t.Error("recovery blob was not replaced")
		}
	}
}

func TestRecoverFinish_RevokesAllSessions(t *testing.T) {
	ts := setupServer(t)

	email := "revoke-sessions@example.com"
	_ = testutil.SeedUserWithRecovery(t, testPool, email, randBytes(32))

	_, refresh1 := seedLoginAndGetTokens(t, ts, email)
	_, refresh2 := seedLoginAndGetTokens(t, ts, email)

	newAuthKey := randBytes(32)
	resp, body := postJSON(t, ts.url+"/auth/recover/finish", map[string]any{
		"email":        email,
		"new_auth_key": b64(newAuthKey),
		"new_wrapped_keys": []map[string]any{
			{"kind": "master", "wrapped_blob": b64(bytes.Repeat([]byte{0x11}, 80))},
		},
	})
	if resp.StatusCode != 204 {
		t.Fatalf("recover: %d %s", resp.StatusCode, body)
	}

	for i, r := range []string{refresh1, refresh2} {
		resp, _ := postJSON(t, ts.url+"/auth/refresh", map[string]any{"refresh_token": r})
		if resp.StatusCode != 401 {
			t.Errorf("refresh token #%d survived recovery: got %d, want 401", i+1, resp.StatusCode)
		}
	}
}

func TestRecoverFinish_UnknownEmail_Unauthorized(t *testing.T) {
	ts := setupServer(t)

	resp, body := postJSON(t, ts.url+"/auth/recover/finish", map[string]any{
		"email":        "ghost@example.com",
		"new_auth_key": b64(randBytes(32)),
		"new_wrapped_keys": []map[string]any{
			{"kind": "master", "wrapped_blob": b64(bytes.Repeat([]byte{0x11}, 80))},
		},
	})

	if resp.StatusCode != 401 {
		t.Fatalf("want 401, got %d. body: %s", resp.StatusCode, body)
	}

	var errBody map[string]any
	_ = json.Unmarshal(body, &errBody)
	if errBody["error"] != "invalid_credentials" {
		t.Errorf("error: want invalid_credentials, got %v", errBody["error"])
	}
}

func TestRecoverFinish_ValidationErrors(t *testing.T) {
	ts := setupServer(t)

	resp, body := postJSON(t, ts.url+"/auth/recover/finish", map[string]any{
		"email": "x@example.com",
	})
	if resp.StatusCode != 400 {
		t.Fatalf("missing new_auth_key: want 400, got %d. body: %s", resp.StatusCode, body)
	}

	resp, body = postJSON(t, ts.url+"/auth/recover/finish", map[string]any{
		"email":        "x@example.com",
		"new_auth_key": b64(randBytes(32)),
	})
	if resp.StatusCode != 400 {
		t.Fatalf("missing wrapped keys: want 400, got %d. body: %s", resp.StatusCode, body)
	}
}
