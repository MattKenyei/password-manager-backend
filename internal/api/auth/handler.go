package auth

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/MattKenyei/password-manager-backend/internal/api/httputil"
	"github.com/MattKenyei/password-manager-backend/internal/audit"
	"github.com/MattKenyei/password-manager-backend/internal/config"
	"github.com/MattKenyei/password-manager-backend/internal/crypto"
	"github.com/MattKenyei/password-manager-backend/internal/domain"
	"github.com/MattKenyei/password-manager-backend/internal/storage"
	"github.com/MattKenyei/password-manager-backend/internal/token"
)

type Handler struct {
	users       *storage.UserRepository
	devices     *storage.DeviceRepository
	refresh     *storage.RefreshTokenRepository
	wrappedKeys *storage.WrappedKeyRepository
	issuer      *token.Issuer
	cfg         *config.Config
	audit       *audit.Logger
	logger      *slog.Logger
}

func NewHandler(
	users *storage.UserRepository,
	devices *storage.DeviceRepository,
	refresh *storage.RefreshTokenRepository,
	wrappedKeys *storage.WrappedKeyRepository,
	issuer *token.Issuer,
	cfg *config.Config,
	auditLogger *audit.Logger,
	logger *slog.Logger,
) *Handler {
	return &Handler{
		users:       users,
		devices:     devices,
		refresh:     refresh,
		wrappedKeys: wrappedKeys,
		issuer:      issuer,
		cfg:         cfg,
		audit:       auditLogger,
		logger:      logger,
	}
}

func clientIP(r *http.Request) string {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}

func (h *Handler) Register(w http.ResponseWriter, r *http.Request) {
	var req RegisterRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid_json", err.Error())
		return
	}

	if errs := validateRegisterRequest(&req); len(errs) > 0 {
		httputil.WriteValidationError(w, errs)
		return
	}

	email := strings.ToLower(strings.TrimSpace(req.Email))

	user := &domain.User{
		Email:        email,
		AuthVerifier: crypto.HashAuthKey(req.AuthKey),
		AuthSalt:     req.AuthSalt,
		EncSalt:      req.EncSalt,
		KDFParams:    req.KDFParams,
	}

	if err := h.users.Create(r.Context(), user); err != nil {
		if errors.Is(err, storage.ErrEmailExists) {
			h.audit.Log(r.Context(), audit.Event{
				EventType: "register_failure",
				Result:    "failure",
				IP:        clientIP(r),
				UserAgent: r.UserAgent(),
				Metadata:  map[string]any{"email": email, "reason": "email_exists"},
			})
			httputil.WriteError(w, http.StatusConflict, "email_exists", "email is already registered")
			return
		}
		h.logger.Error("failed to create user", "error", err, "email", email)
		httputil.WriteError(w, http.StatusInternalServerError, "internal_error", "failed to create user")
		return
	}

	var keysToSave []storage.WrappedKey
	if len(req.WrappedKeys) > 0 {
		for _, wk := range req.WrappedKeys {
			keysToSave = append(keysToSave, storage.WrappedKey{
				UserID:      user.ID,
				Kind:        wk.Kind,
				WrappedBlob: wk.WrappedBlob,
			})
		}
	} else if len(req.WrappedAccountKey) > 0 {
		keysToSave = append(keysToSave, storage.WrappedKey{
			UserID:      user.ID,
			Kind:        "master",
			WrappedBlob: req.WrappedAccountKey,
		})
	} else {
		httputil.WriteError(w, http.StatusBadRequest, "invalid_request", "wrapped keys required")
		return
	}

	if err := h.wrappedKeys.CreateMany(r.Context(), keysToSave); err != nil {
		h.logger.Error("failed to save wrapped keys", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "internal_error", "failed to save keys")
		return
	}

	h.audit.Log(r.Context(), audit.Event{
		UserID:    &user.ID,
		EventType: "register_success",
		Result:    "success",
		IP:        clientIP(r),
		UserAgent: r.UserAgent(),
		Metadata:  map[string]any{"email": email},
	})

	httputil.WriteJSON(w, http.StatusCreated, RegisterResponse{
		ID:        user.ID.String(),
		Email:     user.Email,
		CreatedAt: user.CreatedAt.UTC().Format(time.RFC3339),
	})
}

func validateRegisterRequest(req *RegisterRequest) map[string]string {
	errs := make(map[string]string)

	if req.Email == "" {
		errs["email"] = "required"
	} else if !strings.Contains(req.Email, "@") || len(req.Email) > 254 {
		errs["email"] = "invalid email format"
	}

	if len(req.AuthKey) != 32 {
		errs["auth_key"] = "must be 32 bytes"
	}
	if len(req.AuthSalt) < 16 || len(req.AuthSalt) > 64 {
		errs["auth_salt"] = "must be between 16 and 64 bytes"
	}
	if len(req.EncSalt) < 16 || len(req.EncSalt) > 64 {
		errs["enc_salt"] = "must be between 16 and 64 bytes"
	}
	if len(req.KDFParams) == 0 {
		errs["kdf_params"] = "required"
	}

	if len(req.WrappedKeys) == 0 && len(req.WrappedAccountKey) == 0 {
		errs["wrapped_account_key"] = "required"
	}
	if len(req.WrappedAccountKey) > 0 && len(req.WrappedAccountKey) < 61 {
		errs["wrapped_account_key"] = "too short"
	}
	for _, wk := range req.WrappedKeys {
		if wk.Kind == "" {
			errs["wrapped_keys"] = "kind required"
		}
		if len(wk.WrappedBlob) < 61 {
			errs["wrapped_keys"] = "wrapped_blob too short"
		}
	}

	return errs
}

func (h *Handler) LoginStart(w http.ResponseWriter, r *http.Request) {
	var req LoginStartRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid_json", err.Error())
		return
	}

	email := strings.ToLower(strings.TrimSpace(req.Email))
	if email == "" || !strings.Contains(email, "@") {
		httputil.WriteError(w, http.StatusBadRequest, "invalid_email", "email is required")
		return
	}

	user, err := h.users.FindByEmail(r.Context(), email)
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			httputil.WriteJSON(w, http.StatusOK, LoginStartResponse{
				AuthSalt:  make([]byte, 16),
				EncSalt:   make([]byte, 16),
				KDFParams: []byte(`{"algo":"argon2id"}`),
			})
			return
		}
		h.logger.Error("failed to find user", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "internal_error", "failed to process request")
		return
	}

	httputil.WriteJSON(w, http.StatusOK, LoginStartResponse{
		AuthSalt:  user.AuthSalt,
		EncSalt:   user.EncSalt,
		KDFParams: user.KDFParams,
	})
}

func (h *Handler) LoginFinish(w http.ResponseWriter, r *http.Request) {
	var req LoginFinishRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid_json", err.Error())
		return
	}

	email := strings.ToLower(strings.TrimSpace(req.Email))
	if email == "" || len(req.AuthKey) != 32 {
		httputil.WriteError(w, http.StatusBadRequest, "invalid_request", "email and auth_key are required")
		return
	}

	deviceID, err := uuid.Parse(req.DeviceID)
	if err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid_device_id", "device_id must be a valid UUID")
		return
	}
	if req.DeviceName == "" || req.DevicePlatform == "" {
		httputil.WriteError(w, http.StatusBadRequest, "invalid_device", "device_name and device_platform are required")
		return
	}

	user, err := h.users.FindByEmail(r.Context(), email)
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			h.audit.Log(r.Context(), audit.Event{
				EventType: "login_failure", Result: "failure",
				IP: clientIP(r), UserAgent: r.UserAgent(),
				Metadata: map[string]any{"email": email, "reason": "user_not_found"},
			})
			httputil.WriteError(w, http.StatusUnauthorized, "invalid_credentials", "invalid email or password")
			return
		}
		h.logger.Error("failed to find user", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "internal_error", "failed to process request")
		return
	}

	providedVerifier := crypto.HashAuthKey(req.AuthKey)
	if subtle.ConstantTimeCompare(providedVerifier, user.AuthVerifier) != 1 {
		h.audit.Log(r.Context(), audit.Event{
			UserID: &user.ID, EventType: "login_failure", Result: "failure",
			IP: clientIP(r), UserAgent: r.UserAgent(),
			Metadata: map[string]any{"reason": "bad_password"},
		})
		httputil.WriteError(w, http.StatusUnauthorized, "invalid_credentials", "invalid email or password")
		return
	}

	if err := h.devices.Upsert(r.Context(), deviceID, user.ID, req.DeviceName, req.DevicePlatform); err != nil {
		h.logger.Error("failed to upsert device", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "internal_error", "failed to register device")
		return
	}

	accessToken, err := h.issuer.Issue(user.ID, deviceID)
	if err != nil {
		h.logger.Error("failed to issue access token", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "internal_error", "failed to issue token")
		return
	}

	rawRefresh, hashRefresh, err := crypto.GenerateRefreshToken()
	if err != nil {
		h.logger.Error("failed to generate refresh token", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "internal_error", "failed to issue token")
		return
	}
	expiresAt := time.Now().Add(h.cfg.JWT.RefreshTTL)
	if err := h.refresh.Create(r.Context(), user.ID, deviceID, hashRefresh, expiresAt); err != nil {
		h.logger.Error("failed to store refresh token", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "internal_error", "failed to issue token")
		return
	}

	keys, err := h.wrappedKeys.ListByUser(r.Context(), user.ID)
	if err != nil {
		h.logger.Error("failed to list wrapped keys", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "internal_error", "failed to load keys")
		return
	}

	resp := LoginFinishResponse{
		AccessToken:  accessToken,
		RefreshToken: base64.StdEncoding.EncodeToString(rawRefresh),
		ExpiresIn:    int(h.cfg.JWT.AccessTTL.Seconds()),
	}
	resp.WrappedKeys = make([]WrappedKeyDTO, 0, len(keys))
	for _, k := range keys {
		resp.WrappedKeys = append(resp.WrappedKeys, WrappedKeyDTO{
			Kind:        k.Kind,
			WrappedBlob: k.WrappedBlob,
		})
		if k.Kind == "master" {
			resp.WrappedAccountKey = k.WrappedBlob
		}
	}

	h.audit.Log(r.Context(), audit.Event{
		UserID: &user.ID, DeviceID: &deviceID,
		EventType: "login_success", Result: "success",
		IP: clientIP(r), UserAgent: r.UserAgent(),
		Metadata: map[string]any{
			"device_platform": req.DevicePlatform,
			"device_name":     req.DeviceName,
		},
	})

	httputil.WriteJSON(w, http.StatusOK, resp)
}

func (h *Handler) Refresh(w http.ResponseWriter, r *http.Request) {
	var req RefreshRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid_json", err.Error())
		return
	}

	rawToken, err := base64.StdEncoding.DecodeString(req.RefreshToken)
	if err != nil || len(rawToken) != 32 {
		httputil.WriteError(w, http.StatusUnauthorized, "invalid_refresh_token", "invalid refresh token")
		return
	}

	hash := crypto.HashToken(rawToken)

	t, err := h.refresh.FindByHash(r.Context(), hash)
	if err != nil {
		if errors.Is(err, storage.ErrRefreshTokenInvalid) {
			if used, err2 := h.refresh.FindByHashUnsafely(r.Context(), hash); err2 == nil && used.UsedAt != nil {
				h.logger.Warn("refresh token reuse detected, revoking device",
					"device_id", used.DeviceID, "user_id", used.UserID)
				h.audit.Log(r.Context(), audit.Event{
					UserID: &used.UserID, DeviceID: &used.DeviceID,
					EventType: "refresh_token_reuse", Result: "security_alert",
					IP: clientIP(r), UserAgent: r.UserAgent(),
					Metadata: map[string]any{"action": "device_tokens_revoked"},
				})
				_ = h.refresh.RevokeDeviceTokens(r.Context(), used.DeviceID)
			}
			httputil.WriteError(w, http.StatusUnauthorized, "invalid_refresh_token", "invalid refresh token")
			return
		}
		h.logger.Error("failed to find refresh token", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "internal_error", "failed to process request")
		return
	}

	if err := h.refresh.MarkUsed(r.Context(), t.ID); err != nil {
		h.logger.Error("failed to mark refresh token used", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "internal_error", "failed to process request")
		return
	}

	newAccess, err := h.issuer.Issue(t.UserID, t.DeviceID)
	if err != nil {
		h.logger.Error("failed to issue access token", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "internal_error", "failed to issue token")
		return
	}

	rawNew, hashNew, err := crypto.GenerateRefreshToken()
	if err != nil {
		h.logger.Error("failed to generate refresh token", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "internal_error", "failed to issue token")
		return
	}
	expiresAt := time.Now().Add(h.cfg.JWT.RefreshTTL)
	if err := h.refresh.Create(r.Context(), t.UserID, t.DeviceID, hashNew, expiresAt); err != nil {
		h.logger.Error("failed to store refresh token", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "internal_error", "failed to issue token")
		return
	}

	httputil.WriteJSON(w, http.StatusOK, RefreshResponse{
		AccessToken:  newAccess,
		RefreshToken: base64.StdEncoding.EncodeToString(rawNew),
		ExpiresIn:    int(h.cfg.JWT.AccessTTL.Seconds()),
	})
}

func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	var req LogoutRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid_json", err.Error())
		return
	}

	rawToken, err := base64.StdEncoding.DecodeString(req.RefreshToken)
	if err != nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	hash := crypto.HashToken(rawToken)

	t, err := h.refresh.FindByHashUnsafely(r.Context(), hash)
	if err == nil && t.RevokedAt == nil {
		if err := h.refresh.RevokeDeviceTokens(r.Context(), t.DeviceID); err != nil {
			h.logger.Error("failed to revoke tokens on logout", "error", err)
		}
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) RecoverStart(w http.ResponseWriter, r *http.Request) {
	var req RecoverStartRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid_json", err.Error())
		return
	}

	email := strings.ToLower(strings.TrimSpace(req.Email))
	if email == "" || !strings.Contains(email, "@") {
		httputil.WriteError(w, http.StatusBadRequest, "invalid_email", "email is required")
		return
	}

	user, err := h.users.FindByEmail(r.Context(), email)
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			httputil.WriteJSON(w, http.StatusOK, RecoverStartResponse{
				WrappedRecoveryBlob: make([]byte, 61),
			})
			return
		}
		h.logger.Error("recover: failed to find user", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "internal_error", "failed to process request")
		return
	}

	keys, err := h.wrappedKeys.ListByUser(r.Context(), user.ID)
	if err != nil {
		h.logger.Error("recover: failed to list keys", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "internal_error", "failed to process request")
		return
	}

	var recoveryBlob []byte
	for _, k := range keys {
		if k.Kind == "recovery" {
			recoveryBlob = k.WrappedBlob
			break
		}
	}
	if recoveryBlob == nil {
		recoveryBlob = make([]byte, 61)
	}

	httputil.WriteJSON(w, http.StatusOK, RecoverStartResponse{
		WrappedRecoveryBlob: recoveryBlob,
	})
}

func (h *Handler) RecoverFinish(w http.ResponseWriter, r *http.Request) {
	var req RecoverFinishRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid_json", err.Error())
		return
	}

	email := strings.ToLower(strings.TrimSpace(req.Email))
	if email == "" || len(req.NewAuthKey) != 32 || len(req.NewWrappedKeys) == 0 {
		httputil.WriteError(w, http.StatusBadRequest, "invalid_request", "email, new_auth_key and new_wrapped_keys are required")
		return
	}

	user, err := h.users.FindByEmail(r.Context(), email)
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			httputil.WriteError(w, http.StatusUnauthorized, "invalid_credentials", "invalid email or recovery code")
			return
		}
		h.logger.Error("recover: failed to find user", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "internal_error", "failed to process request")
		return
	}

	if len(req.NewAuthSalt) < 16 || len(req.NewEncSalt) < 16 || len(req.NewKDFParams) == 0 {
		httputil.WriteError(w, http.StatusBadRequest, "invalid_request", "new salts and kdf_params are required")
		return
	}

	newVerifier := crypto.HashAuthKey(req.NewAuthKey)
	if err := h.users.UpdateCredentials(
		r.Context(), user.ID,
		newVerifier, req.NewAuthSalt, req.NewEncSalt, req.NewKDFParams,
	); err != nil {
		h.logger.Error("recover: failed to update credentials", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "internal_error", "failed to update password")
		return
	}

	var keysToSave []storage.WrappedKey
	for _, wk := range req.NewWrappedKeys {
		keysToSave = append(keysToSave, storage.WrappedKey{
			UserID:      user.ID,
			Kind:        wk.Kind,
			WrappedBlob: wk.WrappedBlob,
		})
	}
	if err := h.wrappedKeys.ReplaceAll(r.Context(), user.ID, keysToSave); err != nil {
		h.logger.Error("recover: failed to replace wrapped keys", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "internal_error", "failed to save keys")
		return
	}

	if err := h.users.RevokeAllRefreshTokens(r.Context(), user.ID); err != nil {
		h.logger.Error("recover: failed to revoke sessions", "error", err)
	}

	h.audit.Log(r.Context(), audit.Event{
		UserID:    &user.ID,
		EventType: "recovery_success",
		Result:    "success",
		IP:        clientIP(r),
		UserAgent: r.UserAgent(),
		Metadata:  map[string]any{"email": email},
	})

	w.WriteHeader(http.StatusNoContent)
}
