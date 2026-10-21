package auth

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/MattKenyei/password-manager-backend/internal/api/httputil"
	"github.com/MattKenyei/password-manager-backend/internal/config"
	"github.com/MattKenyei/password-manager-backend/internal/crypto"
	"github.com/MattKenyei/password-manager-backend/internal/domain"
	"github.com/MattKenyei/password-manager-backend/internal/storage"
	"github.com/MattKenyei/password-manager-backend/internal/token"
	"github.com/google/uuid"
)

type Handler struct {
	users   *storage.UserRepository
	devices *storage.DeviceRepository
	refresh *storage.RefreshTokenRepository
	issuer  *token.Issuer
	cfg     *config.Config
	logger  *slog.Logger
}

func NewHandler(users *storage.UserRepository, devices *storage.DeviceRepository, refresh *storage.RefreshTokenRepository, issuer *token.Issuer, cfg *config.Config, logger *slog.Logger) *Handler {
	return &Handler{
		users:   users,
		devices: devices,
		refresh: refresh,
		issuer:  issuer,
		cfg:     cfg,
		logger:  logger,
	}
}

func (h *Handler) Register(w http.ResponseWriter, r *http.Request) {
	h.logger.Info("Register handler called", "email_len", len(r.Header.Get("Content-Type")))
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
		Email:             email,
		AuthVerifier:      crypto.HashAuthKey(req.AuthKey),
		AuthSalt:          req.AuthSalt,
		EncSalt:           req.EncSalt,
		KDFParams:         req.KDFParams,
		WrappedAccountKey: req.WrappedAccountKey,
	}

	if err := h.users.Create(r.Context(), user); err != nil {
		if errors.Is(err, storage.ErrEmailExists) {
			httputil.WriteError(w, http.StatusConflict, "email_exists", "email is already registered")
			return
		}
		h.logger.Error("failed to create user", "error", err, "email", email)
		httputil.WriteError(w, http.StatusInternalServerError, "internal_error", "failed to create user")
		return
	}

	httputil.WriteJSON(w, http.StatusCreated, RegisterResponse{
		ID:        user.ID.String(),
		Email:     user.Email,
		CreatedAt: user.CreatedAt.UTC().Format("2006-01-02T15:04:05Z07:00"),
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
	if len(req.WrappedAccountKey) < 61 {
		errs["wrapped_account_key"] = "too short"
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
			httputil.WriteError(w, http.StatusUnauthorized, "invalid_credentials", "invalid email or password")
			return
		}
		h.logger.Error("failed to find user", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "internal_error", "failed to process request")
		return
	}

	providedVerifier := crypto.HashAuthKey(req.AuthKey)
	if subtle.ConstantTimeCompare(providedVerifier, user.AuthVerifier) != 1 {
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

	h.logger.Info("user logged in", "user_id", user.ID, "device_id", deviceID)

	httputil.WriteJSON(w, http.StatusOK, LoginFinishResponse{
		AccessToken:       accessToken,
		RefreshToken:      base64.StdEncoding.EncodeToString(rawRefresh),
		ExpiresIn:         int(h.cfg.JWT.AccessTTL.Seconds()),
		WrappedAccountKey: user.WrappedAccountKey,
	})
}

func (h *Handler) Refresh(w http.ResponseWriter, r *http.Request) {
	var req RefreshRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid_json", err.Error())
		return
	}

	rawToken, err := base64.StdEncoding.DecodeString(req.RefreshToken)
	if err != nil {
		httputil.WriteError(w, http.StatusUnauthorized, "invalid_refresh_token", "invalid refresh token")
		return
	}
	if len(rawToken) != 32 {
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
				if err := h.refresh.RevokeDeviceTokens(r.Context(), used.DeviceID); err != nil {
					h.logger.Error("failed to revoke device tokens", "error", err)
				}
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
			httputil.WriteError(w, http.StatusInternalServerError, "internal_error", "failed to logout")
			return
		}
	}

	w.WriteHeader(http.StatusNoContent)
}
