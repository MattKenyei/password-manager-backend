package auth

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/MattKenyei/password-manager-backend/internal/api/httputil"
	"github.com/MattKenyei/password-manager-backend/internal/crypto"
	"github.com/MattKenyei/password-manager-backend/internal/domain"
	"github.com/MattKenyei/password-manager-backend/internal/storage"
)

type Handler struct {
	users *storage.UserRepository
	logger *slog.Logger
}

func NewHandler(users *storage.UserRepository, logger *slog.Logger) *Handler {
	return &Handler{users: users, logger: logger}
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
		Email: email,
		AuthVerifier: crypto.HashAuthKey(req.AuthKey),
		AuthSalt: req.AuthSalt,
		EncSalt: req.EncSalt,
		KDFParams: req.KDFParams,
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
	if len(req.WrappedAccountKey) < 73 {
		errs["wrapped_account_key"] = "too short"
	}

	return errs
}