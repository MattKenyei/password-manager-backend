package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/MattKenyei/password-manager-backend/internal/api/httputil"
	"github.com/MattKenyei/password-manager-backend/internal/ctxkey"
	"github.com/MattKenyei/password-manager-backend/internal/token"
	"github.com/google/uuid"
)

func RequireAuth(issuer *token.Issuer, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			httputil.WriteError(w, http.StatusUnauthorized, "unathorized", "missing Authorization header")
			return
		}

		const bearerPrefix = "Bearer "
		if !strings.HasPrefix(authHeader, bearerPrefix) {
			httputil.WriteError(w, http.StatusUnauthorized, "unauthorized", "invalid Authorization scheme")
			return
		}

		tokenStr := strings.TrimPrefix(authHeader, bearerPrefix)
		if tokenStr == "" {
			httputil.WriteError(w, http.StatusUnauthorized, "unauthorized", "empty token")
			return
		}

		userID, deviceID, err := issuer.Parse(tokenStr)
		if err != nil {
			httputil.WriteError(w, http.StatusUnauthorized, "unauthorized", "invalid or expired token")
			return
		}

		ctx := context.WithValue(r.Context(), ctxkey.UserID, userID)
		ctx = context.WithValue(ctx, ctxkey.DeviceID, deviceID)

		next(w, r.WithContext(ctx))
	}
}

func UserIDFromContext(ctx context.Context) (uuid.UUID, bool) {
	v := ctx.Value(ctxkey.UserID)
	if v == nil {
		return uuid.Nil, false
	}
	id, ok := v.(uuid.UUID)
	return id, ok
}

func DeviceIDFromContext(ctx context.Context) (uuid.UUID, bool) {
	v := ctx.Value(ctxkey.DeviceID)
	if v == nil {
		return uuid.Nil, false
	}
	id, ok := v.(uuid.UUID)
	return id, ok
}
