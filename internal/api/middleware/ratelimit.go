package middleware

import (
	"log/slog"
	"net"
	"net/http"

	"github.com/MattKenyei/password-manager-backend/internal/api/httputil"
	"github.com/MattKenyei/password-manager-backend/internal/ratelimit"
)

func RateLimit(limiter *ratelimit.Limiter, logger *slog.Logger, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			ip = r.RemoteAddr
		}

		allowed, err := limiter.Allow(r.Context(), ip)
		if err != nil {
			logger.Warn("ratelimit unavailable, allowing request", "error", err)
			next(w, r)
			return
		}

		if !allowed {
			w.Header().Set("Retry-After", "60")
			httputil.WriteError(w, http.StatusTooManyRequests, "rate_limited", "too many requests, slow down")
			return
		}
		next(w, r)
	}
}
