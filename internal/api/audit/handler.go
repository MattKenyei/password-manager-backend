package audit

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/MattKenyei/password-manager-backend/internal/api/httputil"
	"github.com/MattKenyei/password-manager-backend/internal/api/middleware"
)

type Handler struct {
	pool   *pgxpool.Pool
	logger *slog.Logger
}

func NewHandler(pool *pgxpool.Pool, logger *slog.Logger) *Handler {
	return &Handler{pool: pool, logger: logger}
}

type Entry struct {
	EventType string          `json:"event_type"`
	Result    string          `json:"result"`
	IP        *string         `json:"ip,omitempty"`
	UserAgent *string         `json:"user_agent,omitempty"`
	Metadata  json.RawMessage `json:"metadata"`
	CreatedAt string          `json:"created_at"`
}

func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.UserIDFromContext(r.Context())
	if !ok {
		httputil.WriteError(w, http.StatusUnauthorized, "unauthorized", "no user in context")
		return
	}

	const query = `
		SELECT event_type, result, ip, user_agent, metadata, created_at
		FROM audit_logs
		WHERE user_id = $1
		ORDER BY created_at DESC
		LIMIT 100
	`
	rows, err := h.pool.Query(r.Context(), query, userID)
	if err != nil {
		h.logger.Error("failed to query audit logs", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "internal_error", "failed to list audit logs")
		return
	}
	defer rows.Close()

	out := make([]Entry, 0, 100)
	for rows.Next() {
		var e Entry
		var createdAt time.Time
		if err := rows.Scan(&e.EventType, &e.Result, &e.IP, &e.UserAgent, &e.Metadata, &createdAt); err != nil {
			h.logger.Error("failed to scan audit log", "error", err)
			httputil.WriteError(w, http.StatusInternalServerError, "internal_error", "failed to list audit logs")
			return
		}
		e.CreatedAt = createdAt.UTC().Format(time.RFC3339)
		out = append(out, e)
	}

	httputil.WriteJSON(w, http.StatusOK, out)
}
