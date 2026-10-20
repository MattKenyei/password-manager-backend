package ws

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/MattKenyei/password-manager-backend/internal/api/httputil"
	"github.com/MattKenyei/password-manager-backend/internal/token"
	"github.com/coder/websocket"
)

type Handler struct {
	hub    *Hub
	issuer *token.Issuer
	logger *slog.Logger
}

func NewHandler(hub *Hub, issuer *token.Issuer, logger *slog.Logger) *Handler {
	return &Handler{hub: hub, issuer: issuer, logger: logger}
}

func contextWithCancel(parent context.Context) (context.Context, context.CancelFunc) {
	return context.WithCancel(parent)
}

func (h *Handler) ServeWS(w http.ResponseWriter, r *http.Request) {
	tokenStr := r.URL.Query().Get("token")
	if tokenStr == "" {
		httputil.WriteError(w, http.StatusUnauthorized, "unauthorized", "missing token")
		return
	}

	userID, deviceID, err := h.issuer.Parse(tokenStr)
	if err != nil {
		httputil.WriteError(w, http.StatusUnauthorized, "unauthorized", "invalid or expired token")
		return
	}

	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		OriginPatterns: []string{"*"},
	})
	if err != nil {
		h.logger.Error("ws accept failed", "error", err)
		return
	}

	c := newClient(conn, userID, deviceID, h.hub, h.logger)
	h.hub.register(c)

	h.logger.Info("ws connected", "user_id", userID, "device_id", deviceID)
	defer h.logger.Info("ws disconnected", "user_id", userID, "device_id", deviceID)

	ctx, cancel := contextWithCancel(r.Context())
	defer cancel()

	go c.writePump(ctx)
	c.readPump(ctx)
	c.Close()
}
