package devices

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/MattKenyei/password-manager-backend/internal/api/httputil"
	"github.com/MattKenyei/password-manager-backend/internal/api/middleware"
	"github.com/MattKenyei/password-manager-backend/internal/storage"
	"github.com/google/uuid"
)

type Handler struct {
	devices *storage.DeviceRepository
	refresh *storage.RefreshTokenRepository
	logger  *slog.Logger
}

func NewHandler(devices *storage.DeviceRepository, refresh *storage.RefreshTokenRepository, logger *slog.Logger) *Handler {
	return &Handler{devices: devices, refresh: refresh, logger: logger}
}

func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.UserIDFromContext(r.Context())
	if !ok {
		httputil.WriteError(w, http.StatusUnauthorized, "unauthorized", "no user in context")
		return
	}

	list, err := h.devices.ListByUser(r.Context(), userID)
	if err != nil {
		h.logger.Error("failed to list devices", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "internal_error", "failed to list devices")
		return
	}
	resp := make([]DeviceResponse, 0, len(list))
	for _, d := range list {
		resp = append(resp, DeviceResponse{
			ID:         d.ID.String(),
			Name:       d.Name,
			Platform:   d.Platform,
			LastSeenAt: d.LastSeenAt.UTC().Format("2006-01-02T15:04:05Z07:00"),
			CreatedAt:  d.CreatedAt.UTC().Format("2006-01-02T15:04:05Z07:00"),
		})
	}

	httputil.WriteJSON(w, http.StatusOK, resp)
}

func (h *Handler) Revoke(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.UserIDFromContext(r.Context())
	if !ok {
		httputil.WriteError(w, http.StatusUnauthorized, "unauthorized", "no user in context")
		return
	}

	idStr := r.PathValue("id")
	deviceID, err := uuid.Parse(idStr)
	if err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid_device_id", "invalid device id")
		return
	}

	if err := h.devices.Revoke(r.Context(), userID, deviceID); err != nil {
		if errors.Is(err, storage.ErrDeviceNotFound) {
			httputil.WriteError(w, http.StatusNotFound, "device_not_found", "device not found")
			return
		}
		h.logger.Error("failed to revoke device", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "internal_error", "failed to revoke device")
		return
	}

	if err := h.refresh.RevokeDeviceTokens(r.Context(), deviceID); err != nil {
		h.logger.Error("failed to revoke device tokens", "error", err)
	}

	w.WriteHeader(http.StatusNoContent)
}
