package sync

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/google/uuid"

	"github.com/MattKenyei/password-manager-backend/internal/api/httputil"
	"github.com/MattKenyei/password-manager-backend/internal/api/middleware"
	"github.com/MattKenyei/password-manager-backend/internal/domain"
	"github.com/MattKenyei/password-manager-backend/internal/storage"
	"github.com/MattKenyei/password-manager-backend/internal/ws"
)

const maxChangesPerPush = 500

type Handler struct {
	items  *storage.ItemRepository
	hub    *ws.Hub
	logger *slog.Logger
}

func NewHandler(items *storage.ItemRepository, hub *ws.Hub, logger *slog.Logger) *Handler {
	return &Handler{items: items, hub: hub, logger: logger}
}

func (h *Handler) Push(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.UserIDFromContext(r.Context())
	if !ok {
		httputil.WriteError(w, http.StatusUnauthorized, "unauthorized", "no user in context")
		return
	}
	deviceID, ok := middleware.DeviceIDFromContext(r.Context())
	if !ok {
		httputil.WriteError(w, http.StatusUnauthorized, "unauthorized", "no device in context")
		return
	}

	var req PushRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid_json", err.Error())
		return
	}

	if len(req.Changes) == 0 {
		httputil.WriteError(w, http.StatusBadRequest, "empty_changes", "changes must not be empty")
		return
	}
	if len(req.Changes) > maxChangesPerPush {
		httputil.WriteError(w, http.StatusBadRequest, "too_many_changes", "too many changes in one request")
		return
	}

	changes := make([]domain.Change, 0, len(req.Changes))
	fieldErrs := make(map[string]string)
	seen := make(map[uuid.UUID]struct{})

	for i, c := range req.Changes {
		id, err := uuid.Parse(c.ID)
		if err != nil {
			fieldErrs["changes."+strconv.Itoa(i)+".id"] = "invalid UUID"
			continue
		}
		if _, dup := seen[id]; dup {
			fieldErrs["changes."+strconv.Itoa(i)+".id"] = "duplicate id in request"
			continue
		}
		seen[id] = struct{}{}

		if c.BaseVersion < 0 {
			fieldErrs["changes."+strconv.Itoa(i)+".base_version"] = "must be non-negative"
			continue
		}
		if len(c.EncryptedBlob) == 0 {
			fieldErrs["changes."+strconv.Itoa(i)+".encrypted_blob"] = "required"
			continue
		}
		if len(c.EncryptedBlob) > 64*1024 {
			fieldErrs["changes."+strconv.Itoa(i)+".encrypted_blob"] = "too large (max 64KB)"
			continue
		}

		changes = append(changes, domain.Change{
			ID:            id,
			EncryptedBlob: c.EncryptedBlob,
			BaseVersion:   c.BaseVersion,
			Deleted:       c.Deleted,
		})
	}

	if len(fieldErrs) > 0 {
		httputil.WriteValidationError(w, fieldErrs)
		return
	}

	result, err := h.items.PushChanges(r.Context(), userID, changes)
	if err != nil {
		h.logger.Error("push failed", "error", err, "user_id", userID)
		httputil.WriteError(w, http.StatusInternalServerError, "internal_error", "push failed")
		return
	}

	if len(result.Applied) > 0 {
		h.hub.BroadcastSync(userID, deviceID, result.NewRevision)
	}

	applied := make([]string, 0, len(result.Applied))
	for _, id := range result.Applied {
		applied = append(applied, id.String())
	}
	conflicts := make([]ConflictResponse, 0, len(result.Conflicts))
	for _, c := range result.Conflicts {
		conflicts = append(conflicts, ConflictResponse{
			ID:            c.ID.String(),
			ServerVersion: c.ServerVersion,
		})
	}

	httputil.WriteJSON(w, http.StatusOK, PushResponse{
		Applied:     applied,
		Conflicts:   conflicts,
		NewRevision: result.NewRevision,
	})
}

func (h *Handler) Pull(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.UserIDFromContext(r.Context())
	if !ok {
		httputil.WriteError(w, http.StatusUnauthorized, "unauthorized", "no user in context")
		return
	}

	var since int64
	if s := r.URL.Query().Get("since"); s != "" {
		v, err := strconv.ParseInt(s, 10, 64)
		if err != nil || v < 0 {
			httputil.WriteError(w, http.StatusBadRequest, "invalid_since", "since must be a non-negative integer")
			return
		}
		since = v
	}

	items, newRev, err := h.items.GetChangesSince(r.Context(), userID, since)
	if err != nil {
		h.logger.Error("pull failed", "error", err, "user_id", userID)
		httputil.WriteError(w, http.StatusInternalServerError, "internal_error", "pull failed")
		return
	}

	resp := make([]ItemResponse, 0, len(items))
	for _, it := range items {
		resp = append(resp, ItemResponse{
			ID:            it.ID.String(),
			EncryptedBlob: it.EncryptedBlob,
			Version:       it.Version,
			Deleted:       it.Deleted,
		})
	}

	httputil.WriteJSON(w, http.StatusOK, PullResponse{
		Items:       resp,
		NewRevision: newRev,
	})
}
