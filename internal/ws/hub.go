package ws

import (
	"encoding/json"
	"log/slog"
	"sync"

	"github.com/google/uuid"
)

type SyncMessage struct {
	Type     string `json:"type"`
	Revision int64  `json:"revision"`
}

type Hub struct {
	mu      sync.RWMutex
	clients map[uuid.UUID]map[*Client]struct{}
	logger  *slog.Logger
}

func NewHub(logger *slog.Logger) *Hub {
	return &Hub{
		clients: make(map[uuid.UUID]map[*Client]struct{}),
		logger:  logger,
	}
}

func (h *Hub) register(c *Client) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.clients[c.userID] == nil {
		h.clients[c.userID] = make(map[*Client]struct{})
	}
	h.clients[c.userID][c] = struct{}{}
}

func (h *Hub) unregister(c *Client) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if set, ok := h.clients[c.userID]; ok {
		delete(set, c)
		if len(set) == 0 {
			delete(h.clients, c.userID)
		}
	}
}

func (h *Hub) BroadcastSync(userID, exceptDeviceID uuid.UUID, revision int64) {
	data, err := json.Marshal(SyncMessage{Type: "sync", Revision: revision})
	if err != nil {
		h.logger.Error("marshal ws message", "error", err)
		return
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	set := h.clients[userID]
	if len(set) == 0 {
		return
	}

	for c := range set {
		if c.deviceID == exceptDeviceID {
			continue
		}

		select {
		case c.send <- data:
		default:
			h.logger.Warn("ws sent buffer full, dropping message", "user_id", userID, "device_id", c.deviceID)
		}
	}
}

func (h *Hub) Shutdown() {
	h.mu.Lock()
	clients := make([]*Client, 0)
	for _, set := range h.clients {
		for c := range set {
			clients = append(clients, c)
		}
	}
	h.clients = map[uuid.UUID]map[*Client]struct{}{}
	defer h.mu.Unlock()

	for _, c := range clients {
		c.Close()
	}
}
