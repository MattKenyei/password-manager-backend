package ws

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/google/uuid"
)

const (
	pingInterval   = 30 * time.Second
	writeTimeout   = 10 * time.Second
	pingTimeout    = 10 * time.Second
	maxMessageSize = 1024
	sendBufferSize = 32
)

type Client struct {
	conn      *websocket.Conn
	userID    uuid.UUID
	deviceID  uuid.UUID
	hub       *Hub
	send      chan []byte
	closeSig  chan struct{}
	closeOnce sync.Once
	logger    *slog.Logger
}

func newClient(conn *websocket.Conn, userID, deviceID uuid.UUID, hub *Hub, logger *slog.Logger) *Client {
	return &Client{
		conn:     conn,
		userID:   userID,
		deviceID: deviceID,
		hub:      hub,
		send:     make(chan []byte, sendBufferSize),
		closeSig: make(chan struct{}),
		logger:   logger,
	}
}

func (c *Client) Close() {
	c.closeOnce.Do(func() {
		close(c.closeSig)
		c.hub.unregister(c)
		_ = c.conn.Close(websocket.StatusNormalClosure, "bye")
	})
}

func (c *Client) writePump(ctx context.Context) {
	ticker := time.NewTicker(pingInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-c.closeSig:
			return
		case msg := <-c.send:
			writeCtx, cancel := context.WithTimeout(ctx, writeTimeout)
			err := c.conn.Write(writeCtx, websocket.MessageText, msg)
			cancel()
			if err != nil {
				c.logger.Debug("ws write failed", "error", err, "user_id", c.userID)
				return
			}
		case <-ticker.C:
			pingCtx, cancel := context.WithTimeout(ctx, pingTimeout)
			err := c.conn.Ping(pingCtx)
			cancel()
			if err != nil {
				c.logger.Debug("ws ping failed", "error", err, "user_id", c.userID)
				return
			}
		}
	}
}

func (c *Client) readPump(ctx context.Context) {
	c.conn.SetReadLimit(maxMessageSize)
	for {
		_, _, err := c.conn.Read(ctx)
		if err != nil {
			return
		}
	}
}
