package audit

import (
	"context"
	"encoding/json"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Event struct {
	UserID    *uuid.UUID
	DeviceID  *uuid.UUID
	EventType string
	Result    string
	IP        string
	UserAgent string
	Metadata  map[string]any
}

type Logger struct {
	pool    *pgxpool.Pool
	ch      chan Event
	dropped atomic.Int64
	logger  *slog.Logger
}

func NewLogger(pool *pgxpool.Pool, bufferSize int, logger *slog.Logger) *Logger {
	l := &Logger{
		pool:   pool,
		ch:     make(chan Event, bufferSize),
		logger: logger,
	}
	go l.worker()
	return l
}

func (l *Logger) Log(_ context.Context, e Event) {
	if l == nil {
		return
	}
	select {
	case l.ch <- e:
	default:
		l.dropped.Add(1)
		l.logger.Warn("audit buffer full, dropping event",
			"event_type", e.EventType, "dropped_total", l.dropped.Load())
	}
}

func (l *Logger) worker() {
	const query = `
		INSERT INTO audit_logs
			(user_id, device_id, event_type, result, ip, user_agent, metadata)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`
	for e := range l.ch {
		meta := e.Metadata
		if meta == nil {
			meta = map[string]any{}
		}
		raw, _ := json.Marshal(meta)

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_, err := l.pool.Exec(ctx, query,
			e.UserID, e.DeviceID, e.EventType, e.Result,
			e.IP, e.UserAgent, raw,
		)
		cancel()

		if err != nil {
			l.logger.Error("audit insert failed", "error", err, "event_type", e.EventType)
		}
	}
}

func (l *Logger) Close() {
	close(l.ch)
}
