package storage

import (
	"context"
	"fmt"
	"os"

	"github.com/redis/go-redis/v9"
)

func NewRedis(ctx context.Context, addr, password string, db int) (*redis.Client, error) {
	// Upstash / cloud providers give a full URL.
	// Prefer REDIS_URL if set — it includes TLS scheme (rediss://).
	var client *redis.Client
	if url := os.Getenv("REDIS_URL"); url != "" {
		opts, err := redis.ParseURL(url)
		if err != nil {
			return nil, fmt.Errorf("parse REDIS_URL: %w", err)
		}
		client = redis.NewClient(opts)
	} else {
		client = redis.NewClient(&redis.Options{
			Addr:     addr,
			Password: password,
			DB:       db,
		})
	}

	if err := client.Ping(ctx).Err(); err != nil {
		client.Close()
		return nil, fmt.Errorf("ping redis: %w", err)
	}

	return client, nil
}
