package testutil

import (
	"context"
	"fmt"
	"time"

	goredis "github.com/redis/go-redis/v9"
	"github.com/testcontainers/testcontainers-go"
	rediscontainer "github.com/testcontainers/testcontainers-go/modules/redis"
)

func StartRedis() (*goredis.Client, func(), error) {
	ctx := context.Background()

	ctr, err := rediscontainer.Run(ctx, "redis:7-alpine")
	if err != nil {
		return nil, nil, fmt.Errorf("start redis container: %w", err)
	}

	cleanupContainer := func() { _ = testcontainers.TerminateContainer(ctr) }

	endpoint, err := ctr.Endpoint(ctx, "")
	if err != nil {
		cleanupContainer()
		return nil, nil, fmt.Errorf("get redis endpoint: %w", err)
	}

	client := goredis.NewClient(&goredis.Options{Addr: endpoint})

	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := client.Ping(pingCtx).Err(); err != nil {
		client.Close()
		cleanupContainer()
		return nil, nil, fmt.Errorf("ping redis: %w", err)
	}

	return client, func() {
		_ = client.Close()
		cleanupContainer()
	}, nil
}

func FlushRedis(client *goredis.Client) error {
	return client.FlushDB(context.Background()).Err()
}
