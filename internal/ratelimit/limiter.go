package ratelimit

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

type Limiter struct {
	rdb    *redis.Client
	prefix string
	limit  int64
	window time.Duration
}

var slidingWindowScript = redis.NewScript(`
local key = KEYS[1]
local now = tonumber(ARGV[1])
local window_ms = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])
local clear_before = now - window_ms

redis.call('ZREMRANGEBYSCORE', key, '-inf', clear_before)
local count = redis.call('ZCARD', key)
if count < limit then
	redis.call('ZADD', key, now, tostring(now) .. ':' .. tostring(math.random(1, 1000000)))
	redis.call('PEXPIRE', key, window_ms)
	return 1
end
return 0
`)

func New(rdb *redis.Client, prefix string, limit int64, window time.Duration) *Limiter {
	return &Limiter{rdb: rdb, prefix: prefix, limit: limit, window: window}
}

func (l *Limiter) Allow(ctx context.Context, key string) (bool, error) {
	now := time.Now().UnixMilli()
	result, err := slidingWindowScript.Run(ctx, l.rdb,
		[]string{"ratelimit:sw:" + l.prefix + ":" + key},
		now, l.window.Milliseconds(), l.limit,
	).Int64()
	if err != nil {
		return true, fmt.Errorf("ratelimit eval: %w", err)
	}
	return result == 1, nil
}
