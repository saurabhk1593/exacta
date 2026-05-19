package redis

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

type BlacklistStore struct {
	rdb *redis.Client
}

func NewBlacklistStore(rdb *redis.Client) *BlacklistStore {
	return &BlacklistStore{rdb: rdb}
}

func (s *BlacklistStore) Add(ctx context.Context, tokenHash string, ttl time.Duration) error {
	return s.rdb.Set(ctx, "bl:"+tokenHash, 1, ttl).Err()
}

func (s *BlacklistStore) IsBlacklisted(ctx context.Context, tokenHash string) (bool, error) {
	n, err := s.rdb.Exists(ctx, "bl:"+tokenHash).Result()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// RateLimiter implements sliding window rate limiting with a Redis sorted set.
// Lua script ensures atomic check-and-increment.
type RateLimiter struct {
	rdb           *redis.Client
	windowSeconds int
	maxRequests   int
}

func NewRateLimiter(rdb *redis.Client, windowSeconds, maxRequests int) *RateLimiter {
	return &RateLimiter{rdb: rdb, windowSeconds: windowSeconds, maxRequests: maxRequests}
}

var slidingWindowScript = redis.NewScript(`
local key = KEYS[1]
local now = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])
local id = ARGV[4]

-- Remove expired entries
redis.call('ZREMRANGEBYSCORE', key, '-inf', now - window * 1000)

-- Count current requests
local count = redis.call('ZCARD', key)

if count >= limit then
  return 0
end

-- Add this request
redis.call('ZADD', key, now, id)
redis.call('PEXPIRE', key, window * 1000)
return 1
`)

// Allow returns true if the request is within rate limits.
func (r *RateLimiter) Allow(ctx context.Context, key string) (bool, error) {
	now := time.Now().UnixMilli()
	result, err := slidingWindowScript.Run(ctx, r.rdb,
		[]string{"rl:" + key},
		now,
		r.windowSeconds,
		r.maxRequests,
		fmt.Sprintf("%d", now),
	).Int()
	if err != nil {
		// Fail open on Redis errors — don't block legitimate traffic
		return true, err
	}
	return result == 1, nil
}
