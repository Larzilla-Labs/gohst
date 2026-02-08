package ratelimit

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"

	"gohst/internal/config"
)

// ──────────────────────────────────────────────
// Redis Store (production / multi-instance)
// ──────────────────────────────────────────────

// RedisStore implements Store using a Redis-backed token bucket.
// Each key is stored as a Redis hash with fields: tokens, max, rate, last.
// An atomic Lua script performs the refill-then-consume operation so that
// concurrent requests can never over-admit.
type RedisStore struct {
	client *redis.Client
	prefix string
}

// NewRedisStore creates a RedisStore. It reads connection details from the
// rate-limit config (falling back to session Redis config).
func NewRedisStore() *RedisStore {
	cfg := config.RateLimit.Redis
	host := cfg.Host
	port := cfg.Port
	password := cfg.Password
	db := cfg.DB
	prefix := config.RateLimit.RedisPrefix

	client := redis.NewClient(&redis.Options{
		Addr:     host + ":" + strconv.Itoa(port),
		Password: password,
		DB:       db,
	})

	return &RedisStore{
		client: client,
		prefix: prefix,
	}
}

// luaTokenBucket is an atomic Lua script that:
//  1. refills tokens based on elapsed time
//  2. tries to consume `cost` tokens
//  3. returns [allowed(0/1), remaining, retryAfterMs, resetAtUnix]
//
// KEYS[1] = bucket key
// ARGV[1] = max_tokens  (limit + burst)
// ARGV[2] = refill_rate (tokens per second, as float string)
// ARGV[3] = cost
// ARGV[4] = now_ms      (current unix time in milliseconds)
// ARGV[5] = ttl_seconds  (key expiry)
var luaTokenBucket = redis.NewScript(`
local key       = KEYS[1]
local max       = tonumber(ARGV[1])
local rate      = tonumber(ARGV[2])
local cost      = tonumber(ARGV[3])
local now_ms    = tonumber(ARGV[4])
local ttl       = tonumber(ARGV[5])

local data = redis.call("HMGET", key, "tokens", "last_ms")
local tokens  = tonumber(data[1])
local last_ms = tonumber(data[2])

if tokens == nil then
    -- first request: start with full bucket
    tokens  = max
    last_ms = now_ms
end

-- refill
local elapsed_s = (now_ms - last_ms) / 1000.0
if elapsed_s > 0 then
    tokens = math.min(max, tokens + elapsed_s * rate)
    last_ms = now_ms
end

local allowed   = 0
local remaining = math.floor(tokens)
local retry_ms  = 0

if tokens >= cost then
    tokens    = tokens - cost
    remaining = math.floor(tokens)
    allowed   = 1
else
    local deficit = cost - tokens
    retry_ms = math.ceil((deficit / rate) * 1000)
end

-- persist
redis.call("HMSET", key, "tokens", tostring(tokens), "last_ms", tostring(last_ms))
redis.call("EXPIRE", key, ttl)

-- compute reset_at: time until full bucket
local deficit_full = max - tokens
local reset_s = 0
if deficit_full > 0 and rate > 0 then
    reset_s = deficit_full / rate
end
local reset_at = math.floor(now_ms / 1000) + math.ceil(reset_s)

return {allowed, remaining, retry_ms, reset_at}
`)

// Allow checks the rate limit for a key.
func (s *RedisStore) Allow(key string, policy Policy, cost int) Result {
	ctx := context.Background()
	fullKey := s.prefix + key

	maxTokens := float64(policy.Limit + policy.Burst)
	refillRate := float64(policy.Limit) / policy.Window.Seconds()
	nowMs := time.Now().UnixMilli()
	ttl := int(policy.Window.Seconds()) * 2 // keep key for 2 windows

	vals, err := luaTokenBucket.Run(ctx, s.client, []string{fullKey},
		fmt.Sprintf("%.4f", maxTokens),
		fmt.Sprintf("%.4f", refillRate),
		cost,
		nowMs,
		ttl,
	).Int64Slice()

	if err != nil {
		// On Redis error, fail open (allow the request).
		return Result{
			Allowed:   true,
			Limit:     policy.Limit + policy.Burst,
			Remaining: policy.Limit + policy.Burst,
		}
	}

	allowed := vals[0] == 1
	remaining := int(vals[1])
	retryMs := int(vals[2])
	resetAt := vals[3]

	retryAfter := retryMs / 1000
	if !allowed && retryAfter < 1 {
		retryAfter = 1
	}

	return Result{
		Allowed:    allowed,
		Limit:      policy.Limit + policy.Burst,
		Remaining:  remaining,
		RetryAfter: retryAfter,
		ResetAt:    resetAt,
	}
}

// Reset removes a key from the store.
func (s *RedisStore) Reset(key string) error {
	return s.client.Del(context.Background(), s.prefix+key).Err()
}

// Close shuts down the Redis client.
func (s *RedisStore) Close() error {
	return s.client.Close()
}

// ──────────────────────────────────────────────
// Redis concurrency store
// ──────────────────────────────────────────────

// RedisConcurrencyStore manages per-key concurrency using Redis INCR/DECR
// with a safety TTL so keys auto-expire if a release is missed.
type RedisConcurrencyStore struct {
	client *redis.Client
	prefix string
	ttl    time.Duration // safety TTL for auto-release
}

// NewRedisConcurrencyStore creates a concurrency store backed by Redis.
func NewRedisConcurrencyStore(client *redis.Client, prefix string, ttl time.Duration) *RedisConcurrencyStore {
	return &RedisConcurrencyStore{
		client: client,
		prefix: prefix + "conc:",
		ttl:    ttl,
	}
}

// Acquire tries to increment the in-flight counter atomically.
var luaConcAcquire = redis.NewScript(`
local key   = KEYS[1]
local limit = tonumber(ARGV[1])
local ttl   = tonumber(ARGV[2])
local cur   = tonumber(redis.call("GET", key) or "0")
if cur >= limit then
    return 0
end
redis.call("INCR", key)
redis.call("EXPIRE", key, ttl)
return 1
`)

func (r *RedisConcurrencyStore) Acquire(key string, limit int) (bool, error) {
	ctx := context.Background()
	res, err := luaConcAcquire.Run(ctx, r.client, []string{r.prefix + key}, limit, int(r.ttl.Seconds())).Int64()
	if err != nil {
		return true, nil // fail open
	}
	return res == 1, nil
}

// Release decrements the in-flight counter.
func (r *RedisConcurrencyStore) Release(key string) error {
	ctx := context.Background()
	fullKey := r.prefix + key
	res, err := r.client.Decr(ctx, fullKey).Result()
	if err != nil {
		return err
	}
	if res <= 0 {
		r.client.Del(ctx, fullKey)
	}
	return nil
}
