package ratelimit

import (
	"math"
	"sync"
	"time"
)

// ──────────────────────────────────────────────
// Token bucket
// ──────────────────────────────────────────────

// Bucket tracks the token-bucket state for a single key.
type Bucket struct {
	Tokens    float64   // current number of available tokens
	MaxTokens float64   // max capacity (limit + burst)
	RefillRate float64  // tokens added per second
	LastRefill time.Time // last time tokens were refilled
}

// NewBucket creates a bucket from a policy.
func NewBucket(p Policy) *Bucket {
	max := float64(p.Limit + p.Burst)
	return &Bucket{
		Tokens:     max, // starts full
		MaxTokens:  max,
		RefillRate: float64(p.Limit) / p.Window.Seconds(),
		LastRefill: time.Now(),
	}
}

// refill adds tokens based on elapsed time (idempotent).
func (b *Bucket) refill(now time.Time) {
	elapsed := now.Sub(b.LastRefill).Seconds()
	if elapsed <= 0 {
		return
	}
	b.Tokens = math.Min(b.MaxTokens, b.Tokens+elapsed*b.RefillRate)
	b.LastRefill = now
}

// Allow tries to consume `cost` tokens. Returns remaining tokens and whether
// the request is allowed.
func (b *Bucket) Allow(cost int, now time.Time) (remaining int, allowed bool) {
	b.refill(now)
	c := float64(cost)
	if b.Tokens >= c {
		b.Tokens -= c
		return int(b.Tokens), true
	}
	return 0, false
}

// RetryAfter returns seconds until `cost` tokens will be available.
func (b *Bucket) RetryAfter(cost int) float64 {
	deficit := float64(cost) - b.Tokens
	if deficit <= 0 {
		return 0
	}
	if b.RefillRate <= 0 {
		return 0
	}
	return math.Ceil(deficit / b.RefillRate)
}

// ResetUnix returns the unix timestamp when the bucket will be fully refilled.
func (b *Bucket) ResetUnix() int64 {
	deficit := b.MaxTokens - b.Tokens
	if deficit <= 0 {
		return time.Now().Unix()
	}
	seconds := deficit / b.RefillRate
	return time.Now().Add(time.Duration(seconds * float64(time.Second))).Unix()
}

// ──────────────────────────────────────────────
// Result returned from Store.Allow
// ──────────────────────────────────────────────

// Result contains the outcome of a rate-limit check.
type Result struct {
	Allowed   bool
	Limit     int
	Remaining int
	RetryAfter int   // seconds (0 when allowed)
	ResetAt   int64  // unix timestamp
}

// ──────────────────────────────────────────────
// Store interface
// ──────────────────────────────────────────────

// Store is the persistence backend for rate-limit buckets.
type Store interface {
	// Allow checks the rate limit for a key given a policy and cost.
	Allow(key string, policy Policy, cost int) Result

	// Reset removes a key from the store (e.g. after successful auth).
	Reset(key string) error

	// Close gracefully shuts down the store.
	Close() error
}

// ──────────────────────────────────────────────
// Concurrency Store interface (optional layer)
// ──────────────────────────────────────────────

// ConcurrencyStore manages per-key in-flight request counts.
type ConcurrencyStore interface {
	// Acquire increments the in-flight counter for key.
	// Returns false if concurrency limit is reached.
	Acquire(key string, limit int) (bool, error)

	// Release decrements the in-flight counter for key.
	Release(key string) error
}

// ──────────────────────────────────────────────
// In-memory concurrency limiter
// ──────────────────────────────────────────────

// MemoryConcurrencyStore is a simple in-process concurrency limiter.
type MemoryConcurrencyStore struct {
	mu       sync.Mutex
	inflight map[string]int
}

// NewMemoryConcurrencyStore creates a new in-memory concurrency store.
func NewMemoryConcurrencyStore() *MemoryConcurrencyStore {
	return &MemoryConcurrencyStore{
		inflight: make(map[string]int),
	}
}

// Acquire increments the in-flight counter. Returns false if limit reached.
func (m *MemoryConcurrencyStore) Acquire(key string, limit int) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.inflight[key] >= limit {
		return false, nil
	}
	m.inflight[key]++
	return true, nil
}

// Release decrements the in-flight counter.
func (m *MemoryConcurrencyStore) Release(key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.inflight[key] > 0 {
		m.inflight[key]--
	}
	if m.inflight[key] == 0 {
		delete(m.inflight, key)
	}
	return nil
}
