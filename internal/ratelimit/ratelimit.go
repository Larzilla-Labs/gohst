package ratelimit

import (
	"log"
	"time"

	"gohst/internal/config"
)

// ──────────────────────────────────────────────
// Factory helpers
// ──────────────────────────────────────────────

// NewStore creates a Store based on the current config ("memory" or "redis").
func NewStore() Store {
	switch config.RateLimit.Store {
	case "redis":
		log.Println("[ratelimit] using Redis store")
		return NewRedisStore()
	default:
		log.Println("[ratelimit] using in-memory store")
		return NewMemoryStore(2 * time.Minute)
	}
}

// NewLogStore creates a LogStore based on config.
func NewLogStoreFromConfig() LogStore {
	if config.RateLimit.LogTableEnabled {
		log.Println("[ratelimit] database logging enabled")
		return NewDBLogStore()
	}
	return NopLogStore{}
}

// ──────────────────────────────────────────────
// Convenience constructors – create a ready-to-use Limiter for common cases.
// ──────────────────────────────────────────────

// NewPublicBrowseLimiter creates a limiter suitable for anonymous page browsing.
//
// Usage in routes:
//
//	limiter := ratelimit.NewPublicBrowseLimiter(store)
//	handler = middleware.Chain(mux, limiter.Middleware, ...)
func NewPublicBrowseLimiter(store Store, opts ...Option) *Limiter {
	return NewLimiter(store, PublicBrowsePolicy(), KeyByUserElseIP(), opts...)
}

// NewAPIDefaultLimiter creates a limiter for general API endpoints.
func NewAPIDefaultLimiter(store Store, opts ...Option) *Limiter {
	return NewLimiter(store, APIDefaultPolicy(), KeyByTokenElseUserElseIP(), opts...)
}

// NewAuthSensitiveLimiter creates a tight limiter for login/reset endpoints.
// `identifierField` is the form field name (e.g. "email") used to build
// composite keys so that brute-force attacks on a specific account are
// limited even if the attacker rotates IPs slightly.
func NewAuthSensitiveLimiter(store Store, identifierField string, opts ...Option) *Limiter {
	return NewLimiter(store, AuthSensitivePolicy(), KeyByIPAndIdentifier(identifierField), opts...)
}

// NewExportsLimiter creates a very tight limiter with concurrency cap.
func NewExportsLimiter(store Store, concStore ConcurrencyStore, opts ...Option) *Limiter {
	opts = append(opts, WithConcurrency(concStore))
	return NewLimiter(store, ExportsPolicy(), KeyByTokenElseUserElseIP(), opts...)
}
