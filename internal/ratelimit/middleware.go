package ratelimit

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"

	"gohst/internal/config"
)

// ──────────────────────────────────────────────
// Middleware
// ──────────────────────────────────────────────

// OnLimitFunc is an optional callback invoked when a request is rate-limited.
// Return true to indicate the response has been handled; false to use default 429.
type OnLimitFunc func(w http.ResponseWriter, r *http.Request, result Result) bool

// Limiter holds all the dependencies for a rate-limit middleware instance.
type Limiter struct {
	store            Store
	concurrencyStore ConcurrencyStore
	policy           Policy
	keyFunc          KeyFunc
	onLimit          OnLimitFunc
	allowlist        []AllowRule
	logStore         LogStore
}

// Option configures a Limiter.
type Option func(*Limiter)

// WithOnLimit sets a custom 429 handler.
func WithOnLimit(fn OnLimitFunc) Option {
	return func(l *Limiter) { l.onLimit = fn }
}

// WithConcurrency attaches a concurrency store.
func WithConcurrency(cs ConcurrencyStore) Option {
	return func(l *Limiter) { l.concurrencyStore = cs }
}

// WithAllowlist adds bypass rules.
func WithAllowlist(rules ...AllowRule) Option {
	return func(l *Limiter) { l.allowlist = rules }
}

// WithLogStore attaches a log store for denied-request logging.
func WithLogStore(ls LogStore) Option {
	return func(l *Limiter) { l.logStore = ls }
}

// NewLimiter creates a new Limiter.
func NewLimiter(store Store, policy Policy, keyFunc KeyFunc, opts ...Option) *Limiter {
	l := &Limiter{
		store:   store,
		policy:  policy,
		keyFunc: keyFunc,
	}
	for _, o := range opts {
		o(l)
	}
	return l
}

// Middleware returns an http middleware function compatible with the existing
// middleware.Chain helper.
func (l *Limiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Global kill-switch
		if !config.RateLimit.Enabled || !l.policy.Enabled {
			next.ServeHTTP(w, r)
			return
		}

		// Allowlist bypass
		for _, rule := range l.allowlist {
			if rule.Matches(r) {
				next.ServeHTTP(w, r)
				return
			}
		}

		key, keyType := l.keyFunc(r)
		cost := l.policy.Cost
		if cost < 1 {
			cost = 1
		}

		// ── Concurrency limit check ────────────────
		if l.policy.ConcurrencyLimit > 0 && l.concurrencyStore != nil {
			ok, err := l.concurrencyStore.Acquire(key, l.policy.ConcurrencyLimit)
			if err != nil {
				log.Printf("[ratelimit] concurrency store error key=%s: %v", truncateKey(key), err)
			}
			if !ok {
				l.denyResponse(w, r, Result{
					Allowed:    false,
					Limit:      l.policy.ConcurrencyLimit,
					Remaining:  0,
					RetryAfter: 1,
					ResetAt:    0,
				}, key, keyType, "concurrency")
				return
			}
			defer func() {
				if err := l.concurrencyStore.Release(key); err != nil {
					log.Printf("[ratelimit] concurrency release error key=%s: %v", truncateKey(key), err)
				}
			}()
		}

		// ── Rate limit check ───────────────────────
		result := l.store.Allow(key, l.policy, cost)

		// Always set rate-limit headers, even on success.
		setRateLimitHeaders(w, result)

		if !result.Allowed {
			l.denyResponse(w, r, result, key, keyType, "rate")
			return
		}

		next.ServeHTTP(w, r)
	})
}

// denyResponse writes a 429 response with proper headers and logging.
func (l *Limiter) denyResponse(w http.ResponseWriter, r *http.Request, result Result, key, keyType, reason string) {
	// Log at warn level (never log raw secrets)
	log.Printf("[ratelimit] DENIED %s %s | type=%s scope=%s key=%s retryAfter=%ds reason=%s",
		r.Method, r.URL.Path, keyType, l.policy.Scope, truncateKey(key), result.RetryAfter, reason)

	// Log to database if configured
	if l.logStore != nil {
		entry := LogEntry{
			Method:     r.Method,
			Path:       r.URL.Path,
			KeyType:    keyType,
			KeyHash:    truncateKey(key),
			Scope:      l.policy.Scope,
			RetryAfter: result.RetryAfter,
			ClientIP:   ClientIP(r),
		}
		if err := l.logStore.Log(entry); err != nil {
			log.Printf("[ratelimit] failed to write log entry: %v", err)
		}
	}

	// Custom handler?
	if l.onLimit != nil && l.onLimit(w, r, result) {
		return
	}

	// Default 429
	setRateLimitHeaders(w, result)

	format := config.RateLimit.DefaultResponseFormat
	// Heuristic: if Accept header prefers JSON, use JSON regardless of config.
	accept := r.Header.Get("Accept")
	if containsJSON(accept) {
		format = "json"
	}

	w.Header().Set("Retry-After", strconv.Itoa(result.RetryAfter))

	switch format {
	case "json":
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusTooManyRequests)
		resp := map[string]interface{}{
			"error":       "Too Many Requests",
			"retry_after": result.RetryAfter,
			"message":     "Rate limit exceeded. Please slow down and try again later.",
		}
		_ = json.NewEncoder(w).Encode(resp)
	default:
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusTooManyRequests)
		fmt.Fprintf(w, `<!DOCTYPE html>
<html><head><title>429 Too Many Requests</title></head>
<body>
<h1>Too Many Requests</h1>
<p>You have exceeded the rate limit. Please try again in %d seconds.</p>
</body></html>`, result.RetryAfter)
	}
}

// setRateLimitHeaders writes the standard rate-limit response headers.
func setRateLimitHeaders(w http.ResponseWriter, r Result) {
	w.Header().Set("X-RateLimit-Limit", strconv.Itoa(r.Limit))
	w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(r.Remaining))
	w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(r.ResetAt, 10))
}

// truncateKey returns a safe-to-log version of the key.
func truncateKey(key string) string {
	if len(key) > 40 {
		return key[:40] + "..."
	}
	return key
}

// containsJSON checks if an Accept header indicates JSON preference.
func containsJSON(accept string) bool {
	return len(accept) > 0 && (contains(accept, "application/json") || contains(accept, "text/json"))
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
