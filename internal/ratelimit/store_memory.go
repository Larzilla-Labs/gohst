package ratelimit

import (
	"sync"
	"time"
)

// ──────────────────────────────────────────────
// In-memory Store (dev / single-instance)
// ──────────────────────────────────────────────

type memEntry struct {
	bucket    *Bucket
	expiresAt time.Time // for cleanup
}

// MemoryStore is a thread-safe, in-process rate-limit store backed by a
// token-bucket per key. Expired entries are swept periodically.
type MemoryStore struct {
	mu      sync.Mutex
	entries map[string]*memEntry
	stop    chan struct{}
}

// NewMemoryStore creates a MemoryStore with a background cleanup goroutine
// that runs every `cleanupInterval`.
func NewMemoryStore(cleanupInterval time.Duration) *MemoryStore {
	s := &MemoryStore{
		entries: make(map[string]*memEntry),
		stop:    make(chan struct{}),
	}
	go s.cleanup(cleanupInterval)
	return s
}

// Allow checks whether the key is within its rate limit.
func (s *MemoryStore) Allow(key string, policy Policy, cost int) Result {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	e, ok := s.entries[key]
	if !ok {
		b := NewBucket(policy)
		e = &memEntry{
			bucket:    b,
			expiresAt: now.Add(policy.Window * 2), // keep alive for 2 windows
		}
		s.entries[key] = e
	}
	// update expiry on every touch
	e.expiresAt = now.Add(policy.Window * 2)

	remaining, allowed := e.bucket.Allow(cost, now)

	res := Result{
		Allowed:   allowed,
		Limit:     policy.Limit + policy.Burst,
		Remaining: remaining,
		ResetAt:   e.bucket.ResetUnix(),
	}
	if !allowed {
		res.RetryAfter = int(e.bucket.RetryAfter(cost))
		if res.RetryAfter < 1 {
			res.RetryAfter = 1
		}
	}
	return res
}

// Reset removes a key from the store (e.g. after successful login).
func (s *MemoryStore) Reset(key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.entries, key)
	return nil
}

// Close stops the background cleanup goroutine.
func (s *MemoryStore) Close() error {
	close(s.stop)
	return nil
}

// cleanup periodically removes expired entries.
func (s *MemoryStore) cleanup(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-s.stop:
			return
		case now := <-ticker.C:
			s.mu.Lock()
			for k, e := range s.entries {
				if now.After(e.expiresAt) {
					delete(s.entries, k)
				}
			}
			s.mu.Unlock()
		}
	}
}
