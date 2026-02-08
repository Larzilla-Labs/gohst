package ratelimit

import (
	"testing"
	"time"
)

func TestMemoryStore_AllowUpToLimit(t *testing.T) {
	store := NewMemoryStore(time.Minute)
	defer store.Close()

	p := Policy{Limit: 5, Window: time.Minute, Burst: 0, Enabled: true, Cost: 1, Scope: "test"}

	for i := 0; i < 5; i++ {
		res := store.Allow("test-key", p, 1)
		if !res.Allowed {
			t.Fatalf("request %d should be allowed", i+1)
		}
	}

	res := store.Allow("test-key", p, 1)
	if res.Allowed {
		t.Fatal("6th request should be denied")
	}
	if res.RetryAfter < 1 {
		t.Fatal("retryAfter should be at least 1")
	}
}

func TestMemoryStore_DifferentKeysIndependent(t *testing.T) {
	store := NewMemoryStore(time.Minute)
	defer store.Close()

	p := Policy{Limit: 1, Window: time.Minute, Burst: 0, Enabled: true, Cost: 1, Scope: "test"}

	res := store.Allow("key-a", p, 1)
	if !res.Allowed {
		t.Fatal("key-a should be allowed")
	}
	res = store.Allow("key-a", p, 1)
	if res.Allowed {
		t.Fatal("key-a should be denied after limit")
	}

	// key-b is independent
	res = store.Allow("key-b", p, 1)
	if !res.Allowed {
		t.Fatal("key-b should be allowed (independent bucket)")
	}
}

func TestMemoryStore_Reset(t *testing.T) {
	store := NewMemoryStore(time.Minute)
	defer store.Close()

	p := Policy{Limit: 1, Window: time.Minute, Burst: 0, Enabled: true, Cost: 1, Scope: "test"}

	store.Allow("reset-key", p, 1)
	res := store.Allow("reset-key", p, 1)
	if res.Allowed {
		t.Fatal("should be denied")
	}

	// Reset the key
	store.Reset("reset-key")

	res = store.Allow("reset-key", p, 1)
	if !res.Allowed {
		t.Fatal("should be allowed after reset")
	}
}

func TestMemoryStore_Headers(t *testing.T) {
	store := NewMemoryStore(time.Minute)
	defer store.Close()

	p := Policy{Limit: 10, Window: time.Minute, Burst: 5, Enabled: true, Cost: 1, Scope: "test"}

	res := store.Allow("header-key", p, 1)
	if !res.Allowed {
		t.Fatal("should be allowed")
	}
	if res.Limit != 15 { // 10 + 5 burst
		t.Fatalf("expected limit 15, got %d", res.Limit)
	}
	if res.Remaining != 14 {
		t.Fatalf("expected remaining 14, got %d", res.Remaining)
	}
	if res.ResetAt <= 0 {
		t.Fatal("resetAt should be a positive unix timestamp")
	}
}
