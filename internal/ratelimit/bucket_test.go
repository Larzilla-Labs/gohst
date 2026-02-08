package ratelimit

import (
	"testing"
	"time"
)

func TestBucket_AllowUpToLimit(t *testing.T) {
	p := Policy{Limit: 5, Window: time.Minute, Burst: 0, Enabled: true, Cost: 1}
	b := NewBucket(p)
	now := time.Now()

	for i := 0; i < 5; i++ {
		_, allowed := b.Allow(1, now)
		if !allowed {
			t.Fatalf("request %d should be allowed", i+1)
		}
	}
}

func TestBucket_DenyAfterLimit(t *testing.T) {
	p := Policy{Limit: 3, Window: time.Minute, Burst: 0, Enabled: true, Cost: 1}
	b := NewBucket(p)
	now := time.Now()

	for i := 0; i < 3; i++ {
		b.Allow(1, now)
	}

	_, allowed := b.Allow(1, now)
	if allowed {
		t.Fatal("request after limit should be denied")
	}
}

func TestBucket_BurstAllowsExtra(t *testing.T) {
	p := Policy{Limit: 5, Window: time.Minute, Burst: 3, Enabled: true, Cost: 1}
	b := NewBucket(p)
	now := time.Now()

	// Should allow 5 + 3 = 8 requests
	allowed := true
	for i := 0; i < 8; i++ {
		_, allowed = b.Allow(1, now)
		if !allowed {
			t.Fatalf("request %d should be allowed (burst capacity)", i+1)
		}
	}

	_, allowed = b.Allow(1, now)
	if allowed {
		t.Fatal("request 9 should be denied (burst exhausted)")
	}
}

func TestBucket_RefillAfterTime(t *testing.T) {
	p := Policy{Limit: 10, Window: time.Second, Burst: 0, Enabled: true, Cost: 1}
	b := NewBucket(p)

	now := time.Now()
	for i := 0; i < 10; i++ {
		b.Allow(1, now)
	}

	_, allowed := b.Allow(1, now)
	if allowed {
		t.Fatal("should be denied when exhausted")
	}

	later := now.Add(time.Second)
	_, allowed = b.Allow(1, later)
	if !allowed {
		t.Fatal("should be allowed after full refill")
	}
}

func TestBucket_CostBasedLimiting(t *testing.T) {
	p := Policy{Limit: 10, Window: time.Minute, Burst: 0, Enabled: true, Cost: 1}
	b := NewBucket(p)
	now := time.Now()

	_, allowed := b.Allow(5, now)
	if !allowed {
		t.Fatal("cost-5 request should be allowed")
	}

	_, allowed = b.Allow(5, now)
	if !allowed {
		t.Fatal("second cost-5 request should be allowed")
	}

	_, allowed = b.Allow(1, now)
	if allowed {
		t.Fatal("should be denied, all tokens consumed")
	}
}

func TestBucket_RetryAfter(t *testing.T) {
	p := Policy{Limit: 10, Window: 10 * time.Second, Burst: 0, Enabled: true, Cost: 1}
	b := NewBucket(p)
	now := time.Now()

	for i := 0; i < 10; i++ {
		b.Allow(1, now)
	}

	retry := b.RetryAfter(1)
	if retry <= 0 {
		t.Fatal("retryAfter should be positive when tokens exhausted")
	}
	if retry > 2 {
		t.Fatalf("retryAfter should be about 1 second, got %.2f", retry)
	}
}
