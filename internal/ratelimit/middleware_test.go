package ratelimit

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"gohst/internal/config"
)

// initTestConfig sets up a minimal config so the middleware can function.
func initTestConfig() {
	config.RateLimit = &config.RateLimitConfig{
		Enabled:               true,
		Store:                 "memory",
		RedisPrefix:           "test:rl:",
		DefaultResponseFormat: "json",
		TrustedProxies:        nil,
		DefaultLimit:          300,
		DefaultWindow:         60,
		DefaultBurst:          60,
	}
}

func TestMiddleware_AllowsWithinLimit(t *testing.T) {
	initTestConfig()
	store := NewMemoryStore(time.Minute)
	defer store.Close()

	p := Policy{Limit: 5, Window: time.Minute, Burst: 0, Enabled: true, Cost: 1, Scope: "test"}
	limiter := NewLimiter(store, p, KeyByIP())

	handler := limiter.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	for i := 0; i < 5; i++ {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "1.2.3.4:1234"
		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Fatalf("request %d: expected 200, got %d", i+1, rr.Code)
		}

		// Should have rate limit headers
		if rr.Header().Get("X-RateLimit-Limit") == "" {
			t.Fatal("missing X-RateLimit-Limit header")
		}
		if rr.Header().Get("X-RateLimit-Remaining") == "" {
			t.Fatal("missing X-RateLimit-Remaining header")
		}
	}
}

func TestMiddleware_DeniesAfterLimit(t *testing.T) {
	initTestConfig()
	store := NewMemoryStore(time.Minute)
	defer store.Close()

	p := Policy{Limit: 3, Window: time.Minute, Burst: 0, Enabled: true, Cost: 1, Scope: "test"}
	limiter := NewLimiter(store, p, KeyByIP())

	handler := limiter.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	for i := 0; i < 3; i++ {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "1.2.3.4:1234"
		handler.ServeHTTP(rr, req)
	}

	// 4th request should be denied
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "1.2.3.4:1234"
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", rr.Code)
	}
	if rr.Header().Get("Retry-After") == "" {
		t.Fatal("missing Retry-After header")
	}
}

func TestMiddleware_DisabledGlobally(t *testing.T) {
	initTestConfig()
	config.RateLimit.Enabled = false

	store := NewMemoryStore(time.Minute)
	defer store.Close()

	p := Policy{Limit: 1, Window: time.Minute, Burst: 0, Enabled: true, Cost: 1, Scope: "test"}
	limiter := NewLimiter(store, p, KeyByIP())

	handler := limiter.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Should always allow when disabled
	for i := 0; i < 10; i++ {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "1.2.3.4:1234"
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("request %d: expected 200 (disabled), got %d", i+1, rr.Code)
		}
	}
}

func TestMiddleware_DisabledPerPolicy(t *testing.T) {
	initTestConfig()

	store := NewMemoryStore(time.Minute)
	defer store.Close()

	p := Policy{Limit: 1, Window: time.Minute, Burst: 0, Enabled: false, Cost: 1, Scope: "test"}
	limiter := NewLimiter(store, p, KeyByIP())

	handler := limiter.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	for i := 0; i < 10; i++ {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "1.2.3.4:1234"
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("request %d: expected 200 (policy disabled), got %d", i+1, rr.Code)
		}
	}
}

func TestMiddleware_AllowlistBypass(t *testing.T) {
	initTestConfig()

	store := NewMemoryStore(time.Minute)
	defer store.Close()

	p := Policy{Limit: 1, Window: time.Minute, Burst: 0, Enabled: true, Cost: 1, Scope: "test"}
	limiter := NewLimiter(store, p, KeyByIP(),
		WithAllowlist(BypassPaths{Prefixes: []string{"/healthz"}}),
	)

	handler := limiter.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Bypassed path — always allowed
	for i := 0; i < 10; i++ {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
		req.RemoteAddr = "1.2.3.4:1234"
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("bypassed path should always return 200, got %d", rr.Code)
		}
	}
}

func TestMiddleware_JSONResponse(t *testing.T) {
	initTestConfig()
	config.RateLimit.DefaultResponseFormat = "json"

	store := NewMemoryStore(time.Minute)
	defer store.Close()

	p := Policy{Limit: 1, Window: time.Minute, Burst: 0, Enabled: true, Cost: 1, Scope: "test"}
	limiter := NewLimiter(store, p, KeyByIP())

	handler := limiter.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Exhaust
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "5.6.7.8:1234"
	handler.ServeHTTP(rr, req)

	// Denied
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "5.6.7.8:1234"
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", rr.Code)
	}
	ct := rr.Header().Get("Content-Type")
	if ct != "application/json; charset=utf-8" {
		t.Fatalf("expected JSON content type, got %s", ct)
	}
}

func TestMemoryConcurrencyStore(t *testing.T) {
	cs := NewMemoryConcurrencyStore()

	ok, _ := cs.Acquire("k1", 2)
	if !ok {
		t.Fatal("1st acquire should succeed")
	}
	ok, _ = cs.Acquire("k1", 2)
	if !ok {
		t.Fatal("2nd acquire should succeed")
	}
	ok, _ = cs.Acquire("k1", 2)
	if ok {
		t.Fatal("3rd acquire should fail (limit=2)")
	}

	cs.Release("k1")
	ok, _ = cs.Acquire("k1", 2)
	if !ok {
		t.Fatal("acquire after release should succeed")
	}
}
