# Rate Limiter

A reusable, middleware-based rate limiter for the Gohst framework. It uses a **token bucket** algorithm with support for burst capacity, composite keys, and both in-memory and Redis-backed stores.

## Quick Start

### 1. Environment Variables (optional — all have defaults)

Add any of these to your `.env` file to override defaults:

```bash
# Global on/off switch (default: true)
RATE_LIMIT_ENABLED=true

# Backing store: "memory" (single instance) or "redis" (multi-instance)
RATE_LIMIT_STORE=memory

# Redis config (falls back to SESSION_REDIS_* values if not set)
RATE_LIMIT_REDIS_HOST=localhost
RATE_LIMIT_REDIS_PORT=6379
RATE_LIMIT_REDIS_PASSWORD=
RATE_LIMIT_REDIS_DB=0
RATE_LIMIT_REDIS_PREFIX=gohst:rl:

# Response format for 429 errors: "json" or "html"
RATE_LIMIT_RESPONSE_FORMAT=json

# Log denied requests to the database (requires migration)
RATE_LIMIT_LOG_TABLE=false

# Trusted reverse proxies (comma-separated IPs or CIDRs)
RATE_LIMIT_TRUSTED_PROXIES=10.0.0.0/8,172.16.0.0/12

# Default policy values (used when no per-route policy is set)
RATE_LIMIT_DEFAULT_LIMIT=300
RATE_LIMIT_DEFAULT_WINDOW=60
RATE_LIMIT_DEFAULT_BURST=60
```

### 2. Using in Routes (with `middleware.Chain`)

The rate limiter produces a standard `func(http.Handler) http.Handler` middleware, so it drops directly into your existing `middleware.Chain` calls.

```go
package routes

import (
    "net/http"

    "gohst/app/controllers"
    "gohst/internal/middleware"
    "gohst/internal/ratelimit"
    "gohst/internal/session"
)

type AppRouter struct {
    rlStore ratelimit.Store // shared store across all limiters
}

func NewAppRouter() *AppRouter {
    return &AppRouter{
        rlStore: ratelimit.NewStore(), // reads RATE_LIMIT_STORE env
    }
}

// Public routes — generous limit (300/min, burst 60)
func (r *AppRouter) setupPublicRoutes() http.Handler {
    mux := http.NewServeMux()
    pages := controllers.NewPagesController()

    mux.HandleFunc("GET /{$}", pages.Index)
    mux.HandleFunc("GET /", pages.NotFound)
    mux.HandleFunc("GET /post/{id}", pages.Post)

    publicLimiter := ratelimit.NewPublicBrowseLimiter(r.rlStore)

    return middleware.Chain(
        mux,
        publicLimiter.Middleware,       // <-- rate limiter
        session.SM.SessionMiddleware,
        middleware.CSRF,
        middleware.Logger,
    )
}

// Auth routes — tight limit (10/min, keyed by IP + email)
func (r *AppRouter) setupAuthRoutes() http.Handler {
    mux := http.NewServeMux()
    auth := controllers.NewAuthController()

    mux.HandleFunc("GET /login", auth.Login)
    mux.HandleFunc("POST /login", auth.HandleLogin)
    mux.HandleFunc("GET /register", auth.Register)
    mux.HandleFunc("POST /register", auth.HandleRegister)

    authLimiter := ratelimit.NewAuthSensitiveLimiter(r.rlStore, "email")

    guestRoutes := middleware.Chain(
        mux,
        authLimiter.Middleware,          // <-- rate limiter
        session.SM.SessionMiddleware,
        middleware.CSRF,
        middleware.Logger,
        middleware.Guest,
    )

    // ... rest of auth setup
    return guestRoutes
}
```

### 3. Custom Policies

You can create your own policy for any route group:

```go
import "time"

limiter := ratelimit.NewLimiter(
    store,
    ratelimit.Policy{
        Limit:   50,
        Window:  30 * time.Second,
        Burst:   10,
        Scope:   "api_search",
        Enabled: true,
        Cost:    1,   // or Cost: 5 for expensive endpoints
    },
    ratelimit.KeyByTokenElseUserElseIP(),
)

handler := middleware.Chain(mux, limiter.Middleware, ...)
```

### 4. Cost-Based Limiting

Charge expensive endpoints more tokens per request:

```go
exportPolicy := ratelimit.Policy{
    Limit:   10,
    Window:  60 * time.Second,
    Burst:   0,
    Scope:   "exports",
    Enabled: true,
    Cost:    5, // each request costs 5 tokens
}
```

## Preset Policies

| Name                    | Limit   | Window | Burst | Key Strategy       | Use For                       |
| ----------------------- | ------- | ------ | ----- | ------------------ | ----------------------------- |
| `PublicBrowsePolicy()`  | 300/min | 60s    | 60    | user or IP         | Public pages                  |
| `APIDefaultPolicy()`    | 120/min | 60s    | 30    | token, user, or IP | API endpoints                 |
| `AuthSensitivePolicy()` | 10/min  | 60s    | 0     | IP + identifier    | Login, password reset         |
| `ExportsPolicy()`       | 10/min  | 60s    | 0     | token or user      | Heavy exports + concurrency=1 |

## Key Strategies

Key functions determine **who** is being rate-limited:

| Function                        | Key Format                                  | Best For                             |
| ------------------------------- | ------------------------------------------- | ------------------------------------ |
| `KeyByIP()`                     | `ip:<addr>`                                 | Fully anonymous routes               |
| `KeyByUserElseIP()`             | `user:<id>` or `ip:<addr>`                  | Pages where users may be logged in   |
| `KeyByTokenElseUserElseIP()`    | `token:<hash>`, `user:<id>`, or `ip:<addr>` | API routes                           |
| `KeyByIPAndIdentifier("email")` | `ipident:<ip>:<hash>`                       | Login/reset (brute-force protection) |
| `KeyByIPAndRoute()`             | `iproute:<ip>:<path>`                       | Limit specific expensive endpoints   |
| `KeyByIPAndUA()`                | `ipua:<ip>:<hash>`                          | Fingerprint-style throttling         |

## Allowlist / Bypass

Skip rate limiting for health checks, internal services, or local dev:

```go
limiter := ratelimit.NewLimiter(store, policy, keyFunc,
    ratelimit.WithAllowlist(
        ratelimit.BypassPaths{Prefixes: []string{"/healthz", "/readyz"}},
        ratelimit.BypassLocalDev{},
        ratelimit.BypassIPs{Allowed: []string{"10.0.0.0/8"}},
        ratelimit.BypassHeader{Header: "X-Internal-Token", Value: "secret"},
    ),
)
```

## Concurrency Limiting

For heavy endpoints (exports, reports), cap **in-flight** requests per key in addition to the rate limit:

```go
concStore := ratelimit.NewMemoryConcurrencyStore()
// or for multi-instance: ratelimit.NewRedisConcurrencyStore(redisClient, prefix, ttl)

exportLimiter := ratelimit.NewExportsLimiter(store, concStore)
```

## Database Logging

When `RATE_LIMIT_LOG_TABLE=true`, denied requests are logged to a `rate_limit_logs` table. Run the migration:

```
database/migrations/2025_02_24_135000_create_rate_limit_logs.sql
```

## Response Behavior

When a request is denied the middleware returns:

- **HTTP 429** Too Many Requests
- **Headers**: `Retry-After`, `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset`
- **Body**: JSON (for API/Accept: application/json) or HTML (configurable via `RATE_LIMIT_RESPONSE_FORMAT`)

## Architecture

```
internal/ratelimit/
├── policy.go          # Policy struct + preset policies
├── bucket.go          # Token bucket algorithm + Store/ConcurrencyStore interfaces
├── store_memory.go    # In-memory store (dev / single-instance)
├── store_redis.go     # Redis store with atomic Lua scripts (production)
├── clientip.go        # Trusted-proxy-aware IP resolution
├── keys.go            # Key computation functions
├── middleware.go       # HTTP middleware + 429 response handling
├── allowlist.go       # Bypass rules
├── log.go             # Database + no-op log stores
├── ratelimit.go       # Factory helpers + convenience constructors
├── bucket_test.go     # Token bucket unit tests
├── store_memory_test.go
├── clientip_test.go
├── keys_test.go
└── middleware_test.go
```
