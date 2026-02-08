// Package ratelimit provides a middleware-based rate limiter for the Gohst
// framework using a token-bucket algorithm.
//
// # Overview
//
// The rate limiter protects routes from abuse by tracking requests per key
// (IP, user ID, bearer token, or composite keys) and enforcing configurable
// limits with optional burst capacity.
//
// Two store backends are provided:
//   - In-memory (single instance / development)
//   - Redis with atomic Lua scripts (production / multi-instance)
//
// # Quick Start
//
// Create a store and a limiter, then add it to your middleware chain:
//
//	store := ratelimit.NewStore() // reads RATE_LIMIT_STORE env
//
//	limiter := ratelimit.NewPublicBrowseLimiter(store)
//
//	handler := middleware.Chain(
//	    mux,
//	    limiter.Middleware,
//	    session.SM.SessionMiddleware,
//	    middleware.CSRF,
//	    middleware.Logger,
//	)
//
// # Preset Policies
//
// Four ready-made policies cover common use cases:
//
//   - [PublicBrowsePolicy]: 300/min, burst 60 — anonymous page browsing
//   - [APIDefaultPolicy]: 120/min, burst 30 — authenticated API traffic
//   - [AuthSensitivePolicy]: 10/min, no burst — login / password reset
//   - [ExportsPolicy]: 10/min, no burst, concurrency 1 — heavy operations
//
// # Custom Policies
//
// Build your own policy for any route group:
//
//	limiter := ratelimit.NewLimiter(
//	    store,
//	    ratelimit.Policy{
//	        Limit:   50,
//	        Window:  30 * time.Second,
//	        Burst:   10,
//	        Scope:   "api_search",
//	        Enabled: true,
//	        Cost:    5, // expensive endpoints consume more tokens
//	    },
//	    ratelimit.KeyByTokenElseUserElseIP(),
//	)
//
// # Key Strategies
//
// Key functions determine "who" is being rate-limited:
//
//   - [KeyByIP]: by client IP address
//   - [KeyByUserElseIP]: by authenticated user ID, falling back to IP
//   - [KeyByTokenElseUserElseIP]: by bearer token, then user, then IP
//   - [KeyByIPAndIdentifier]: by IP + form field (e.g. email) — for brute-force protection
//   - [KeyByIPAndRoute]: by IP + request path — for per-endpoint limits
//   - [KeyByIPAndUA]: by IP + user-agent hash
//
// # Configuration
//
// All settings are configurable via environment variables (see [config.RateLimitConfig]):
//
//	RATE_LIMIT_ENABLED, RATE_LIMIT_STORE, RATE_LIMIT_REDIS_PREFIX,
//	RATE_LIMIT_RESPONSE_FORMAT, RATE_LIMIT_LOG_TABLE, RATE_LIMIT_TRUSTED_PROXIES,
//	RATE_LIMIT_DEFAULT_LIMIT, RATE_LIMIT_DEFAULT_WINDOW, RATE_LIMIT_DEFAULT_BURST
//
// See the README.md in this directory for the full reference.
package ratelimit
