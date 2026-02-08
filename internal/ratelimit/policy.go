package ratelimit

import (
	"time"
)

// Policy defines a rate-limit policy that can be attached to a route or group.
type Policy struct {
	// Limit is the maximum number of allowed requests in the window.
	Limit int

	// Window is the time period for the limit.
	Window time.Duration

	// Burst is extra capacity for short spikes (token bucket style).
	// Set to 0 for strict limiting (fixed-window behaviour).
	Burst int

	// Scope is an optional human-readable name used for logging/reporting.
	Scope string

	// Enabled allows per-policy overrides. When false the middleware is a no-op.
	Enabled bool

	// Cost is the token cost of a single request (default 1).
	// Use higher values for expensive endpoints.
	Cost int

	// ConcurrencyLimit caps the number of in-flight requests per key.
	// 0 means unlimited.
	ConcurrencyLimit int
}

// DefaultPolicy returns a sensible default (300/min, burst 60).
func DefaultPolicy() Policy {
	return Policy{
		Limit:   300,
		Window:  60 * time.Second,
		Burst:   60,
		Scope:   "default",
		Enabled: true,
		Cost:    1,
	}
}

// PublicBrowsePolicy is a generous limit for anonymous page browsing.
func PublicBrowsePolicy() Policy {
	return Policy{
		Limit:   300,
		Window:  60 * time.Second,
		Burst:   60,
		Scope:   "public_browse",
		Enabled: true,
		Cost:    1,
	}
}

// APIDefaultPolicy is the standard limit for authenticated API traffic.
func APIDefaultPolicy() Policy {
	return Policy{
		Limit:   120,
		Window:  60 * time.Second,
		Burst:   30,
		Scope:   "api_default",
		Enabled: true,
		Cost:    1,
	}
}

// AuthSensitivePolicy is a tight limit for login / password-reset.
func AuthSensitivePolicy() Policy {
	return Policy{
		Limit:   10,
		Window:  60 * time.Second,
		Burst:   0,
		Scope:   "auth_sensitive",
		Enabled: true,
		Cost:    1,
	}
}

// ExportsPolicy is very tight plus concurrency cap.
func ExportsPolicy() Policy {
	return Policy{
		Limit:            10,
		Window:           60 * time.Second,
		Burst:            0,
		Scope:            "exports",
		Enabled:          true,
		Cost:             1,
		ConcurrencyLimit: 1,
	}
}
