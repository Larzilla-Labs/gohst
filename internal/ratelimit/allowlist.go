package ratelimit

import (
	"net"
	"net/http"
	"strings"
)

// ──────────────────────────────────────────────
// Allowlist / bypass rules
// ──────────────────────────────────────────────

// AllowRule determines whether a request should bypass rate limiting.
type AllowRule interface {
	Matches(r *http.Request) bool
}

// BypassLocalDev bypasses all requests from loopback addresses (127.0.0.1, ::1).
type BypassLocalDev struct{}

func (BypassLocalDev) Matches(r *http.Request) bool {
	ip := ClientIP(r)
	parsed := net.ParseIP(ip)
	return parsed != nil && parsed.IsLoopback()
}

// BypassPaths bypasses requests whose path has a given prefix (e.g. /healthz).
type BypassPaths struct {
	Prefixes []string
}

func (b BypassPaths) Matches(r *http.Request) bool {
	for _, p := range b.Prefixes {
		if strings.HasPrefix(r.URL.Path, p) {
			return true
		}
	}
	return false
}

// BypassIPs bypasses requests from specific IPs or CIDRs.
type BypassIPs struct {
	Allowed []string
}

func (b BypassIPs) Matches(r *http.Request) bool {
	ip := ClientIP(r)
	return isTrusted(ip, b.Allowed)
}

// BypassHeader bypasses requests that carry a specific header value,
// useful for service-to-service communication with an internal token.
// IMPORTANT: the value should be hashed before comparison in production.
type BypassHeader struct {
	Header string
	Value  string
}

func (b BypassHeader) Matches(r *http.Request) bool {
	return r.Header.Get(b.Header) == b.Value
}
