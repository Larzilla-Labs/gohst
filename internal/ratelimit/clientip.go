package ratelimit

import (
	"net"
	"net/http"
	"strings"

	"gohst/internal/config"
)

// ──────────────────────────────────────────────
// Client IP resolution
// ──────────────────────────────────────────────

// ClientIP extracts the real client IP from the request, respecting trusted
// proxies from config.RateLimit.TrustedProxies. The rules:
//
//  1. If the immediate peer (RemoteAddr) is NOT in TrustedProxies, return it.
//  2. If the peer IS trusted, inspect X-Real-IP first, then X-Forwarded-For
//     (rightmost untrusted entry).
//  3. Strip port, normalise IPv6.
func ClientIP(r *http.Request) string {
	peerIP := extractIP(r.RemoteAddr)

	// Guard: config may not be initialised (e.g. in tests).
	var trusted []string
	if config.RateLimit != nil {
		trusted = config.RateLimit.TrustedProxies
	}

	// If no trusted proxies configured, or peer is not trusted, return peer IP.
	if len(trusted) == 0 || !isTrusted(peerIP, trusted) {
		return normalizeIP(peerIP)
	}

	// Try X-Real-IP first (single value set by Nginx, etc.)
	if realIP := r.Header.Get("X-Real-IP"); realIP != "" {
		return normalizeIP(strings.TrimSpace(realIP))
	}

	// Walk X-Forwarded-For from right to left; return the first untrusted IP.
	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		parts := strings.Split(xff, ",")
		for i := len(parts) - 1; i >= 0; i-- {
			ip := strings.TrimSpace(parts[i])
			if ip == "" {
				continue
			}
			if !isTrusted(ip, trusted) {
				return normalizeIP(ip)
			}
		}
		// All entries are trusted? Fall back to leftmost.
		if first := strings.TrimSpace(parts[0]); first != "" {
			return normalizeIP(first)
		}
	}

	return normalizeIP(peerIP)
}

// extractIP strips the port from host:port strings.
func extractIP(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr // already bare IP
	}
	return host
}

// normalizeIP normalises an IP string: trims whitespace, parses + re-serialises
// so that IPv4-mapped-IPv6 and other variants are standardised.
func normalizeIP(raw string) string {
	raw = strings.TrimSpace(raw)
	ip := net.ParseIP(raw)
	if ip == nil {
		return raw
	}
	return ip.String()
}

// isTrusted returns true if `ip` matches any entry in the trusted list.
// Entries can be plain IPs ("10.0.0.1") or CIDRs ("10.0.0.0/8").
func isTrusted(ip string, trusted []string) bool {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}
	for _, entry := range trusted {
		// CIDR check
		if strings.Contains(entry, "/") {
			_, cidr, err := net.ParseCIDR(entry)
			if err != nil {
				continue
			}
			if cidr.Contains(parsedIP) {
				return true
			}
		} else {
			// Plain IP comparison
			if net.ParseIP(entry) != nil && net.ParseIP(entry).Equal(parsedIP) {
				return true
			}
		}
	}
	return false
}

// CoarsenIPv6 maps an IPv6 address to its /64 prefix for fairness (optional).
// IPv4 addresses are returned unchanged.
func CoarsenIPv6(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ip
	}
	// IPv4 – no coarsening
	if parsed.To4() != nil {
		return ip
	}
	// Zero-out the last 8 bytes to get a /64. 
	mask := net.CIDRMask(64, 128)
	masked := parsed.Mask(mask)
	return masked.String() + "/64"
}
