package ratelimit

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"

	"gohst/internal/auth"
	"gohst/internal/session"
)

// ──────────────────────────────────────────────
// Key types
// ──────────────────────────────────────────────

const (
	KeyTypeToken   = "token"
	KeyTypeUser    = "user"
	KeyTypeSession = "session"
	KeyTypeIP      = "ip"
	KeyTypeIPUA    = "ipua"
	KeyTypeIPRoute = "iproute"
	KeyTypeIPIdent = "ipident"
)

// KeyFunc computes a (key, keyType) pair from a request.
type KeyFunc func(r *http.Request) (key string, keyType string)

// ──────────────────────────────────────────────
// Pre-built key functions
// ──────────────────────────────────────────────

// KeyByIP keys solely by the client IP address.
func KeyByIP() KeyFunc {
	return func(r *http.Request) (string, string) {
		ip := ClientIP(r)
		return "ip:" + ip, KeyTypeIP
	}
}

// KeyByUserElseIP keys by authenticated user ID, falling back to IP.
func KeyByUserElseIP() KeyFunc {
	return func(r *http.Request) (string, string) {
		sess := session.FromContext(r.Context())
		if sess != nil && auth.IsAuthenticated(sess) {
			if uid, ok := sess.Get("user_id"); ok && uid != nil {
				return fmt.Sprintf("user:%v", uid), KeyTypeUser
			}
		}
		ip := ClientIP(r)
		return "ip:" + ip, KeyTypeIP
	}
}

// KeyByTokenElseUserElseIP keys by bearer token hash, then user ID, then IP.
func KeyByTokenElseUserElseIP() KeyFunc {
	return func(r *http.Request) (string, string) {
		// Check for bearer token
		if token := extractBearerToken(r); token != "" {
			return "token:" + hashValue(token), KeyTypeToken
		}
		// Check for authenticated user
		sess := session.FromContext(r.Context())
		if sess != nil && auth.IsAuthenticated(sess) {
			if uid, ok := sess.Get("user_id"); ok && uid != nil {
				return fmt.Sprintf("user:%v", uid), KeyTypeUser
			}
		}
		// Fallback to IP
		ip := ClientIP(r)
		return "ip:" + ip, KeyTypeIP
	}
}

// KeyByIPAndIdentifier creates a composite key from IP + a form/query value,
// ideal for login/reset endpoints where you want to limit attempts on a
// specific account from a specific IP.
//
// The identifier (e.g. email) is normalised and hashed so it is safe to log
// and store.
func KeyByIPAndIdentifier(field string) KeyFunc {
	return func(r *http.Request) (string, string) {
		ip := ClientIP(r)
		identifier := extractIdentifier(r, field)
		return fmt.Sprintf("ipident:%s:%s", ip, hashValue(identifier)), KeyTypeIPIdent
	}
}

// KeyByIPAndRoute creates a composite key from IP + request path,
// useful for limiting expensive endpoints without penalising the whole site.
func KeyByIPAndRoute() KeyFunc {
	return func(r *http.Request) (string, string) {
		ip := ClientIP(r)
		route := r.URL.Path
		return fmt.Sprintf("iproute:%s:%s", ip, route), KeyTypeIPRoute
	}
}

// KeyByIPAndUA creates a composite key from IP + user-agent hash.
func KeyByIPAndUA() KeyFunc {
	return func(r *http.Request) (string, string) {
		ip := ClientIP(r)
		ua := r.Header.Get("User-Agent")
		return fmt.Sprintf("ipua:%s:%s", ip, hashValue(ua)), KeyTypeIPUA
	}
}

// ──────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────

// extractBearerToken pulls a bearer token from the Authorization header.
func extractBearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if h == "" {
		return ""
	}
	const prefix = "Bearer "
	if len(h) > len(prefix) && strings.EqualFold(h[:len(prefix)], prefix) {
		return strings.TrimSpace(h[len(prefix):])
	}
	return ""
}

// extractIdentifier reads a value from form data or query params,
// normalises it (trim + lowercase).
func extractIdentifier(r *http.Request, field string) string {
	// Try form body first (must parse form)
	if r.Method == http.MethodPost || r.Method == http.MethodPut {
		_ = r.ParseForm()
		if v := r.FormValue(field); v != "" {
			return strings.ToLower(strings.TrimSpace(v))
		}
	}
	// Query param fallback
	if v := r.URL.Query().Get(field); v != "" {
		return strings.ToLower(strings.TrimSpace(v))
	}
	return ""
}

// hashValue returns the first 16 chars of the SHA-256 hex digest.
// This is safe to log and store; the original value cannot be recovered.
func hashValue(v string) string {
	h := sha256.Sum256([]byte(v))
	return hex.EncodeToString(h[:])[:16]
}
