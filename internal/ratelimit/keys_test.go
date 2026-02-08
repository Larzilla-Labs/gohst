package ratelimit

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestKeyByIP(t *testing.T) {
	fn := KeyByIP()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "1.2.3.4:9999"

	key, keyType := fn(r)
	if keyType != KeyTypeIP {
		t.Fatalf("expected keyType %q, got %q", KeyTypeIP, keyType)
	}
	if key != "ip:1.2.3.4" {
		t.Fatalf("expected key ip:1.2.3.4, got %s", key)
	}
}

func TestKeyByIPAndRoute(t *testing.T) {
	fn := KeyByIPAndRoute()
	r := httptest.NewRequest(http.MethodGet, "/api/export", nil)
	r.RemoteAddr = "10.0.0.1:1234"

	key, keyType := fn(r)
	if keyType != KeyTypeIPRoute {
		t.Fatalf("expected keyType %q, got %q", KeyTypeIPRoute, keyType)
	}
	expected := "iproute:10.0.0.1:/api/export"
	if key != expected {
		t.Fatalf("expected key %q, got %q", expected, key)
	}
}

func TestKeyByIPAndUA(t *testing.T) {
	fn := KeyByIPAndUA()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "10.0.0.1:1234"
	r.Header.Set("User-Agent", "Mozilla/5.0")

	key, keyType := fn(r)
	if keyType != KeyTypeIPUA {
		t.Fatalf("expected keyType %q, got %q", KeyTypeIPUA, keyType)
	}
	if key == "" {
		t.Fatal("key should not be empty")
	}
}

func TestExtractBearerToken(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer my-secret-token")

	tok := extractBearerToken(r)
	if tok != "my-secret-token" {
		t.Fatalf("expected my-secret-token, got %s", tok)
	}

	// No header
	r2 := httptest.NewRequest(http.MethodGet, "/", nil)
	if extractBearerToken(r2) != "" {
		t.Fatal("should return empty when no header")
	}
}

func TestHashValue_Deterministic(t *testing.T) {
	a := hashValue("test@example.com")
	b := hashValue("test@example.com")
	if a != b {
		t.Fatal("hash should be deterministic")
	}
	if len(a) != 16 {
		t.Fatalf("expected 16 char hash, got %d", len(a))
	}
}

func TestHashValue_DifferentInputs(t *testing.T) {
	a := hashValue("alice@example.com")
	b := hashValue("bob@example.com")
	if a == b {
		t.Fatal("different inputs should produce different hashes")
	}
}
