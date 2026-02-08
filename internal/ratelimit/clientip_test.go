package ratelimit

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClientIP_RemoteAddrDirect(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "192.168.1.100:12345"

	ip := ClientIP(r)
	if ip != "192.168.1.100" {
		t.Fatalf("expected 192.168.1.100, got %s", ip)
	}
}

func TestClientIP_IPv6(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "[::1]:12345"

	ip := ClientIP(r)
	if ip != "::1" {
		t.Fatalf("expected ::1, got %s", ip)
	}
}

func TestNormalizeIP(t *testing.T) {
	cases := []struct {
		input    string
		expected string
	}{
		{"192.168.1.1", "192.168.1.1"},
		{"::1", "::1"},
		{"  10.0.0.1 ", "10.0.0.1"},
		{"::ffff:192.168.1.1", "192.168.1.1"}, // IPv4-mapped IPv6
	}

	for _, tc := range cases {
		got := normalizeIP(tc.input)
		if got != tc.expected {
			t.Errorf("normalizeIP(%q) = %q, want %q", tc.input, got, tc.expected)
		}
	}
}

func TestIsTrusted(t *testing.T) {
	trusted := []string{"10.0.0.0/8", "172.16.0.1"}

	cases := []struct {
		ip       string
		expected bool
	}{
		{"10.0.0.1", true},
		{"10.255.255.255", true},
		{"172.16.0.1", true},
		{"172.16.0.2", false},
		{"192.168.1.1", false},
	}

	for _, tc := range cases {
		got := isTrusted(tc.ip, trusted)
		if got != tc.expected {
			t.Errorf("isTrusted(%q) = %v, want %v", tc.ip, got, tc.expected)
		}
	}
}

func TestCoarsenIPv6(t *testing.T) {
	// IPv4 unchanged
	if got := CoarsenIPv6("192.168.1.1"); got != "192.168.1.1" {
		t.Fatalf("IPv4 should be unchanged, got %s", got)
	}

	// IPv6 coarsened to /64
	result := CoarsenIPv6("2001:db8:85a3::8a2e:370:7334")
	if result != "2001:db8:85a3::/64" {
		t.Fatalf("expected 2001:db8:85a3::/64, got %s", result)
	}
}
