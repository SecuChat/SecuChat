package middleware

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRateLimiterGetIPIgnoresForwardedWithoutTrustedProxy(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	rl := NewRateLimiter(ctx, 10, time.Minute)
	req := httptest.NewRequest("GET", "http://localhost", nil)
	req.RemoteAddr = "192.0.2.10:54321"
	req.Header.Set("X-Forwarded-For", "203.0.113.50")

	got := rl.getIP(req)
	if got != "192.0.2.10" {
		t.Fatalf("expected direct remote IP, got %q", got)
	}
}

func TestRateLimiterGetIPUsesNearestUntrustedForwardedHop(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	rl := NewRateLimiter(ctx, 10, time.Minute)
	rl.SetTrustedProxies([]string{"10.0.0.0/8"})

	req := httptest.NewRequest("GET", "http://localhost", nil)
	req.RemoteAddr = "10.1.2.3:44321"
	req.Header.Set("X-Forwarded-For", "198.51.100.66, 203.0.113.10, 10.1.2.3")

	got := rl.getIP(req)
	if got != "203.0.113.10" {
		t.Fatalf("expected nearest untrusted forwarded hop, got %q", got)
	}
}

func TestRateLimiterGetIPFallsBackToOldestWhenAllForwardedTrusted(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	rl := NewRateLimiter(ctx, 10, time.Minute)
	rl.SetTrustedProxies([]string{"10.0.0.0/8"})

	req := httptest.NewRequest("GET", "http://localhost", nil)
	req.RemoteAddr = "10.1.2.3:44321"
	req.Header.Set("X-Forwarded-For", "10.9.9.9, 10.2.2.2")

	got := rl.getIP(req)
	if got != "10.9.9.9" {
		t.Fatalf("expected oldest forwarded hop when all are trusted, got %q", got)
	}
}
