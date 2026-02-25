package handler

import (
	"net/http/httptest"
	"testing"
)

func TestCheckOriginSchemeAndHostValidation(t *testing.T) {
	SetAllowedOrigins([]string{"https://chat.example.com"})

	allowedReq := httptest.NewRequest("GET", "http://localhost/ws", nil)
	allowedReq.Header.Set("Origin", "https://chat.example.com")
	if !checkOrigin(allowedReq) {
		t.Fatalf("expected matching https origin to be allowed")
	}

	disallowedReq := httptest.NewRequest("GET", "http://localhost/ws", nil)
	disallowedReq.Header.Set("Origin", "http://chat.example.com")
	if checkOrigin(disallowedReq) {
		t.Fatalf("expected http origin to be rejected when https origin is configured")
	}
}

func TestCheckOriginRequiresExactHTTPSMatch(t *testing.T) {
	SetAllowedOrigins([]string{"https://chat.example.com"})

	wrongHostReq := httptest.NewRequest("GET", "http://localhost/ws", nil)
	wrongHostReq.Header.Set("Origin", "https://sub.example.com")
	if checkOrigin(wrongHostReq) {
		t.Fatalf("expected non-configured host to be rejected")
	}

	bareHostReq := httptest.NewRequest("GET", "http://localhost/ws", nil)
	bareHostReq.Header.Set("Origin", "chat.example.com")
	if checkOrigin(bareHostReq) {
		t.Fatalf("expected non-origin bare host value to be rejected")
	}
}
