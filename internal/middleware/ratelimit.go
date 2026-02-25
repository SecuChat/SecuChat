package middleware

import (
	"context"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

type RateLimiter struct {
	visitors       map[string]*visitor
	mu             sync.RWMutex
	rate           int
	window         time.Duration
	trustedProxies map[string]bool
}

type visitor struct {
	lastSeen time.Time
	count    int
}

func NewRateLimiter(ctx context.Context, rate int, window time.Duration) *RateLimiter {
	rl := &RateLimiter{
		visitors:       make(map[string]*visitor),
		rate:           rate,
		window:         window,
		trustedProxies: make(map[string]bool),
	}
	go rl.cleanup(ctx)
	return rl
}

func (rl *RateLimiter) SetTrustedProxies(proxies []string) {
	for _, p := range proxies {
		p = strings.TrimSpace(p)
		if p != "" {
			if strings.Contains(p, "/") {
				_, ipNet, err := net.ParseCIDR(p)
				if err == nil {
					rl.trustedProxies[ipNet.String()] = true
					continue
				}
			}
			if parsed := net.ParseIP(p); parsed != nil {
				rl.trustedProxies[parsed.String()] = true
				continue
			}
			rl.trustedProxies[p] = true
		}
	}
}

func (rl *RateLimiter) isTrustedProxy(ip string) bool {
	if len(rl.trustedProxies) == 0 {
		return false
	}

	if rl.trustedProxies[ip] {
		return true
	}

	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}

	for proxy := range rl.trustedProxies {
		if strings.Contains(proxy, "/") {
			_, ipNet, err := net.ParseCIDR(proxy)
			if err == nil && ipNet.Contains(parsedIP) {
				return true
			}
		}
	}

	return false
}

func (rl *RateLimiter) cleanup(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			rl.mu.Lock()
			for ip, v := range rl.visitors {
				if time.Since(v.lastSeen) > rl.window {
					delete(rl.visitors, ip)
				}
			}
			rl.mu.Unlock()
		}
	}
}

func (rl *RateLimiter) getIP(r *http.Request) string {
	remoteIP, ok := normalizeIP(r.RemoteAddr)
	if !ok {
		return r.RemoteAddr
	}

	if len(rl.trustedProxies) == 0 || !rl.isTrustedProxy(remoteIP) {
		return remoteIP
	}

	forwarded := r.Header.Get("X-Forwarded-For")
	if forwarded == "" {
		return remoteIP
	}

	parts := strings.Split(forwarded, ",")
	chain := make([]string, 0, len(parts)+1)
	for _, part := range parts {
		if ip, ok := normalizeIP(part); ok {
			chain = append(chain, ip)
		}
	}
	if len(chain) == 0 {
		return remoteIP
	}

	// Trust only hops that are known proxies, then pick the nearest untrusted hop.
	for i := len(chain) - 1; i >= 0; i-- {
		if !rl.isTrustedProxy(chain[i]) {
			return chain[i]
		}
	}

	// All forwarded hops are trusted proxies; use the oldest forwarded hop.
	return chain[0]
}

func normalizeIP(raw string) (string, bool) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", false
	}

	if host, _, err := net.SplitHostPort(value); err == nil {
		value = strings.TrimSpace(host)
	}
	value = strings.TrimPrefix(value, "[")
	value = strings.TrimSuffix(value, "]")

	parsed := net.ParseIP(value)
	if parsed == nil {
		return "", false
	}
	return parsed.String(), true
}

func (rl *RateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := rl.getIP(r)

		rl.mu.Lock()
		v, exists := rl.visitors[ip]
		if !exists {
			rl.visitors[ip] = &visitor{
				lastSeen: time.Now(),
				count:    1,
			}
			rl.mu.Unlock()
			next.ServeHTTP(w, r)
			return
		}

		if time.Since(v.lastSeen) > rl.window {
			v.count = 1
			v.lastSeen = time.Now()
		} else {
			v.count++
			v.lastSeen = time.Now()
		}
		count := v.count
		rl.mu.Unlock()

		if count > rl.rate {
			WriteJSONError(w, "Too many requests. Please try again later.", "RATE_LIMITED", http.StatusTooManyRequests)
			return
		}

		next.ServeHTTP(w, r)
	})
}
