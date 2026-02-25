package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"secuchat/internal/db"
	"secuchat/internal/handler"
	"secuchat/internal/middleware"
	"secuchat/internal/session"
)

const (
	InactiveRoomExpiryDays = 30
)

func main() {
	sessionSecret := os.Getenv("SESSION_SECRET")
	if sessionSecret == "" {
		log.Fatal("SESSION_SECRET environment variable is required")
	}
	if len(sessionSecret) < 32 {
		log.Fatal("SESSION_SECRET must be at least 32 characters")
	}
	session.SetSecret(sessionSecret)

	allowedOriginsEnv := os.Getenv("ALLOWED_ORIGINS")
	if allowedOriginsEnv == "" {
		log.Fatal("ALLOWED_ORIGINS environment variable is required for production security. Set to your domain (e.g., 'https://chat.example.com') or comma-separated list.")
	}
	allowedOrigins, err := parseAllowedOrigins(allowedOriginsEnv)
	if err != nil {
		log.Fatal(err)
	}
	handler.SetAllowedOrigins(allowedOrigins)

	trustedProxies := os.Getenv("TRUSTED_PROXIES")
	session.SetTrustedProxies(trustedProxies)

	dbPath := os.Getenv("DB_PATH")
	if dbPath == "" {
		dbPath = "secuchat.db"
	}
	database, err := db.New(dbPath)
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}
	defer database.Close()

	middleware.SetCSRFDatabase(database)
	middleware.SetAuthDatabase(database)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go runCleanupTasks(ctx, database)

	slog.Info("Database initialized successfully")

	wsHandler := handler.NewWSHandler(database)
	authHandler := &handler.AuthHandler{DB: database, WS: wsHandler}
	roomHandler := &handler.RoomHandler{DB: database}

	rateLimiter := middleware.NewRateLimiter(ctx, 10, time.Minute)
	sensitiveLimiter := middleware.NewRateLimiter(ctx, 5, time.Minute)
	csrfBootstrapLimiter := middleware.NewRateLimiter(ctx, 60, time.Minute)
	if trustedProxies != "" {
		proxies := strings.Split(trustedProxies, ",")
		rateLimiter.SetTrustedProxies(proxies)
		sensitiveLimiter.SetTrustedProxies(proxies)
		csrfBootstrapLimiter.SetTrustedProxies(proxies)
	}

	mux := http.NewServeMux()

	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := database.Ping(); err != nil {
			slog.Error("Health check failed", "error", err)
			w.WriteHeader(http.StatusServiceUnavailable)
			json.NewEncoder(w).Encode(map[string]string{
				"status":   "unhealthy",
				"database": "disconnected",
			})
			return
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "healthy"})
	})

	mux.HandleFunc("POST /api/auth/create", rateLimiter.Middleware(csrfProtected(http.HandlerFunc(authHandler.CreateAccount))).ServeHTTP)
	mux.HandleFunc("POST /api/auth/login", rateLimiter.Middleware(csrfProtected(http.HandlerFunc(authHandler.Login))).ServeHTTP)
	mux.HandleFunc("POST /api/auth/verify", rateLimiter.Middleware(csrfProtected(http.HandlerFunc(authHandler.Verify))).ServeHTTP)
	mux.HandleFunc("GET /api/auth/me", csrfBootstrapLimiter.Middleware(middleware.CSRFMiddleware(http.HandlerFunc(authHandler.GetMe))).ServeHTTP)
	mux.HandleFunc("POST /api/auth/logout", csrfProtected(http.HandlerFunc(authHandler.Logout)).ServeHTTP)
	mux.HandleFunc("GET /api/users/{id}/key", middleware.RequireAuth(http.HandlerFunc(authHandler.GetUserKey)).ServeHTTP)

	mux.HandleFunc("POST /api/auth/delete-account", middleware.RequireAuthHandler(sensitiveLimiter.Middleware(csrfProtected(http.HandlerFunc(authHandler.DeleteAccount)))).ServeHTTP)
	mux.HandleFunc("POST /api/auth/confirm-delete", middleware.RequireAuthHandler(sensitiveLimiter.Middleware(csrfProtected(http.HandlerFunc(authHandler.ConfirmDeleteAccount)))).ServeHTTP)
	mux.HandleFunc("POST /api/auth/rotate-keys", middleware.RequireAuthHandler(sensitiveLimiter.Middleware(csrfProtected(http.HandlerFunc(authHandler.RotateKeys)))).ServeHTTP)
	mux.HandleFunc("POST /api/auth/confirm-rotate-keys", middleware.RequireAuthHandler(sensitiveLimiter.Middleware(csrfProtected(http.HandlerFunc(authHandler.ConfirmRotateKeys)))).ServeHTTP)

	mux.HandleFunc("GET /api/rooms", middleware.RequireAuth(http.HandlerFunc(roomHandler.ListRooms)).ServeHTTP)
	mux.HandleFunc("POST /api/rooms", middleware.RequireAuth(csrfProtected(http.HandlerFunc(roomHandler.CreateRoom))).ServeHTTP)
	mux.HandleFunc("GET /api/rooms/{id}", middleware.RequireAuth(http.HandlerFunc(roomHandler.GetRoom)).ServeHTTP)
	mux.HandleFunc("POST /api/rooms/{id}/join", middleware.RequireAuth(csrfProtected(http.HandlerFunc(roomHandler.JoinRoom))).ServeHTTP)
	mux.HandleFunc("POST /api/rooms/join-by-code", middleware.RequireAuthHandler(sensitiveLimiter.Middleware(csrfProtected(http.HandlerFunc(roomHandler.JoinRoomByCode)))).ServeHTTP)
	mux.HandleFunc("POST /api/rooms/{id}/leave", middleware.RequireAuth(csrfProtected(http.HandlerFunc(roomHandler.LeaveRoom))).ServeHTTP)
	mux.HandleFunc("GET /api/rooms/{id}/members", middleware.RequireAuth(http.HandlerFunc(roomHandler.GetRoomMembers)).ServeHTTP)
	mux.HandleFunc("POST /api/rooms/{id}/regenerate-code", middleware.RequireAuth(csrfProtected(http.HandlerFunc(roomHandler.RegenerateInviteCode))).ServeHTTP)

	mux.HandleFunc("GET /ws", wsHandler.HandleWebSocket)

	fs := http.FileServer(http.Dir("web"))
	mux.Handle("/", fs)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	server := &http.Server{
		Addr:        ":" + port,
		Handler:     bodyLimitMiddleware(securityHeadersMiddleware(corsMiddleware(loggingMiddleware(mux), allowedOrigins))),
		ReadTimeout: 15 * time.Second,
		IdleTimeout: 60 * time.Second,
	}

	go func() {
		slog.Info("SecuChat server starting", "port", port)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal("Server error:", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	slog.Info("Shutting down server...")
	cancel()

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		slog.Error("Server shutdown error", "error", err)
	}

	slog.Info("Server stopped")
}

func runCleanupTasks(ctx context.Context, database *db.Database) {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			slog.Info("Cleanup tasks stopped")
			return
		case <-ticker.C:
			cleanedChallenges, err := database.CleanupChallenges(5 * time.Minute)
			if err != nil {
				slog.Error("Failed to cleanup challenges", "error", err)
			} else if cleanedChallenges > 0 {
				slog.Debug("Cleaned up expired challenges", "count", cleanedChallenges)
			}

			cleanedCSRF, err := database.CleanupCSRFTokens(24 * time.Hour)
			if err != nil {
				slog.Error("Failed to cleanup CSRF tokens", "error", err)
			} else if cleanedCSRF > 0 {
				slog.Debug("Cleaned up expired CSRF tokens", "count", cleanedCSRF)
			}

			cleanedSessions, err := database.CleanupExpiredSessions()
			if err != nil {
				slog.Error("Failed to cleanup expired sessions", "error", err)
			} else if cleanedSessions > 0 {
				slog.Info("Cleaned up expired sessions", "count", cleanedSessions)
			}

			cleanedRooms, err := database.CleanupInactiveRooms(InactiveRoomExpiryDays * 24 * time.Hour)
			if err != nil {
				slog.Error("Failed to cleanup inactive rooms", "error", err)
			} else if cleanedRooms > 0 {
				slog.Info("Cleaned up inactive rooms", "count", cleanedRooms, "inactive_days", InactiveRoomExpiryDays)
			}
		}
	}
}

func csrfProtected(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		middleware.CSRFMiddleware(next).ServeHTTP(w, r)
	}
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		slog.Debug("HTTP request",
			"method", r.Method,
			"path", r.URL.Path,
			"duration", time.Since(start),
			"remote_addr", r.RemoteAddr,
		)
	})
}

func securityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			// Avoid caching responses that may include credentials, key material, or CSRF tokens.
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Pragma", "no-cache")
		}
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; "+
				"script-src 'self'; "+
				"style-src 'self'; "+
				"img-src 'self' data:; "+
				"connect-src 'self'; "+
				"font-src 'self'; "+
				"frame-ancestors 'none'; "+
				"base-uri 'self'; "+
				"form-action 'self'")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
		next.ServeHTTP(w, r)
	})
}

const maxBodySize = 64 * 1024

func bodyLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" || r.Method == "PUT" {
			r.Body = http.MaxBytesReader(w, r.Body, maxBodySize)
		}
		next.ServeHTTP(w, r)
	})
}

func corsMiddleware(next http.Handler, allowedOrigins []string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")

		if origin != "" && isOriginAllowed(origin, allowedOrigins) {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Add("Vary", "Origin")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-CSRF-Token")
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Max-Age", "86400")
		}

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func parseAllowedOrigins(raw string) ([]string, error) {
	parts := strings.Split(raw, ",")
	origins := make([]string, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))

	for _, entry := range parts {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if entry == "*" || strings.HasPrefix(entry, "*.") {
			return nil, fmt.Errorf("ALLOWED_ORIGINS entries must be full https origins; wildcard values are not allowed: %q", entry)
		}

		normalized, ok := normalizeHTTPSOrigin(entry)
		if !ok {
			return nil, fmt.Errorf("ALLOWED_ORIGINS entry is invalid (%q). Use full https origins only, e.g. https://chat.example.com", entry)
		}

		if _, exists := seen[normalized]; exists {
			continue
		}
		seen[normalized] = struct{}{}
		origins = append(origins, normalized)
	}

	if len(origins) == 0 {
		return nil, fmt.Errorf("ALLOWED_ORIGINS must include at least one full https origin")
	}
	return origins, nil
}

func isOriginAllowed(origin string, allowedOrigins []string) bool {
	normalizedOrigin, ok := normalizeHTTPSOrigin(origin)
	if !ok {
		return false
	}

	for _, allowed := range allowedOrigins {
		if strings.EqualFold(strings.TrimSpace(allowed), normalizedOrigin) {
			return true
		}
	}

	return false
}

func normalizeHTTPSOrigin(origin string) (string, bool) {
	originURL, err := url.Parse(strings.TrimSpace(origin))
	if err != nil || originURL.Scheme == "" || originURL.Host == "" {
		return "", false
	}
	if !strings.EqualFold(originURL.Scheme, "https") {
		return "", false
	}
	if (originURL.Path != "" && originURL.Path != "/") || originURL.RawQuery != "" || originURL.Fragment != "" || originURL.User != nil {
		return "", false
	}
	return "https://" + strings.ToLower(originURL.Host), true
}
