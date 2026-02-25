package middleware

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"secuchat/internal/db"
	"secuchat/internal/models"
	"secuchat/internal/session"
)

const (
	csrfTokenLength = 32
	csrfCookieName  = "csrf_token"
	csrfHeaderName  = "X-CSRF-Token"
	csrfExpiry      = 24 * time.Hour
)

var csrfDB *db.Database

func SetCSRFDatabase(database *db.Database) {
	csrfDB = database
}

func generateCSRFToken() (string, error) {
	b := make([]byte, csrfTokenLength)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

func getCSRFCookieToken(r *http.Request) string {
	cookie, err := r.Cookie(csrfCookieName)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(cookie.Value)
}

func csrfTokensEqual(a, b string) bool {
	if len(a) == 0 || len(b) == 0 {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func CSRFMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" || r.Method == "HEAD" || r.Method == "OPTIONS" {
			// Reuse an existing CSRF cookie token to avoid minting unbounded rows on repeated reads.
			token := getCSRFCookieToken(r)
			if token == "" {
				var err error
				token, err = generateCSRFToken()
				if err != nil {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusInternalServerError)
					json.NewEncoder(w).Encode(models.ErrorResponse{
						Error: "Failed to generate CSRF token",
						Code:  "INTERNAL_ERROR",
					})
					return
				}
			}

			sessionID, _, _ := session.GetFromCookie(r)
			if csrfDB != nil {
				if sessionID != "" {
					_ = csrfDB.CreateCSRFTokenWithSession(token, sessionID)
				} else {
					_ = csrfDB.CreateCSRFToken(token)
				}
			}

			http.SetCookie(w, &http.Cookie{
				Name:     csrfCookieName,
				Value:    token,
				Path:     "/",
				HttpOnly: false,
				Secure:   session.IsSecureRequest(r),
				SameSite: http.SameSiteStrictMode,
				MaxAge:   int(csrfExpiry.Seconds()),
			})

			w.Header().Set("X-CSRF-Token", token)
			next.ServeHTTP(w, r)
			return
		}

		cookie, err := r.Cookie(csrfCookieName)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(models.ErrorResponse{
				Error: "CSRF token missing",
				Code:  "CSRF_MISSING",
			})
			return
		}

		headerToken := r.Header.Get(csrfHeaderName)
		if headerToken == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(models.ErrorResponse{
				Error: "CSRF token missing in header",
				Code:  "CSRF_MISSING",
			})
			return
		}

		if !csrfTokensEqual(cookie.Value, headerToken) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(models.ErrorResponse{
				Error: "CSRF token mismatch",
				Code:  "CSRF_MISMATCH",
			})
			return
		}

		sessionID, _, _ := session.GetFromCookie(r)

		if csrfDB != nil {
			var valid bool
			var err error
			if sessionID != "" {
				valid, err = csrfDB.ValidateAndDeleteCSRFTokenWithSession(cookie.Value, sessionID)
			} else {
				valid, err = csrfDB.ValidateAndDeleteCSRFToken(cookie.Value)
			}
			if err != nil || !valid {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				json.NewEncoder(w).Encode(models.ErrorResponse{
					Error: "Invalid or expired CSRF token",
					Code:  "CSRF_INVALID",
				})
				return
			}
		}

		nextToken, err := generateCSRFToken()
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(models.ErrorResponse{
				Error: "Failed to generate CSRF token",
				Code:  "INTERNAL_ERROR",
			})
			return
		}
		if csrfDB != nil {
			if sessionID != "" {
				csrfDB.CreateCSRFTokenWithSession(nextToken, sessionID)
			} else {
				csrfDB.CreateCSRFToken(nextToken)
			}
		}

		http.SetCookie(w, &http.Cookie{
			Name:     csrfCookieName,
			Value:    nextToken,
			Path:     "/",
			HttpOnly: false,
			Secure:   session.IsSecureRequest(r),
			SameSite: http.SameSiteStrictMode,
			MaxAge:   int(csrfExpiry.Seconds()),
		})
		w.Header().Set("X-CSRF-Token", nextToken)

		next.ServeHTTP(w, r)
	})
}
