package middleware

import (
	"encoding/json"
	"net/http"

	"secuchat/internal/db"
	"secuchat/internal/models"
	"secuchat/internal/session"
)

var authDB *db.Database

func SetAuthDatabase(database *db.Database) {
	authDB = database
}

func WriteJSONError(w http.ResponseWriter, message, code string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(models.ErrorResponse{
		Error: message,
		Code:  code,
	})
}

func RequireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sessionID, userID, _ := session.GetFromCookie(r)
		if userID == "" {
			WriteJSONError(w, "Not authenticated", "UNAUTHORIZED", http.StatusUnauthorized)
			return
		}

		if authDB != nil {
			valid, err := authDB.ValidateSession(sessionID, userID)
			if err != nil || !valid {
				WriteJSONError(w, "Session expired or invalid", "SESSION_INVALID", http.StatusUnauthorized)
				return
			}
		}

		next(w, r)
	}
}

func RequireAuthHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sessionID, userID, _ := session.GetFromCookie(r)
		if userID == "" {
			WriteJSONError(w, "Not authenticated", "UNAUTHORIZED", http.StatusUnauthorized)
			return
		}

		if authDB != nil {
			valid, err := authDB.ValidateSession(sessionID, userID)
			if err != nil || !valid {
				WriteJSONError(w, "Session expired or invalid", "SESSION_INVALID", http.StatusUnauthorized)
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}
