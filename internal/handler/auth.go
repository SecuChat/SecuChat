package handler

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"secuchat/internal/db"
	"secuchat/internal/models"
	"secuchat/internal/session"
)

const (
	BcryptCost        = 12
	ChallengeExpiry   = 5 * time.Minute
	MaxChallengePerIP = 10
	PasswordMinLength = 8
	UsernameMinLength = 3
	UsernameMaxLength = 32
	MaxRoomsPerUser   = 256
	MaxMembersPerRoom = 256
)

var usernameRegex = regexp.MustCompile(`^[a-zA-Z0-9_]+$`)
var dummyPasswordHash []byte

func hashPasswordForBcrypt(password string) []byte {
	h := sha256.Sum256([]byte(password))
	return []byte(hex.EncodeToString(h[:]))
}

func init() {
	dummyPasswordHash, _ = bcrypt.GenerateFromPassword(hashPasswordForBcrypt("dummy_password_for_constant_time"), BcryptCost)
}

var allowedOrigins []string

func SetAllowedOrigins(origins []string) {
	allowedOrigins = make([]string, len(origins))
	for i, o := range origins {
		allowedOrigins[i] = strings.TrimSpace(o)
	}
}

type AuthHandler struct {
	DB *db.Database
	WS *WSHandler
}

type CreateAccountRequest struct {
	Username   string             `json:"username"`
	Password   string             `json:"password"`
	PublicKey  models.Base64Bytes `json:"public_key"`
	SigningKey models.Base64Bytes `json:"signing_key"`
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type VerifyRequest struct {
	Username  string             `json:"username"`
	Nonce     string             `json:"nonce"`
	Signature models.Base64Bytes `json:"signature"`
}

type DeleteAccountRequest struct {
	Password     string `json:"password"`
	Confirmation string `json:"confirmation"`
}

type ConfirmDeleteRequest struct {
	Nonce     string             `json:"nonce"`
	Signature models.Base64Bytes `json:"signature"`
}

type RotateKeysRequest struct {
	Password string `json:"password"`
}

type ConfirmRotateKeysRequest struct {
	Nonce         string             `json:"nonce"`
	Signature     models.Base64Bytes `json:"signature"`
	NewPublicKey  models.Base64Bytes `json:"new_public_key"`
	NewSigningKey models.Base64Bytes `json:"new_signing_key"`
}

type ChallengeResponse struct {
	Nonce     string `json:"nonce"`
	ExpiresAt int64  `json:"expires_at"`
	UserID    string `json:"user_id"`
}

func generateID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func generateNonce() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

func hmacSHA256(data string) string {
	return session.HmacSHA256(data)
}

func isValidUsername(username string) bool {
	if len(username) < UsernameMinLength || len(username) > UsernameMaxLength {
		return false
	}
	return usernameRegex.MatchString(username)
}

func isStrongPassword(password string) bool {
	if len(password) < PasswordMinLength {
		return false
	}
	hasUpper := false
	hasLower := false
	hasDigit := false
	hasSpecial := false

	for _, c := range password {
		switch {
		case 'A' <= c && c <= 'Z':
			hasUpper = true
		case 'a' <= c && c <= 'z':
			hasLower = true
		case '0' <= c && c <= '9':
			hasDigit = true
		case strings.ContainsRune("!@#$%^&*()_+-=[]{}|;:',.<>?/~`", c):
			hasSpecial = true
		}
	}
	return hasUpper && hasLower && hasDigit && hasSpecial
}

func writeJSONError(w http.ResponseWriter, message, code string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(models.ErrorResponse{
		Error: message,
		Code:  code,
	})
}

func (h *AuthHandler) CreateAccount(w http.ResponseWriter, r *http.Request) {
	var req CreateAccountRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, "Invalid request body", "INVALID_REQUEST", http.StatusBadRequest)
		return
	}

	if !isValidUsername(req.Username) {
		writeJSONError(w, "Username must be 3-32 characters and contain only letters, numbers, and underscores", "INVALID_USERNAME", http.StatusBadRequest)
		return
	}

	if !isStrongPassword(req.Password) {
		writeJSONError(w, "Password must be at least 8 characters and contain uppercase, lowercase, a digit, and a special character", "INVALID_PASSWORD", http.StatusBadRequest)
		return
	}

	if len(req.PublicKey) == 0 {
		writeJSONError(w, "Public key is required", "MISSING_PUBLIC_KEY", http.StatusBadRequest)
		return
	}

	if len(req.SigningKey) == 0 {
		writeJSONError(w, "Signing key is required", "MISSING_SIGNING_KEY", http.StatusBadRequest)
		return
	}

	passwordHash, err := bcrypt.GenerateFromPassword(hashPasswordForBcrypt(req.Password), BcryptCost)
	if err != nil {
		writeJSONError(w, "Failed to process password", "INTERNAL_ERROR", http.StatusInternalServerError)
		return
	}

	id, err := generateID()
	if err != nil {
		writeJSONError(w, "Failed to generate account identifier", "INTERNAL_ERROR", http.StatusInternalServerError)
		return
	}

	if err := h.DB.CreateUserIfNotExists(id, req.Username, string(passwordHash), []byte(req.PublicKey), []byte(req.SigningKey)); err != nil {
		if errors.Is(err, db.ErrUserExists) {
			writeJSONError(w, "Invalid request", "INVALID_REQUEST", http.StatusBadRequest)
			return
		}
		writeJSONError(w, "Failed to create account", "INTERNAL_ERROR", http.StatusInternalServerError)
		return
	}

	if err := setSessionCookie(w, r, h.DB, id, req.Username); err != nil {
		writeJSONError(w, "Failed to create session", "INTERNAL_ERROR", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{
		"id":       id,
		"username": req.Username,
	})
}

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, "Invalid request body", "INVALID_REQUEST", http.StatusBadRequest)
		return
	}

	if req.Username == "" || req.Password == "" {
		_ = bcrypt.CompareHashAndPassword(dummyPasswordHash, hashPasswordForBcrypt(req.Password))
		time.Sleep(100 * time.Millisecond)
		writeJSONError(w, "Invalid credentials", "INVALID_CREDENTIALS", http.StatusUnauthorized)
		return
	}

	user, err := h.DB.GetUserByUsername(req.Username)
	if err != nil {
		_ = bcrypt.CompareHashAndPassword(dummyPasswordHash, hashPasswordForBcrypt(req.Password))
		time.Sleep(100 * time.Millisecond)
		writeJSONError(w, "Invalid credentials", "INVALID_CREDENTIALS", http.StatusUnauthorized)
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), hashPasswordForBcrypt(req.Password)); err != nil {
		time.Sleep(100 * time.Millisecond)
		writeJSONError(w, "Invalid credentials", "INVALID_CREDENTIALS", http.StatusUnauthorized)
		return
	}

	challengeCount, err := h.DB.CountUserChallenges(user.ID)
	if err != nil {
		writeJSONError(w, "Failed to check challenge count", "INTERNAL_ERROR", http.StatusInternalServerError)
		return
	}
	if challengeCount >= MaxChallengePerIP {
		writeJSONError(w, "Too many pending challenges", "RATE_LIMITED", http.StatusTooManyRequests)
		return
	}

	nonce, err := generateNonce()
	if err != nil {
		writeJSONError(w, "Failed to create challenge", "INTERNAL_ERROR", http.StatusInternalServerError)
		return
	}
	expiresAt := time.Now().Add(ChallengeExpiry)

	if err := h.DB.CreateChallenge(nonce, user.ID); err != nil {
		writeJSONError(w, "Failed to create challenge", "INTERNAL_ERROR", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(ChallengeResponse{
		Nonce:     nonce,
		ExpiresAt: expiresAt.Unix(),
		UserID:    user.ID,
	})
}

func (h *AuthHandler) Verify(w http.ResponseWriter, r *http.Request) {
	var req VerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, "Invalid request body", "INVALID_REQUEST", http.StatusBadRequest)
		return
	}

	if req.Username == "" || req.Nonce == "" || len(req.Signature) == 0 {
		writeJSONError(w, "Missing required fields", "INVALID_REQUEST", http.StatusBadRequest)
		return
	}

	userID, createdAt, err := h.DB.GetAndDeleteChallenge(req.Nonce)
	if err != nil {
		writeJSONError(w, "Invalid or expired challenge", "INVALID_CHALLENGE", http.StatusUnauthorized)
		return
	}

	if time.Since(createdAt) > ChallengeExpiry {
		writeJSONError(w, "Invalid or expired challenge", "INVALID_CHALLENGE", http.StatusUnauthorized)
		return
	}

	user, err := h.DB.GetUserByUsername(req.Username)
	if err != nil {
		writeJSONError(w, "Invalid credentials", "INVALID_CREDENTIALS", http.StatusUnauthorized)
		return
	}

	if userID != user.ID {
		writeJSONError(w, "Invalid credentials", "INVALID_CREDENTIALS", http.StatusUnauthorized)
		return
	}

	expectedMessage := req.Nonce + ":" + user.ID
	if !verifySignature(user.SigningKey, []byte(expectedMessage), []byte(req.Signature)) {
		writeJSONError(w, "Invalid signature", "INVALID_SIGNATURE", http.StatusUnauthorized)
		return
	}

	if err := setSessionCookie(w, r, h.DB, user.ID, user.Username); err != nil {
		writeJSONError(w, "Failed to create session", "INTERNAL_ERROR", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"id":       user.ID,
		"username": user.Username,
	})
}

func (h *AuthHandler) GetMe(w http.ResponseWriter, r *http.Request) {
	sessionID, userID, username := getSessionFromCookie(r)
	if sessionID == "" || userID == "" {
		writeJSONError(w, "Not authenticated", "UNAUTHORIZED", http.StatusUnauthorized)
		return
	}

	valid, err := h.DB.ValidateSession(sessionID, userID)
	if err != nil || !valid {
		clearSessionCookie(w, r)
		writeJSONError(w, "Not authenticated", "UNAUTHORIZED", http.StatusUnauthorized)
		return
	}

	validUsername, err := h.DB.GetUserSessionValidation(userID)
	if err != nil || validUsername != username {
		clearSessionCookie(w, r)
		writeJSONError(w, "Not authenticated", "UNAUTHORIZED", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"id":       userID,
		"username": username,
	})
}

func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	sessionID, _, _ := getSessionFromCookie(r)
	if sessionID != "" {
		h.DB.DeleteSession(sessionID)
		h.DB.DeleteSessionCSRFTokens(sessionID)
		if h.WS != nil {
			h.WS.DisconnectSession(sessionID)
		}
	}
	clearSessionCookie(w, r)
	w.WriteHeader(http.StatusOK)
}

func (h *AuthHandler) GetUserKey(w http.ResponseWriter, r *http.Request) {
	_, sessionUserID, _ := getSessionFromCookie(r)
	if sessionUserID == "" {
		writeJSONError(w, "Not authenticated", "UNAUTHORIZED", http.StatusUnauthorized)
		return
	}

	userID := r.PathValue("id")
	if userID == "" {
		writeJSONError(w, "User ID required", "INVALID_REQUEST", http.StatusBadRequest)
		return
	}

	if userID != sessionUserID {
		roomID := r.URL.Query().Get("room_id")
		if roomID == "" {
			writeJSONError(w, "room_id required when requesting another user's key", "INVALID_REQUEST", http.StatusBadRequest)
			return
		}

		isMember, err := h.DB.IsRoomMember(roomID, sessionUserID)
		if err != nil {
			writeJSONError(w, "Failed to verify room membership", "INTERNAL_ERROR", http.StatusInternalServerError)
			return
		}
		if !isMember {
			writeJSONError(w, "Not authorized to access this room", "FORBIDDEN", http.StatusForbidden)
			return
		}

		isTargetMember, err := h.DB.IsRoomMember(roomID, userID)
		if err != nil {
			writeJSONError(w, "Failed to verify target user membership", "INTERNAL_ERROR", http.StatusInternalServerError)
			return
		}
		if !isTargetMember {
			writeJSONError(w, "Target user is not in the requested room", "FORBIDDEN", http.StatusForbidden)
			return
		}
	}

	user, err := h.DB.GetUserByID(userID)
	if err != nil {
		writeJSONError(w, "User not found", "USER_NOT_FOUND", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"id":          user.ID,
		"username":    user.Username,
		"public_key":  user.PublicKey,
		"signing_key": user.SigningKey,
	})
}

func setSessionCookie(w http.ResponseWriter, r *http.Request, database *db.Database, userID, username string) error {
	sessionID := uuid.New().String()
	timestamp := time.Now().Unix()
	expiresAt := time.Now().Add(24 * time.Hour)

	if err := database.CreateSession(sessionID, userID, expiresAt); err != nil {
		return err
	}

	// Colon-delimited format is safe because usernameRegex (^[a-zA-Z0-9_]+$) excludes colons,
	// and sessionID/userID are hex/UUID strings that also cannot contain colons.
	data := sessionID + ":" + userID + ":" + username + ":" + strconv.FormatInt(timestamp, 10)
	signature := hmacSHA256(data)
	token := data + ":" + signature

	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    base64.URLEncoding.EncodeToString([]byte(token)),
		Path:     "/",
		HttpOnly: true,
		Secure:   session.IsSecureRequest(r),
		SameSite: http.SameSiteStrictMode,
		MaxAge:   86400,
	})
	return nil
}

func getSessionFromCookie(r *http.Request) (sessionID, userID, username string) {
	return session.GetFromCookie(r)
}

func clearSessionCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   session.IsSecureRequest(r),
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})
}

func (h *AuthHandler) DeleteAccount(w http.ResponseWriter, r *http.Request) {
	_, userID, _ := getSessionFromCookie(r)
	if userID == "" {
		writeJSONError(w, "Not authenticated", "UNAUTHORIZED", http.StatusUnauthorized)
		return
	}

	var req DeleteAccountRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, "Invalid request body", "INVALID_REQUEST", http.StatusBadRequest)
		return
	}

	if req.Confirmation != "DELETE" {
		writeJSONError(w, "Confirmation must be 'DELETE'", "INVALID_CONFIRMATION", http.StatusBadRequest)
		return
	}

	if req.Password == "" {
		writeJSONError(w, "Password is required", "INVALID_REQUEST", http.StatusBadRequest)
		return
	}

	user, err := h.DB.GetUserByID(userID)
	if err != nil {
		writeJSONError(w, "User not found", "USER_NOT_FOUND", http.StatusNotFound)
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), hashPasswordForBcrypt(req.Password)); err != nil {
		time.Sleep(100 * time.Millisecond)
		writeJSONError(w, "Invalid password", "INVALID_CREDENTIALS", http.StatusUnauthorized)
		return
	}

	count, err := h.DB.CountUserChallenges(userID)
	if err != nil {
		writeJSONError(w, "Failed to check challenge count", "INTERNAL_ERROR", http.StatusInternalServerError)
		return
	}
	if count >= MaxChallengePerIP {
		writeJSONError(w, "Too many pending challenges", "RATE_LIMITED", http.StatusTooManyRequests)
		return
	}

	nonce, err := generateNonce()
	if err != nil {
		writeJSONError(w, "Failed to create challenge", "INTERNAL_ERROR", http.StatusInternalServerError)
		return
	}

	if err := h.DB.CreateChallenge(nonce, userID); err != nil {
		writeJSONError(w, "Failed to create challenge", "INTERNAL_ERROR", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(ChallengeResponse{
		Nonce:     nonce,
		ExpiresAt: time.Now().Add(ChallengeExpiry).Unix(),
		UserID:    userID,
	})
}

func (h *AuthHandler) ConfirmDeleteAccount(w http.ResponseWriter, r *http.Request) {
	_, userID, _ := getSessionFromCookie(r)
	if userID == "" {
		writeJSONError(w, "Not authenticated", "UNAUTHORIZED", http.StatusUnauthorized)
		return
	}

	var req ConfirmDeleteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, "Invalid request body", "INVALID_REQUEST", http.StatusBadRequest)
		return
	}

	if req.Nonce == "" || len(req.Signature) == 0 {
		writeJSONError(w, "Missing required fields", "INVALID_REQUEST", http.StatusBadRequest)
		return
	}

	challengeUserID, createdAt, err := h.DB.GetAndDeleteChallenge(req.Nonce)
	if err != nil {
		writeJSONError(w, "Invalid or expired challenge", "INVALID_CHALLENGE", http.StatusUnauthorized)
		return
	}

	if time.Since(createdAt) > ChallengeExpiry {
		writeJSONError(w, "Challenge expired", "INVALID_CHALLENGE", http.StatusUnauthorized)
		return
	}

	if challengeUserID != userID {
		writeJSONError(w, "Invalid challenge", "INVALID_CHALLENGE", http.StatusUnauthorized)
		return
	}

	user, err := h.DB.GetUserByID(userID)
	if err != nil {
		writeJSONError(w, "User not found", "USER_NOT_FOUND", http.StatusNotFound)
		return
	}

	expectedMessage := req.Nonce + ":" + userID
	if !verifySignature(user.SigningKey, []byte(expectedMessage), []byte(req.Signature)) {
		writeJSONError(w, "Invalid signature", "INVALID_SIGNATURE", http.StatusUnauthorized)
		return
	}

	// Collect broadcast data BEFORE deletion
	memberRoomIDs, _ := h.DB.GetUserRoomIDs(userID)
	createdRoomIDs, _ := h.DB.GetRoomsCreatedByUser(userID)

	if h.WS != nil {
		for _, roomID := range createdRoomIDs {
			h.WS.BroadcastToUserRooms([]string{roomID}, models.Message{
				Type:     "room_deleted",
				RoomID:   roomID,
				SenderID: userID,
				Sender:   user.Username,
			})
		}
	}

	if err := h.DB.DeleteUser(userID); err != nil {
		writeJSONError(w, "Failed to delete account", "INTERNAL_ERROR", http.StatusInternalServerError)
		return
	}

	if h.WS != nil {
		h.WS.InvalidateSigningKeyCache(userID)

		// Broadcast user_deleted to rooms where user was a member
		h.WS.BroadcastToUserRooms(memberRoomIDs, models.Message{
			Type:     "user_deleted",
			SenderID: userID,
			Sender:   user.Username,
		})

		h.WS.DisconnectUser(userID)
		h.WS.CleanupUserReplayState(userID)
	}

	clearSessionCookie(w, r)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "deleted"})
}

func (h *AuthHandler) RotateKeys(w http.ResponseWriter, r *http.Request) {
	_, userID, _ := getSessionFromCookie(r)
	if userID == "" {
		writeJSONError(w, "Not authenticated", "UNAUTHORIZED", http.StatusUnauthorized)
		return
	}

	var req RotateKeysRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, "Invalid request body", "INVALID_REQUEST", http.StatusBadRequest)
		return
	}

	if req.Password == "" {
		writeJSONError(w, "Password is required", "INVALID_REQUEST", http.StatusBadRequest)
		return
	}

	user, err := h.DB.GetUserByID(userID)
	if err != nil {
		writeJSONError(w, "User not found", "USER_NOT_FOUND", http.StatusNotFound)
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), hashPasswordForBcrypt(req.Password)); err != nil {
		time.Sleep(100 * time.Millisecond)
		writeJSONError(w, "Invalid password", "INVALID_CREDENTIALS", http.StatusUnauthorized)
		return
	}

	count, err := h.DB.CountUserChallenges(userID)
	if err != nil {
		writeJSONError(w, "Failed to check challenge count", "INTERNAL_ERROR", http.StatusInternalServerError)
		return
	}
	if count >= MaxChallengePerIP {
		writeJSONError(w, "Too many pending challenges", "RATE_LIMITED", http.StatusTooManyRequests)
		return
	}

	nonce, err := generateNonce()
	if err != nil {
		writeJSONError(w, "Failed to create challenge", "INTERNAL_ERROR", http.StatusInternalServerError)
		return
	}

	if err := h.DB.CreateChallenge(nonce, userID); err != nil {
		writeJSONError(w, "Failed to create challenge", "INTERNAL_ERROR", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(ChallengeResponse{
		Nonce:     nonce,
		ExpiresAt: time.Now().Add(ChallengeExpiry).Unix(),
		UserID:    userID,
	})
}

func (h *AuthHandler) ConfirmRotateKeys(w http.ResponseWriter, r *http.Request) {
	_, userID, _ := getSessionFromCookie(r)
	if userID == "" {
		writeJSONError(w, "Not authenticated", "UNAUTHORIZED", http.StatusUnauthorized)
		return
	}

	var req ConfirmRotateKeysRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, "Invalid request body", "INVALID_REQUEST", http.StatusBadRequest)
		return
	}

	if req.Nonce == "" || len(req.Signature) == 0 {
		writeJSONError(w, "Missing required fields", "INVALID_REQUEST", http.StatusBadRequest)
		return
	}

	if len(req.NewPublicKey) == 0 || len(req.NewSigningKey) == 0 {
		writeJSONError(w, "New keys are required", "INVALID_REQUEST", http.StatusBadRequest)
		return
	}

	challengeUserID, createdAt, err := h.DB.GetAndDeleteChallenge(req.Nonce)
	if err != nil {
		writeJSONError(w, "Invalid or expired challenge", "INVALID_CHALLENGE", http.StatusUnauthorized)
		return
	}

	if time.Since(createdAt) > ChallengeExpiry {
		writeJSONError(w, "Challenge expired", "INVALID_CHALLENGE", http.StatusUnauthorized)
		return
	}

	if challengeUserID != userID {
		writeJSONError(w, "Invalid challenge", "INVALID_CHALLENGE", http.StatusUnauthorized)
		return
	}

	user, err := h.DB.GetUserByID(userID)
	if err != nil {
		writeJSONError(w, "User not found", "USER_NOT_FOUND", http.StatusNotFound)
		return
	}

	// Verify with CURRENT signing key
	expectedMessage := req.Nonce + ":" + userID
	if !verifySignature(user.SigningKey, []byte(expectedMessage), []byte(req.Signature)) {
		writeJSONError(w, "Invalid signature", "INVALID_SIGNATURE", http.StatusUnauthorized)
		return
	}

	if err := h.DB.UpdateUserKeys(userID, []byte(req.NewPublicKey), []byte(req.NewSigningKey)); err != nil {
		writeJSONError(w, "Failed to update keys", "INTERNAL_ERROR", http.StatusInternalServerError)
		return
	}

	if h.WS != nil {
		h.WS.InvalidateSigningKeyCache(userID)

		roomIDs, _ := h.DB.GetUserRoomIDs(userID)
		keyData := map[string]interface{}{
			"user_id":     userID,
			"username":    user.Username,
			"public_key":  req.NewPublicKey,
			"signing_key": req.NewSigningKey,
		}
		keyContent, _ := json.Marshal(keyData)
		h.WS.BroadcastToUserRooms(roomIDs, models.Message{
			Type:     "key_rotated",
			SenderID: userID,
			Sender:   user.Username,
			Content:  keyContent,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "keys_rotated"})
}

func verifySignature(publicKeySPKI, message, signature []byte) bool {
	// Accept only P1363 (IEEE P1363) format: raw r||s, 64 bytes for P-256.
	// This matches Web Crypto API's ECDSA sign output format.
	if len(publicKeySPKI) == 0 || len(signature) != 64 {
		return false
	}

	pubKey, err := x509.ParsePKIXPublicKey(publicKeySPKI)
	if err != nil {
		return false
	}

	ecdsaPubKey, ok := pubKey.(*ecdsa.PublicKey)
	if !ok {
		return false
	}

	hashed := sha256.Sum256(message)
	r := new(big.Int).SetBytes(signature[:32])
	s := new(big.Int).SetBytes(signature[32:])
	return ecdsa.Verify(ecdsaPubKey, hashed[:], r, s)
}
