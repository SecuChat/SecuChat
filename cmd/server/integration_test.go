package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"secuchat/internal/db"
	"secuchat/internal/handler"
	"secuchat/internal/middleware"
	"secuchat/internal/session"
)

// signP1363 signs the hash and returns a 64-byte P1363 (r||s) signature for P-256,
// matching the format produced by Web Crypto API's ECDSA.
func signP1363(t *testing.T, privateKey *ecdsa.PrivateKey, hash []byte) []byte {
	t.Helper()
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash)
	if err != nil {
		t.Fatalf("failed to sign: %v", err)
	}
	byteLen := (privateKey.Curve.Params().BitSize + 7) / 8
	sig := make([]byte, 2*byteLen)
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	copy(sig[byteLen-len(rBytes):byteLen], rBytes)
	copy(sig[2*byteLen-len(sBytes):], sBytes)
	return sig
}

const testOrigin = "https://example.com"

type testUser struct {
	ID             string
	Username       string
	Password       string
	PublicKey      []byte
	SigningKey     []byte
	SigningPrivate *ecdsa.PrivateKey
}

type challengeResponse struct {
	Nonce     string `json:"nonce"`
	ExpiresAt int64  `json:"expires_at"`
	UserID    string `json:"user_id"`
}

type roomResponse struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	IsPrivate    bool   `json:"is_private"`
	InviteCode   string `json:"invite_code"`
	CurrentEpoch int    `json:"current_epoch"`
}

type roomMember struct {
	ID       string `json:"id"`
	Username string `json:"username"`
}

type wsMessageEnvelope struct {
	Type       string         `json:"type"`
	RoomID     string         `json:"room_id"`
	Content    map[string]any `json:"content"`
	Signature  []byte         `json:"signature"`
	Timestamp  int64          `json:"timestamp"`
	Generation int            `json:"generation"`
	MessageNum int            `json:"message_num"`
}

func TestOriginValidationHelpers(t *testing.T) {
	allowed, err := parseAllowedOrigins("https://chat.example.com, https://app.example.com/")
	if err != nil {
		t.Fatalf("expected valid ALLOWED_ORIGINS: %v", err)
	}
	if len(allowed) != 2 {
		t.Fatalf("expected two allowed origins, got %d", len(allowed))
	}

	if !isOriginAllowed("https://chat.example.com", allowed) {
		t.Fatalf("expected exact origin match to be allowed")
	}
	if !isOriginAllowed("https://app.example.com", allowed) {
		t.Fatalf("expected trailing-slash origin normalization to be allowed")
	}
	if isOriginAllowed("http://chat.example.com", allowed) {
		t.Fatalf("did not expect non-https origin to be allowed")
	}
	if isOriginAllowed("https://evil.example.com", allowed) {
		t.Fatalf("did not expect unrelated origin to be allowed")
	}

	invalid := []string{
		"*",
		"*.example.com",
		"chat.local",
		"http://chat.example.com",
		"https://chat.example.com/path",
	}
	for _, raw := range invalid {
		if _, err := parseAllowedOrigins(raw); err == nil {
			t.Fatalf("expected invalid ALLOWED_ORIGINS entry %q to be rejected", raw)
		}
	}
}

func TestAuthLoginVerifyAndCSRFRotation(t *testing.T) {
	server := newTestHTTPServer(t)
	client := newTestClient(t)
	user := newTestUser(t, "alice", "Password123!")

	csrf1 := fetchCSRFToken(t, client, server.URL)
	user.ID = createAccount(t, client, server.URL, user, csrf1)

	csrf2 := getCookieValue(t, client, server.URL, "csrf_token")
	if csrf2 == "" {
		t.Fatalf("expected csrf token after account creation")
	}
	if csrf2 == csrf1 {
		t.Fatalf("expected csrf token rotation after successful POST")
	}

	status, _, body := doJSONRequest(
		t,
		client,
		http.MethodPost,
		server.URL+"/api/rooms",
		map[string]any{"name": "stale-token-room", "is_private": false},
		map[string]string{"X-CSRF-Token": csrf1},
	)
	if status != http.StatusForbidden {
		t.Fatalf("expected stale csrf token to be rejected, got %d body=%s", status, string(body))
	}

	status, _, body = doJSONRequest(
		t,
		client,
		http.MethodPost,
		server.URL+"/api/rooms",
		map[string]any{"name": "fresh-token-room", "is_private": false},
		map[string]string{"X-CSRF-Token": csrf2},
	)
	if status != http.StatusOK {
		t.Fatalf("expected room creation to succeed with rotated csrf token, got %d body=%s", status, string(body))
	}

	csrf3 := getCookieValue(t, client, server.URL, "csrf_token")
	if csrf3 == "" || csrf3 == csrf2 {
		t.Fatalf("expected csrf token to rotate after room creation")
	}

	status, _, body = doJSONRequest(
		t,
		client,
		http.MethodPost,
		server.URL+"/api/auth/logout",
		nil,
		map[string]string{"X-CSRF-Token": csrf3},
	)
	if status != http.StatusOK {
		t.Fatalf("expected logout success, got %d body=%s", status, string(body))
	}

	csrfLogin := fetchCSRFToken(t, client, server.URL)
	challenge := login(t, client, server.URL, csrfLogin, user.Username, user.Password)
	if challenge.UserID != user.ID {
		t.Fatalf("expected challenge user_id %s, got %s", user.ID, challenge.UserID)
	}

	signature := signChallenge(t, user.SigningPrivate, challenge.Nonce, challenge.UserID)
	csrfVerify := getCookieValue(t, client, server.URL, "csrf_token")
	status, _, body = doJSONRequest(
		t,
		client,
		http.MethodPost,
		server.URL+"/api/auth/verify",
		map[string]any{
			"username":  user.Username,
			"nonce":     challenge.Nonce,
			"signature": signature,
		},
		map[string]string{"X-CSRF-Token": csrfVerify},
	)
	if status != http.StatusOK {
		t.Fatalf("expected verify success, got %d body=%s", status, string(body))
	}

	var verifyResp struct {
		ID       string `json:"id"`
		Username string `json:"username"`
	}
	unmarshalJSON(t, body, &verifyResp)
	if verifyResp.ID != user.ID {
		t.Fatalf("expected verify response id %s, got %s", user.ID, verifyResp.ID)
	}
}

func TestAPIBinaryFieldsRequireBase64Strings(t *testing.T) {
	server := newTestHTTPServer(t)
	client := newTestClient(t)

	csrf := fetchCSRFToken(t, client, server.URL)
	status, _, body := doJSONRequest(
		t,
		client,
		http.MethodPost,
		server.URL+"/api/auth/create",
		map[string]any{
			"username":    "badkeys",
			"password":    "Password123!",
			"public_key":  []int{1, 2, 3},
			"signing_key": []int{4, 5, 6},
		},
		map[string]string{"X-CSRF-Token": csrf},
	)
	if status != http.StatusBadRequest {
		t.Fatalf("expected create to reject array-encoded keys, got %d body=%s", status, string(body))
	}

	csrf = fetchCSRFToken(t, client, server.URL)
	status, _, body = doJSONRequest(
		t,
		client,
		http.MethodPost,
		server.URL+"/api/auth/verify",
		map[string]any{
			"username":  "alice",
			"nonce":     "nonce",
			"signature": []int{1, 2, 3},
		},
		map[string]string{"X-CSRF-Token": csrf},
	)
	if status != http.StatusBadRequest {
		t.Fatalf("expected verify to reject array-encoded signature, got %d body=%s", status, string(body))
	}
}

func TestCSRFTokenReusedAcrossUnauthenticatedReads(t *testing.T) {
	server := newTestHTTPServer(t)
	client := newTestClient(t)

	status, headers, body := doJSONRequest(
		t,
		client,
		http.MethodGet,
		server.URL+"/api/auth/me",
		nil,
		nil,
	)
	if status != http.StatusUnauthorized {
		t.Fatalf("expected unauthorized status, got %d body=%s", status, string(body))
	}
	token1 := headers.Get("X-CSRF-Token")
	if token1 == "" {
		t.Fatalf("expected csrf token header on initial read request")
	}

	status, headers, body = doJSONRequest(
		t,
		client,
		http.MethodGet,
		server.URL+"/api/auth/me",
		nil,
		nil,
	)
	if status != http.StatusUnauthorized {
		t.Fatalf("expected unauthorized status on second read, got %d body=%s", status, string(body))
	}
	token2 := headers.Get("X-CSRF-Token")
	if token2 == "" {
		t.Fatalf("expected csrf token header on second read request")
	}
	if token1 != token2 {
		t.Fatalf("expected csrf token to be reused across unauthenticated read requests")
	}
}

func TestPrivateRoomInviteFlow(t *testing.T) {
	server := newTestHTTPServer(t)

	ownerClient := newTestClient(t)
	owner := newTestUser(t, "owner", "Password123!")
	ownerCSRF := fetchCSRFToken(t, ownerClient, server.URL)
	owner.ID = createAccount(t, ownerClient, server.URL, owner, ownerCSRF)

	room := createRoom(t, ownerClient, server.URL, "private-room", true)
	if room.InviteCode == "" {
		t.Fatalf("expected invite code for private room")
	}

	ownerCSRF = fetchCSRFToken(t, ownerClient, server.URL)
	status, _, body := doJSONRequest(
		t,
		ownerClient,
		http.MethodPost,
		fmt.Sprintf("%s/api/rooms/%s/regenerate-code", server.URL, room.ID),
		nil,
		map[string]string{"X-CSRF-Token": ownerCSRF},
	)
	if status != http.StatusOK {
		t.Fatalf("expected invite code regeneration success, got %d body=%s", status, string(body))
	}
	var regenResp struct {
		InviteCode string `json:"invite_code"`
	}
	unmarshalJSON(t, body, &regenResp)
	if regenResp.InviteCode == "" || regenResp.InviteCode == room.InviteCode {
		t.Fatalf("expected regenerated invite code to differ from original")
	}

	guestClient := newTestClient(t)
	guest := newTestUser(t, "guest", "Password123!")
	guestCSRF := fetchCSRFToken(t, guestClient, server.URL)
	guest.ID = createAccount(t, guestClient, server.URL, guest, guestCSRF)

	guestCSRF = fetchCSRFToken(t, guestClient, server.URL)
	status, _, body = doJSONRequest(
		t,
		guestClient,
		http.MethodPost,
		server.URL+"/api/rooms/join-by-code",
		map[string]any{"invite_code": room.InviteCode},
		map[string]string{"X-CSRF-Token": guestCSRF},
	)
	if status != http.StatusNotFound {
		t.Fatalf("expected old invite code to fail after regeneration, got %d body=%s", status, string(body))
	}

	guestCSRF = fetchCSRFToken(t, guestClient, server.URL)
	status, _, body = doJSONRequest(
		t,
		guestClient,
		http.MethodPost,
		server.URL+"/api/rooms/join-by-code",
		map[string]any{"invite_code": regenResp.InviteCode},
		map[string]string{"X-CSRF-Token": guestCSRF},
	)
	if status != http.StatusOK {
		t.Fatalf("expected join-by-code success, got %d body=%s", status, string(body))
	}

	status, _, body = doJSONRequest(
		t,
		guestClient,
		http.MethodGet,
		fmt.Sprintf("%s/api/rooms/%s/members", server.URL, room.ID),
		nil,
		nil,
	)
	if status != http.StatusOK {
		t.Fatalf("expected members query success, got %d body=%s", status, string(body))
	}

	var members []roomMember
	unmarshalJSON(t, body, &members)
	if !hasMember(members, owner.ID) || !hasMember(members, guest.ID) {
		t.Fatalf("expected owner and guest in room members list")
	}
}

func TestGetUserKeyAuthorization(t *testing.T) {
	server := newTestHTTPServer(t)

	ownerClient := newTestClient(t)
	owner := newTestUser(t, "key_owner", "Password123!")
	ownerCSRF := fetchCSRFToken(t, ownerClient, server.URL)
	owner.ID = createAccount(t, ownerClient, server.URL, owner, ownerCSRF)
	room := createRoom(t, ownerClient, server.URL, "key-room", false)

	memberClient := newTestClient(t)
	member := newTestUser(t, "key_member", "Password123!")
	memberCSRF := fetchCSRFToken(t, memberClient, server.URL)
	member.ID = createAccount(t, memberClient, server.URL, member, memberCSRF)
	memberCSRF = fetchCSRFToken(t, memberClient, server.URL)
	status, _, body := doJSONRequest(
		t,
		memberClient,
		http.MethodPost,
		fmt.Sprintf("%s/api/rooms/%s/join", server.URL, room.ID),
		map[string]any{},
		map[string]string{"X-CSRF-Token": memberCSRF},
	)
	if status != http.StatusOK {
		t.Fatalf("expected member join success, got %d body=%s", status, string(body))
	}

	outsiderClient := newTestClient(t)
	outsider := newTestUser(t, "key_outsider", "Password123!")
	outsiderCSRF := fetchCSRFToken(t, outsiderClient, server.URL)
	outsider.ID = createAccount(t, outsiderClient, server.URL, outsider, outsiderCSRF)

	status, _, body = doJSONRequest(
		t,
		ownerClient,
		http.MethodGet,
		fmt.Sprintf("%s/api/users/%s/key", server.URL, owner.ID),
		nil,
		nil,
	)
	if status != http.StatusOK {
		t.Fatalf("expected self key fetch success, got %d body=%s", status, string(body))
	}
	var selfResp struct {
		ID         string `json:"id"`
		PublicKey  []byte `json:"public_key"`
		SigningKey []byte `json:"signing_key"`
	}
	unmarshalJSON(t, body, &selfResp)
	if selfResp.ID != owner.ID {
		t.Fatalf("expected self key id %s, got %s", owner.ID, selfResp.ID)
	}
	if len(selfResp.PublicKey) == 0 || len(selfResp.SigningKey) == 0 {
		t.Fatalf("expected non-empty self key material")
	}
	var selfRaw map[string]any
	unmarshalJSON(t, body, &selfRaw)
	pubKeyB64, ok := selfRaw["public_key"].(string)
	if !ok || pubKeyB64 == "" {
		t.Fatalf("expected public_key to be base64 string, got %T", selfRaw["public_key"])
	}
	if _, err := base64.StdEncoding.DecodeString(pubKeyB64); err != nil {
		t.Fatalf("expected public_key to be valid base64: %v", err)
	}
	signingKeyB64, ok := selfRaw["signing_key"].(string)
	if !ok || signingKeyB64 == "" {
		t.Fatalf("expected signing_key to be base64 string, got %T", selfRaw["signing_key"])
	}
	if _, err := base64.StdEncoding.DecodeString(signingKeyB64); err != nil {
		t.Fatalf("expected signing_key to be valid base64: %v", err)
	}

	status, _, body = doJSONRequest(
		t,
		ownerClient,
		http.MethodGet,
		fmt.Sprintf("%s/api/users/%s/key?room_id=%s", server.URL, member.ID, room.ID),
		nil,
		nil,
	)
	if status != http.StatusOK {
		t.Fatalf("expected room-scoped key fetch success, got %d body=%s", status, string(body))
	}
	var memberResp struct {
		ID string `json:"id"`
	}
	unmarshalJSON(t, body, &memberResp)
	if memberResp.ID != member.ID {
		t.Fatalf("expected fetched member id %s, got %s", member.ID, memberResp.ID)
	}

	status, _, body = doJSONRequest(
		t,
		ownerClient,
		http.MethodGet,
		fmt.Sprintf("%s/api/users/%s/key", server.URL, member.ID),
		nil,
		nil,
	)
	if status != http.StatusBadRequest {
		t.Fatalf("expected missing room_id rejection, got %d body=%s", status, string(body))
	}

	status, _, body = doJSONRequest(
		t,
		ownerClient,
		http.MethodGet,
		fmt.Sprintf("%s/api/users/%s/key?room_id=%s", server.URL, outsider.ID, room.ID),
		nil,
		nil,
	)
	if status != http.StatusForbidden {
		t.Fatalf("expected non-member target rejection, got %d body=%s", status, string(body))
	}

	status, _, body = doJSONRequest(
		t,
		outsiderClient,
		http.MethodGet,
		fmt.Sprintf("%s/api/users/%s/key?room_id=%s", server.URL, member.ID, room.ID),
		nil,
		nil,
	)
	if status != http.StatusForbidden {
		t.Fatalf("expected outsider key fetch rejection, got %d body=%s", status, string(body))
	}
}

func TestWebSocketSignedMessageAndReplayProtection(t *testing.T) {
	server := newTestHTTPServer(t)

	user1Client := newTestClient(t)
	user1 := newTestUser(t, "ws_sender", "Password123!")
	user1CSRF := fetchCSRFToken(t, user1Client, server.URL)
	user1.ID = createAccount(t, user1Client, server.URL, user1, user1CSRF)
	room := createRoom(t, user1Client, server.URL, "ws-room", false)

	user2Client := newTestClient(t)
	user2 := newTestUser(t, "ws_receiver", "Password123!")
	user2CSRF := fetchCSRFToken(t, user2Client, server.URL)
	user2.ID = createAccount(t, user2Client, server.URL, user2, user2CSRF)

	user2CSRF = fetchCSRFToken(t, user2Client, server.URL)
	status, _, body := doJSONRequest(
		t,
		user2Client,
		http.MethodPost,
		fmt.Sprintf("%s/api/rooms/%s/join", server.URL, room.ID),
		map[string]any{},
		map[string]string{"X-CSRF-Token": user2CSRF},
	)
	if status != http.StatusOK {
		t.Fatalf("expected second user room join success, got %d body=%s", status, string(body))
	}
	var joinResp struct {
		CurrentEpoch int `json:"current_epoch"`
	}
	unmarshalJSON(t, body, &joinResp)
	if joinResp.CurrentEpoch < 1 {
		t.Fatalf("expected join response to include current_epoch >= 1, got %d", joinResp.CurrentEpoch)
	}
	currentEpoch := joinResp.CurrentEpoch

	ws1 := dialWebSocket(t, server.URL, user1Client)
	defer ws1.Close()
	ws2 := dialWebSocket(t, server.URL, user2Client)
	defer ws2.Close()

	writeWSJSON(t, ws1, map[string]any{"type": "join", "room_id": room.ID})
	writeWSJSON(t, ws2, map[string]any{"type": "join", "room_id": room.ID})

	if _, err := waitForWSMessageType(ws1, "members", 2*time.Second); err != nil {
		t.Fatalf("expected sender to receive members update after join: %v", err)
	}
	if _, err := waitForWSMessageType(ws2, "members", 2*time.Second); err != nil {
		t.Fatalf("expected receiver to receive members update after join: %v", err)
	}

	ivB64 := base64.StdEncoding.EncodeToString([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12})
	ciphertextB64 := base64.StdEncoding.EncodeToString([]byte{99, 100, 101})

	firstTimestamp := time.Now().UnixMilli()
	firstSignature := signChatPayload(t, user1.SigningPrivate, room.ID, ivB64, ciphertextB64, firstTimestamp, currentEpoch, 0)
	writeWSJSON(t, ws1, wsMessageEnvelope{
		Type:       "message",
		RoomID:     room.ID,
		Content:    map[string]any{"iv": ivB64, "ciphertext": ciphertextB64},
		Signature:  firstSignature,
		Timestamp:  firstTimestamp,
		Generation: currentEpoch,
		MessageNum: 0,
	})

	msg, err := waitForWSMessageType(ws2, "message", 2*time.Second)
	if err != nil {
		t.Fatalf("expected receiver to get signed message: %v", err)
	}
	if msg["room_id"] != room.ID {
		t.Fatalf("expected room_id %s, got %v", room.ID, msg["room_id"])
	}
	requireWSStringField(t, msg, "sender_id", user1.ID)
	requireWSStringField(t, msg, "sender", user1.Username)
	signatureB64, ok := msg["signature"].(string)
	if !ok || signatureB64 == "" {
		t.Fatalf("expected signature to be base64 string, got %T", msg["signature"])
	}
	if _, err := base64.StdEncoding.DecodeString(signatureB64); err != nil {
		t.Fatalf("expected signature to be valid base64: %v", err)
	}
	content, ok := msg["content"].(map[string]any)
	if !ok {
		t.Fatalf("expected content to be object, got %T", msg["content"])
	}
	ivGot, ok := content["iv"].(string)
	if !ok || ivGot != ivB64 {
		t.Fatalf("expected content.iv to be %q, got %v (%T)", ivB64, content["iv"], content["iv"])
	}
	ciphertextGot, ok := content["ciphertext"].(string)
	if !ok || ciphertextGot != ciphertextB64 {
		t.Fatalf("expected content.ciphertext to be %q, got %v (%T)", ciphertextB64, content["ciphertext"], content["ciphertext"])
	}

	replayTimestamp := time.Now().UnixMilli() + 5
	replaySignature := signChatPayload(t, user1.SigningPrivate, room.ID, ivB64, ciphertextB64, replayTimestamp, currentEpoch, 0)
	writeWSJSON(t, ws1, wsMessageEnvelope{
		Type:       "message",
		RoomID:     room.ID,
		Content:    map[string]any{"iv": ivB64, "ciphertext": ciphertextB64},
		Signature:  replaySignature,
		Timestamp:  replayTimestamp,
		Generation: currentEpoch,
		MessageNum: 0,
	})

	if _, err := waitForWSMessageType(ws2, "message", 700*time.Millisecond); err == nil {
		t.Fatalf("expected replayed message_num to be rejected by server")
	}
}

func TestWebSocketRejectsArrayEncodedCiphertext(t *testing.T) {
	server := newTestHTTPServer(t)

	user1Client := newTestClient(t)
	user1 := newTestUser(t, "ws_array_sender", "Password123!")
	user1CSRF := fetchCSRFToken(t, user1Client, server.URL)
	user1.ID = createAccount(t, user1Client, server.URL, user1, user1CSRF)
	room := createRoom(t, user1Client, server.URL, "ws-array-room", false)

	user2Client := newTestClient(t)
	user2 := newTestUser(t, "ws_array_receiver", "Password123!")
	user2CSRF := fetchCSRFToken(t, user2Client, server.URL)
	user2.ID = createAccount(t, user2Client, server.URL, user2, user2CSRF)

	user2CSRF = fetchCSRFToken(t, user2Client, server.URL)
	status, _, body := doJSONRequest(
		t,
		user2Client,
		http.MethodPost,
		fmt.Sprintf("%s/api/rooms/%s/join", server.URL, room.ID),
		map[string]any{},
		map[string]string{"X-CSRF-Token": user2CSRF},
	)
	if status != http.StatusOK {
		t.Fatalf("expected second user room join success, got %d body=%s", status, string(body))
	}
	var joinResp struct {
		CurrentEpoch int `json:"current_epoch"`
	}
	unmarshalJSON(t, body, &joinResp)
	currentEpoch := joinResp.CurrentEpoch
	if currentEpoch < 1 {
		t.Fatalf("expected join response to include current_epoch >= 1, got %d", currentEpoch)
	}

	ws1 := dialWebSocket(t, server.URL, user1Client)
	defer ws1.Close()
	ws2 := dialWebSocket(t, server.URL, user2Client)
	defer ws2.Close()

	writeWSJSON(t, ws1, map[string]any{"type": "join", "room_id": room.ID})
	writeWSJSON(t, ws2, map[string]any{"type": "join", "room_id": room.ID})

	if _, err := waitForWSMessageType(ws1, "members", 2*time.Second); err != nil {
		t.Fatalf("expected sender to receive members update after join: %v", err)
	}
	if _, err := waitForWSMessageType(ws2, "members", 2*time.Second); err != nil {
		t.Fatalf("expected receiver to receive members update after join: %v", err)
	}

	ivArr := []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	ctArr := []int{99, 100, 101}

	timestamp := time.Now().UnixMilli()
	sig := signChatPayload(t, user1.SigningPrivate, room.ID, ivArr, ctArr, timestamp, currentEpoch, 0)
	writeWSJSON(t, ws1, wsMessageEnvelope{
		Type:       "message",
		RoomID:     room.ID,
		Content:    map[string]any{"iv": ivArr, "ciphertext": ctArr},
		Signature:  sig,
		Timestamp:  timestamp,
		Generation: currentEpoch,
		MessageNum: 0,
	})

	if _, err := waitForWSMessageType(ws2, "message", 700*time.Millisecond); err == nil {
		t.Fatalf("expected array-encoded iv/ciphertext to be rejected by server")
	}
}

func TestWebSocketControlMessagesUseServerIdentity(t *testing.T) {
	server := newTestHTTPServer(t)

	user1Client := newTestClient(t)
	user1 := newTestUser(t, "ctrl_sender", "Password123!")
	user1CSRF := fetchCSRFToken(t, user1Client, server.URL)
	user1.ID = createAccount(t, user1Client, server.URL, user1, user1CSRF)
	room := createRoom(t, user1Client, server.URL, "ctrl-room", false)

	user2Client := newTestClient(t)
	user2 := newTestUser(t, "ctrl_receiver", "Password123!")
	user2CSRF := fetchCSRFToken(t, user2Client, server.URL)
	user2.ID = createAccount(t, user2Client, server.URL, user2, user2CSRF)

	user2CSRF = fetchCSRFToken(t, user2Client, server.URL)
	status, _, body := doJSONRequest(
		t,
		user2Client,
		http.MethodPost,
		fmt.Sprintf("%s/api/rooms/%s/join", server.URL, room.ID),
		map[string]any{},
		map[string]string{"X-CSRF-Token": user2CSRF},
	)
	if status != http.StatusOK {
		t.Fatalf("expected second user room join success, got %d body=%s", status, string(body))
	}

	ws1 := dialWebSocket(t, server.URL, user1Client)
	defer ws1.Close()
	ws2 := dialWebSocket(t, server.URL, user2Client)
	defer ws2.Close()

	writeWSJSON(t, ws1, map[string]any{"type": "join", "room_id": room.ID})
	if _, err := waitForWSMessageType(ws1, "members", 2*time.Second); err != nil {
		t.Fatalf("expected user1 member update after join: %v", err)
	}

	writeWSJSON(t, ws2, map[string]any{
		"type":      "join",
		"room_id":   room.ID,
		"sender_id": user1.ID,
		"sender":    "spoofed-join",
	})
	joinMsg, err := waitForWSMessageType(ws1, "join", 2*time.Second)
	if err != nil {
		t.Fatalf("expected canonical join message on user1 socket: %v", err)
	}
	requireWSStringField(t, joinMsg, "sender_id", user2.ID)
	requireWSStringField(t, joinMsg, "sender", user2.Username)

	if _, err := waitForWSMessageType(ws2, "members", 2*time.Second); err != nil {
		t.Fatalf("expected user2 member update after join: %v", err)
	}

	writeWSJSON(t, ws2, map[string]any{
		"type":      "key_request",
		"room_id":   room.ID,
		"sender_id": user1.ID,
		"sender":    "spoofed-key-request",
		"content": map[string]any{
			"hint": "ignored",
		},
	})
	keyReqMsg, err := waitForWSMessageType(ws1, "key_request", 2*time.Second)
	if err != nil {
		t.Fatalf("expected canonical key_request on user1 socket: %v", err)
	}
	requireWSStringField(t, keyReqMsg, "sender_id", user2.ID)
	requireWSStringField(t, keyReqMsg, "sender", user2.Username)

	ratchetState := map[string]any{
		"iv":         base64.StdEncoding.EncodeToString([]byte{1, 2, 3}),
		"ciphertext": base64.StdEncoding.EncodeToString([]byte{4, 5, 6}),
	}
	ratchetEpoch := 2
	ratchetReason := "test_transfer"
	ratchetTimestamp := time.Now().UnixMilli()
	ratchetSignature := signRatchetStatePayload(t, user1.SigningPrivate, room.ID, user2.ID, ratchetState, ratchetEpoch, ratchetReason, ratchetTimestamp)
	writeWSJSON(t, ws1, map[string]any{
		"type":      "ratchet_state",
		"room_id":   room.ID,
		"sender_id": user2.ID,
		"sender":    "spoofed-ratchet",
		"content": map[string]any{
			"user_id":   user2.ID,
			"state":     ratchetState,
			"epoch":     ratchetEpoch,
			"reason":    ratchetReason,
			"timestamp": ratchetTimestamp,
			"signature": ratchetSignature,
		},
	})
	ratchetMsg, err := waitForWSMessageType(ws2, "ratchet_state", 2*time.Second)
	if err != nil {
		t.Fatalf("expected canonical ratchet_state on user2 socket: %v", err)
	}
	requireWSStringField(t, ratchetMsg, "sender_id", user1.ID)
	requireWSStringField(t, ratchetMsg, "sender", user1.Username)
}

func TestWebSocketRatchetStateRequiresValidSignature(t *testing.T) {
	server := newTestHTTPServer(t)

	senderClient := newTestClient(t)
	sender := newTestUser(t, "ratchet_sender", "Password123!")
	senderCSRF := fetchCSRFToken(t, senderClient, server.URL)
	sender.ID = createAccount(t, senderClient, server.URL, sender, senderCSRF)
	room := createRoom(t, senderClient, server.URL, "ratchet-signature-room", false)

	receiverClient := newTestClient(t)
	receiver := newTestUser(t, "ratchet_receiver", "Password123!")
	receiverCSRF := fetchCSRFToken(t, receiverClient, server.URL)
	receiver.ID = createAccount(t, receiverClient, server.URL, receiver, receiverCSRF)

	receiverCSRF = fetchCSRFToken(t, receiverClient, server.URL)
	status, _, body := doJSONRequest(
		t,
		receiverClient,
		http.MethodPost,
		fmt.Sprintf("%s/api/rooms/%s/join", server.URL, room.ID),
		map[string]any{},
		map[string]string{"X-CSRF-Token": receiverCSRF},
	)
	if status != http.StatusOK {
		t.Fatalf("expected receiver join success, got %d body=%s", status, string(body))
	}

	wsSender := dialWebSocket(t, server.URL, senderClient)
	defer wsSender.Close()
	wsReceiverInvalid := dialWebSocket(t, server.URL, receiverClient)

	writeWSJSON(t, wsSender, map[string]any{"type": "join", "room_id": room.ID})
	writeWSJSON(t, wsReceiverInvalid, map[string]any{"type": "join", "room_id": room.ID})
	if _, err := waitForWSMessageType(wsSender, "members", 2*time.Second); err != nil {
		t.Fatalf("expected sender members update after join: %v", err)
	}
	if _, err := waitForWSMessageType(wsReceiverInvalid, "members", 2*time.Second); err != nil {
		t.Fatalf("expected receiver members update after join: %v", err)
	}

	invalidState := map[string]any{
		"iv":         base64.StdEncoding.EncodeToString([]byte{9, 8, 7}),
		"ciphertext": base64.StdEncoding.EncodeToString([]byte{6, 5, 4}),
	}
	writeWSJSON(t, wsSender, map[string]any{
		"type":    "ratchet_state",
		"room_id": room.ID,
		"content": map[string]any{
			"user_id":   receiver.ID,
			"state":     invalidState,
			"epoch":     1,
			"reason":    "test_invalid",
			"timestamp": time.Now().UnixMilli(),
			"signature": "",
		},
	})
	if _, err := waitForWSMessageType(wsReceiverInvalid, "ratchet_state", 700*time.Millisecond); err == nil {
		t.Fatalf("expected unsigned ratchet_state to be rejected")
	}
	_ = wsReceiverInvalid.Close()

	wsReceiverValid := dialWebSocket(t, server.URL, receiverClient)
	defer wsReceiverValid.Close()
	writeWSJSON(t, wsReceiverValid, map[string]any{"type": "join", "room_id": room.ID})
	if _, err := waitForWSMessageType(wsReceiverValid, "members", 2*time.Second); err != nil {
		t.Fatalf("expected receiver members update after rejoin: %v", err)
	}

	validState := map[string]any{
		"iv":         base64.StdEncoding.EncodeToString([]byte{1, 1, 1}),
		"ciphertext": base64.StdEncoding.EncodeToString([]byte{2, 2, 2}),
	}
	epoch := 3
	reason := "membership_change"
	timestamp := time.Now().UnixMilli()
	signature := signRatchetStatePayload(t, sender.SigningPrivate, room.ID, receiver.ID, validState, epoch, reason, timestamp)
	writeWSJSON(t, wsSender, map[string]any{
		"type":    "ratchet_state",
		"room_id": room.ID,
		"content": map[string]any{
			"user_id":   receiver.ID,
			"state":     validState,
			"epoch":     epoch,
			"reason":    reason,
			"timestamp": timestamp,
			"signature": signature,
		},
	})

	msg, err := waitForWSMessageType(wsReceiverValid, "ratchet_state", 2*time.Second)
	if err != nil {
		t.Fatalf("expected signed ratchet_state to be delivered: %v", err)
	}
	requireWSStringField(t, msg, "sender_id", sender.ID)
	requireWSStringField(t, msg, "sender", sender.Username)
}

func TestWebSocketRejectsMessageBelowRoomEpoch(t *testing.T) {
	server := newTestHTTPServer(t)

	senderClient := newTestClient(t)
	sender := newTestUser(t, "epoch_msg_sender", "Password123!")
	senderCSRF := fetchCSRFToken(t, senderClient, server.URL)
	sender.ID = createAccount(t, senderClient, server.URL, sender, senderCSRF)
	room := createRoom(t, senderClient, server.URL, "epoch-message-room", false)

	receiverClient := newTestClient(t)
	receiver := newTestUser(t, "epoch_msg_receiver", "Password123!")
	receiverCSRF := fetchCSRFToken(t, receiverClient, server.URL)
	receiver.ID = createAccount(t, receiverClient, server.URL, receiver, receiverCSRF)

	receiverCSRF = fetchCSRFToken(t, receiverClient, server.URL)
	status, _, body := doJSONRequest(
		t,
		receiverClient,
		http.MethodPost,
		fmt.Sprintf("%s/api/rooms/%s/join", server.URL, room.ID),
		map[string]any{},
		map[string]string{"X-CSRF-Token": receiverCSRF},
	)
	if status != http.StatusOK {
		t.Fatalf("expected receiver join success, got %d body=%s", status, string(body))
	}
	var joinResp struct {
		CurrentEpoch int `json:"current_epoch"`
	}
	unmarshalJSON(t, body, &joinResp)
	if joinResp.CurrentEpoch <= 1 {
		t.Fatalf("expected room epoch to advance after membership change, got %d", joinResp.CurrentEpoch)
	}
	currentEpoch := joinResp.CurrentEpoch
	staleEpoch := currentEpoch - 1

	wsSender := dialWebSocket(t, server.URL, senderClient)
	defer wsSender.Close()
	wsReceiverInvalid := dialWebSocket(t, server.URL, receiverClient)

	writeWSJSON(t, wsSender, map[string]any{"type": "join", "room_id": room.ID})
	writeWSJSON(t, wsReceiverInvalid, map[string]any{"type": "join", "room_id": room.ID})
	if _, err := waitForWSMessageType(wsSender, "members", 2*time.Second); err != nil {
		t.Fatalf("expected sender members update after join: %v", err)
	}
	if _, err := waitForWSMessageType(wsReceiverInvalid, "members", 2*time.Second); err != nil {
		t.Fatalf("expected receiver members update after join: %v", err)
	}

	ivB64 := base64.StdEncoding.EncodeToString([]byte{7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7})
	ciphertextB64 := base64.StdEncoding.EncodeToString([]byte{8, 8, 8})

	staleTimestamp := time.Now().UnixMilli()
	staleSignature := signChatPayload(t, sender.SigningPrivate, room.ID, ivB64, ciphertextB64, staleTimestamp, staleEpoch, 0)
	writeWSJSON(t, wsSender, wsMessageEnvelope{
		Type:       "message",
		RoomID:     room.ID,
		Content:    map[string]any{"iv": ivB64, "ciphertext": ciphertextB64},
		Signature:  staleSignature,
		Timestamp:  staleTimestamp,
		Generation: staleEpoch,
		MessageNum: 0,
	})
	if _, err := waitForWSMessageType(wsReceiverInvalid, "message", 700*time.Millisecond); err == nil {
		t.Fatalf("expected message below room epoch to be rejected")
	}
	_ = wsReceiverInvalid.Close()

	wsReceiverValid := dialWebSocket(t, server.URL, receiverClient)
	defer wsReceiverValid.Close()
	writeWSJSON(t, wsReceiverValid, map[string]any{"type": "join", "room_id": room.ID})
	if _, err := waitForWSMessageType(wsReceiverValid, "members", 2*time.Second); err != nil {
		t.Fatalf("expected receiver members update after rejoin: %v", err)
	}

	status, _, body = doJSONRequest(
		t,
		senderClient,
		http.MethodGet,
		fmt.Sprintf("%s/api/rooms/%s", server.URL, room.ID),
		nil,
		nil,
	)
	if status != http.StatusOK {
		t.Fatalf("expected sender room read success, got %d body=%s", status, string(body))
	}
	var roomState struct {
		CurrentEpoch int `json:"current_epoch"`
	}
	unmarshalJSON(t, body, &roomState)
	if roomState.CurrentEpoch < currentEpoch {
		t.Fatalf("expected room epoch to be monotonic, got %d < %d", roomState.CurrentEpoch, currentEpoch)
	}
	currentEpoch = roomState.CurrentEpoch

	validTimestamp := time.Now().UnixMilli() + 5
	validSignature := signChatPayload(t, sender.SigningPrivate, room.ID, ivB64, ciphertextB64, validTimestamp, currentEpoch, 0)
	writeWSJSON(t, wsSender, wsMessageEnvelope{
		Type:       "message",
		RoomID:     room.ID,
		Content:    map[string]any{"iv": ivB64, "ciphertext": ciphertextB64},
		Signature:  validSignature,
		Timestamp:  validTimestamp,
		Generation: currentEpoch,
		MessageNum: 0,
	})
	if _, err := waitForWSMessageType(wsReceiverValid, "message", 2*time.Second); err != nil {
		t.Fatalf("expected message at current room epoch to be delivered: %v", err)
	}
}

func TestWebSocketRejectsRatchetStateBelowRoomEpoch(t *testing.T) {
	server := newTestHTTPServer(t)

	senderClient := newTestClient(t)
	sender := newTestUser(t, "epoch_ratchet_sender", "Password123!")
	senderCSRF := fetchCSRFToken(t, senderClient, server.URL)
	sender.ID = createAccount(t, senderClient, server.URL, sender, senderCSRF)
	room := createRoom(t, senderClient, server.URL, "epoch-ratchet-room", false)

	receiverClient := newTestClient(t)
	receiver := newTestUser(t, "epoch_ratchet_receiver", "Password123!")
	receiverCSRF := fetchCSRFToken(t, receiverClient, server.URL)
	receiver.ID = createAccount(t, receiverClient, server.URL, receiver, receiverCSRF)

	receiverCSRF = fetchCSRFToken(t, receiverClient, server.URL)
	status, _, body := doJSONRequest(
		t,
		receiverClient,
		http.MethodPost,
		fmt.Sprintf("%s/api/rooms/%s/join", server.URL, room.ID),
		map[string]any{},
		map[string]string{"X-CSRF-Token": receiverCSRF},
	)
	if status != http.StatusOK {
		t.Fatalf("expected receiver join success, got %d body=%s", status, string(body))
	}
	var joinResp struct {
		CurrentEpoch int `json:"current_epoch"`
	}
	unmarshalJSON(t, body, &joinResp)
	if joinResp.CurrentEpoch <= 1 {
		t.Fatalf("expected room epoch to advance after membership change, got %d", joinResp.CurrentEpoch)
	}
	currentEpoch := joinResp.CurrentEpoch
	staleEpoch := currentEpoch - 1

	wsSender := dialWebSocket(t, server.URL, senderClient)
	defer wsSender.Close()
	wsReceiverInvalid := dialWebSocket(t, server.URL, receiverClient)

	writeWSJSON(t, wsSender, map[string]any{"type": "join", "room_id": room.ID})
	writeWSJSON(t, wsReceiverInvalid, map[string]any{"type": "join", "room_id": room.ID})
	if _, err := waitForWSMessageType(wsSender, "members", 2*time.Second); err != nil {
		t.Fatalf("expected sender members update after join: %v", err)
	}
	if _, err := waitForWSMessageType(wsReceiverInvalid, "members", 2*time.Second); err != nil {
		t.Fatalf("expected receiver members update after join: %v", err)
	}

	staleState := map[string]any{
		"iv":         base64.StdEncoding.EncodeToString([]byte{5, 5, 5}),
		"ciphertext": base64.StdEncoding.EncodeToString([]byte{6, 6, 6}),
	}
	staleTimestamp := time.Now().UnixMilli()
	staleSignature := signRatchetStatePayload(t, sender.SigningPrivate, room.ID, receiver.ID, staleState, staleEpoch, "epoch_test", staleTimestamp)
	writeWSJSON(t, wsSender, map[string]any{
		"type":    "ratchet_state",
		"room_id": room.ID,
		"content": map[string]any{
			"user_id":   receiver.ID,
			"state":     staleState,
			"epoch":     staleEpoch,
			"reason":    "epoch_test",
			"timestamp": staleTimestamp,
			"signature": staleSignature,
		},
	})
	if _, err := waitForWSMessageType(wsReceiverInvalid, "ratchet_state", 700*time.Millisecond); err == nil {
		t.Fatalf("expected ratchet_state below room epoch to be rejected")
	}
	_ = wsReceiverInvalid.Close()

	wsReceiverValid := dialWebSocket(t, server.URL, receiverClient)
	defer wsReceiverValid.Close()
	writeWSJSON(t, wsReceiverValid, map[string]any{"type": "join", "room_id": room.ID})
	if _, err := waitForWSMessageType(wsReceiverValid, "members", 2*time.Second); err != nil {
		t.Fatalf("expected receiver members update after rejoin: %v", err)
	}

	status, _, body = doJSONRequest(
		t,
		senderClient,
		http.MethodGet,
		fmt.Sprintf("%s/api/rooms/%s", server.URL, room.ID),
		nil,
		nil,
	)
	if status != http.StatusOK {
		t.Fatalf("expected sender room read success, got %d body=%s", status, string(body))
	}
	var roomState struct {
		CurrentEpoch int `json:"current_epoch"`
	}
	unmarshalJSON(t, body, &roomState)
	if roomState.CurrentEpoch < currentEpoch {
		t.Fatalf("expected room epoch to be monotonic, got %d < %d", roomState.CurrentEpoch, currentEpoch)
	}
	currentEpoch = roomState.CurrentEpoch

	validState := map[string]any{
		"iv":         base64.StdEncoding.EncodeToString([]byte{9, 9, 9}),
		"ciphertext": base64.StdEncoding.EncodeToString([]byte{1, 2, 3}),
	}
	validTimestamp := time.Now().UnixMilli() + 5
	validSignature := signRatchetStatePayload(t, sender.SigningPrivate, room.ID, receiver.ID, validState, currentEpoch, "epoch_test", validTimestamp)
	writeWSJSON(t, wsSender, map[string]any{
		"type":    "ratchet_state",
		"room_id": room.ID,
		"content": map[string]any{
			"user_id":   receiver.ID,
			"state":     validState,
			"epoch":     currentEpoch,
			"reason":    "epoch_test",
			"timestamp": validTimestamp,
			"signature": validSignature,
		},
	})
	if _, err := waitForWSMessageType(wsReceiverValid, "ratchet_state", 2*time.Second); err != nil {
		t.Fatalf("expected ratchet_state at current room epoch to be delivered: %v", err)
	}
}

func TestDeleteAccountBroadcastsRoomDeletedWithRoomID(t *testing.T) {
	server := newTestHTTPServer(t)

	ownerClient := newTestClient(t)
	owner := newTestUser(t, "room_delete_owner", "Password123!")
	ownerCSRF := fetchCSRFToken(t, ownerClient, server.URL)
	owner.ID = createAccount(t, ownerClient, server.URL, owner, ownerCSRF)
	room := createRoom(t, ownerClient, server.URL, "owner-delete-room", false)

	memberClient := newTestClient(t)
	member := newTestUser(t, "room_delete_member", "Password123!")
	memberCSRF := fetchCSRFToken(t, memberClient, server.URL)
	member.ID = createAccount(t, memberClient, server.URL, member, memberCSRF)

	memberCSRF = fetchCSRFToken(t, memberClient, server.URL)
	status, _, body := doJSONRequest(
		t,
		memberClient,
		http.MethodPost,
		fmt.Sprintf("%s/api/rooms/%s/join", server.URL, room.ID),
		map[string]any{},
		map[string]string{"X-CSRF-Token": memberCSRF},
	)
	if status != http.StatusOK {
		t.Fatalf("expected member join success, got %d body=%s", status, string(body))
	}

	wsMember := dialWebSocket(t, server.URL, memberClient)
	defer wsMember.Close()
	writeWSJSON(t, wsMember, map[string]any{"type": "join", "room_id": room.ID})
	if _, err := waitForWSMessageType(wsMember, "members", 2*time.Second); err != nil {
		t.Fatalf("expected members update on member socket: %v", err)
	}

	ownerCSRF = fetchCSRFToken(t, ownerClient, server.URL)
	status, _, body = doJSONRequest(
		t,
		ownerClient,
		http.MethodPost,
		server.URL+"/api/auth/delete-account",
		map[string]any{
			"password":     owner.Password,
			"confirmation": "DELETE",
		},
		map[string]string{"X-CSRF-Token": ownerCSRF},
	)
	if status != http.StatusOK {
		t.Fatalf("expected delete-account challenge success, got %d body=%s", status, string(body))
	}

	var challenge challengeResponse
	unmarshalJSON(t, body, &challenge)
	if challenge.Nonce == "" || challenge.UserID != owner.ID {
		t.Fatalf("unexpected delete-account challenge response: nonce=%q user_id=%q", challenge.Nonce, challenge.UserID)
	}

	ownerCSRF = fetchCSRFToken(t, ownerClient, server.URL)
	deleteSignature := signChallenge(t, owner.SigningPrivate, challenge.Nonce, challenge.UserID)
	status, _, body = doJSONRequest(
		t,
		ownerClient,
		http.MethodPost,
		server.URL+"/api/auth/confirm-delete",
		map[string]any{
			"nonce":     challenge.Nonce,
			"signature": deleteSignature,
		},
		map[string]string{"X-CSRF-Token": ownerCSRF},
	)
	if status != http.StatusOK {
		t.Fatalf("expected confirm-delete success, got %d body=%s", status, string(body))
	}

	msg, err := waitForWSMessageType(wsMember, "room_deleted", 2*time.Second)
	if err != nil {
		t.Fatalf("expected room_deleted websocket message: %v", err)
	}
	requireWSStringField(t, msg, "room_id", room.ID)
	requireWSStringField(t, msg, "sender_id", owner.ID)
}

func TestWebSocketPrivateRoomRequiresInviteCode(t *testing.T) {
	server := newTestHTTPServer(t)

	ownerClient := newTestClient(t)
	owner := newTestUser(t, "private_ws_owner", "Password123!")
	ownerCSRF := fetchCSRFToken(t, ownerClient, server.URL)
	owner.ID = createAccount(t, ownerClient, server.URL, owner, ownerCSRF)

	room := createRoom(t, ownerClient, server.URL, "private-ws-room", true)
	if room.InviteCode == "" {
		t.Fatalf("expected invite code for private room")
	}

	guestClient := newTestClient(t)
	guest := newTestUser(t, "private_ws_guest", "Password123!")
	guestCSRF := fetchCSRFToken(t, guestClient, server.URL)
	guest.ID = createAccount(t, guestClient, server.URL, guest, guestCSRF)

	wsMissingCode := dialWebSocket(t, server.URL, guestClient)
	writeWSJSON(t, wsMissingCode, map[string]any{
		"type":    "join",
		"room_id": room.ID,
	})
	if _, err := waitForWSMessageType(wsMissingCode, "members", 700*time.Millisecond); err == nil {
		t.Fatalf("expected join without invite code to be rejected")
	}
	_ = wsMissingCode.Close()

	wsWrongCode := dialWebSocket(t, server.URL, guestClient)
	writeWSJSON(t, wsWrongCode, map[string]any{
		"type":    "join",
		"room_id": room.ID,
		"content": map[string]any{
			"invite_code": "invalid-code",
		},
	})
	if _, err := waitForWSMessageType(wsWrongCode, "members", 700*time.Millisecond); err == nil {
		t.Fatalf("expected join with invalid invite code to be rejected")
	}
	_ = wsWrongCode.Close()

	wsValid := dialWebSocket(t, server.URL, guestClient)
	defer wsValid.Close()
	writeWSJSON(t, wsValid, map[string]any{
		"type":    "join",
		"room_id": room.ID,
		"content": map[string]any{
			"invite_code": room.InviteCode,
		},
	})
	if _, err := waitForWSMessageType(wsValid, "members", 2*time.Second); err != nil {
		t.Fatalf("expected join with valid invite code to succeed: %v", err)
	}
}

func TestWebSocketMembershipRevokedAcrossSockets(t *testing.T) {
	server := newTestHTTPServer(t)

	ownerClient := newTestClient(t)
	owner := newTestUser(t, "revoke_owner", "Password123!")
	ownerCSRF := fetchCSRFToken(t, ownerClient, server.URL)
	owner.ID = createAccount(t, ownerClient, server.URL, owner, ownerCSRF)
	room := createRoom(t, ownerClient, server.URL, "revocation-room", false)

	memberClient := newTestClient(t)
	member := newTestUser(t, "revoke_member", "Password123!")
	memberCSRF := fetchCSRFToken(t, memberClient, server.URL)
	member.ID = createAccount(t, memberClient, server.URL, member, memberCSRF)

	memberCSRF = fetchCSRFToken(t, memberClient, server.URL)
	status, _, body := doJSONRequest(
		t,
		memberClient,
		http.MethodPost,
		fmt.Sprintf("%s/api/rooms/%s/join", server.URL, room.ID),
		map[string]any{},
		map[string]string{"X-CSRF-Token": memberCSRF},
	)
	if status != http.StatusOK {
		t.Fatalf("expected member join success, got %d body=%s", status, string(body))
	}

	wsOwner := dialWebSocket(t, server.URL, ownerClient)
	defer wsOwner.Close()
	wsMember := dialWebSocket(t, server.URL, memberClient)
	defer wsMember.Close()

	writeWSJSON(t, wsOwner, map[string]any{"type": "join", "room_id": room.ID})
	if _, err := waitForWSMessageType(wsOwner, "members", 2*time.Second); err != nil {
		t.Fatalf("expected owner members update after join: %v", err)
	}

	writeWSJSON(t, wsMember, map[string]any{"type": "join", "room_id": room.ID})
	if _, err := waitForWSMessageType(wsMember, "members", 2*time.Second); err != nil {
		t.Fatalf("expected member members update after join: %v", err)
	}

	memberCSRF = fetchCSRFToken(t, memberClient, server.URL)
	status, _, body = doJSONRequest(
		t,
		memberClient,
		http.MethodPost,
		fmt.Sprintf("%s/api/rooms/%s/leave", server.URL, room.ID),
		nil,
		map[string]string{"X-CSRF-Token": memberCSRF},
	)
	if status != http.StatusOK {
		t.Fatalf("expected member leave success, got %d body=%s", status, string(body))
	}

	status, _, body = doJSONRequest(
		t,
		ownerClient,
		http.MethodGet,
		fmt.Sprintf("%s/api/rooms/%s", server.URL, room.ID),
		nil,
		nil,
	)
	if status != http.StatusOK {
		t.Fatalf("expected owner room read success, got %d body=%s", status, string(body))
	}
	var roomState struct {
		CurrentEpoch int `json:"current_epoch"`
	}
	unmarshalJSON(t, body, &roomState)
	if roomState.CurrentEpoch < 1 {
		t.Fatalf("expected room current_epoch >= 1 after leave, got %d", roomState.CurrentEpoch)
	}
	// After fix #12: broadcastToRoom no longer checks membership per-recipient
	// (session ticker and send-time checks enforce membership instead).
	// The revoked member may still receive broadcasts but cannot decrypt them
	// (room epoch bumped on leave). Verify that send-side checks still block
	// the revoked member from injecting messages into the room.
	writeWSJSON(t, wsMember, map[string]any{
		"type":    "key_request",
		"room_id": room.ID,
		"content": map[string]any{"reason": "should be rejected"},
	})
	if _, err := waitForWSMessageType(wsOwner, "key_request", 900*time.Millisecond); err == nil {
		t.Fatalf("expected revoked member websocket control message to be rejected")
	}
}

func TestWebSocketLogoutClosesActiveSessionSocket(t *testing.T) {
	server := newTestHTTPServer(t)

	client := newTestClient(t)
	user := newTestUser(t, "logout_ws_user", "Password123!")
	csrf := fetchCSRFToken(t, client, server.URL)
	user.ID = createAccount(t, client, server.URL, user, csrf)

	wsConn := dialWebSocket(t, server.URL, client)
	defer wsConn.Close()

	csrf = fetchCSRFToken(t, client, server.URL)
	status, _, body := doJSONRequest(
		t,
		client,
		http.MethodPost,
		server.URL+"/api/auth/logout",
		nil,
		map[string]string{"X-CSRF-Token": csrf},
	)
	if status != http.StatusOK {
		t.Fatalf("expected logout success, got %d body=%s", status, string(body))
	}

	wsConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, _, err := wsConn.ReadMessage(); err == nil {
		t.Fatalf("expected websocket to close after session logout invalidation")
	}
}

func TestCSRFTokensAreCaseSensitive(t *testing.T) {
	server := newTestHTTPServer(t)
	client := newTestClient(t)
	user := newTestUser(t, "csrf_case_user", "Password123!")

	csrf := fetchCSRFToken(t, client, server.URL)
	user.ID = createAccount(t, client, server.URL, user, csrf)

	validToken := fetchCSRFToken(t, client, server.URL)
	mutatedToken, ok := mutateTokenCase(validToken)
	if !ok {
		t.Fatalf("expected csrf token to contain alphabetical characters for case-sensitivity test")
	}

	status, _, body := doJSONRequest(
		t,
		client,
		http.MethodPost,
		server.URL+"/api/rooms",
		map[string]any{"name": "csrf-case-room", "is_private": false},
		map[string]string{"X-CSRF-Token": mutatedToken},
	)
	if status != http.StatusForbidden {
		t.Fatalf("expected case-mutated csrf token to be rejected, got %d body=%s", status, string(body))
	}

	status, _, body = doJSONRequest(
		t,
		client,
		http.MethodPost,
		server.URL+"/api/rooms",
		map[string]any{"name": "csrf-valid-room", "is_private": false},
		map[string]string{"X-CSRF-Token": validToken},
	)
	if status != http.StatusOK {
		t.Fatalf("expected original csrf token to succeed, got %d body=%s", status, string(body))
	}
}

func TestSessionCookieSecureFlagRequiresTrustedProxy(t *testing.T) {
	userNoTrust := newTestUser(t, "secure_cookie_no_trust", "Password123!")
	serverNoTrust := newTestHTTPServerWithTrustedProxies(t, "")
	clientNoTrust := newTestClient(t)
	csrfNoTrust := fetchCSRFToken(t, clientNoTrust, serverNoTrust.URL)
	status, headers, body := doJSONRequest(
		t,
		clientNoTrust,
		http.MethodPost,
		serverNoTrust.URL+"/api/auth/create",
		map[string]any{
			"username":    userNoTrust.Username,
			"password":    userNoTrust.Password,
			"public_key":  userNoTrust.PublicKey,
			"signing_key": userNoTrust.SigningKey,
		},
		map[string]string{
			"X-CSRF-Token":      csrfNoTrust,
			"X-Forwarded-Proto": "https",
		},
	)
	if status != http.StatusCreated {
		t.Fatalf("expected account creation success without trusted proxy, got %d body=%s", status, string(body))
	}
	if sessionCookie := findSetCookie(headers, "session"); sessionCookie == "" {
		t.Fatalf("expected session cookie in response")
	} else if strings.Contains(sessionCookie, "; Secure") {
		t.Fatalf("did not expect secure cookie when forwarded proto is untrusted")
	}
	if csrfCookie := findSetCookie(headers, "csrf_token"); csrfCookie == "" {
		t.Fatalf("expected csrf cookie in response")
	} else if strings.Contains(csrfCookie, "; Secure") {
		t.Fatalf("did not expect secure csrf cookie when forwarded proto is untrusted")
	}

	userTrusted := newTestUser(t, "secure_cookie_trusted", "Password123!")
	serverTrusted := newTestHTTPServerWithTrustedProxies(t, "127.0.0.1,::1")
	clientTrusted := newTestClient(t)
	csrfTrusted := fetchCSRFToken(t, clientTrusted, serverTrusted.URL)
	status, headers, body = doJSONRequest(
		t,
		clientTrusted,
		http.MethodPost,
		serverTrusted.URL+"/api/auth/create",
		map[string]any{
			"username":    userTrusted.Username,
			"password":    userTrusted.Password,
			"public_key":  userTrusted.PublicKey,
			"signing_key": userTrusted.SigningKey,
		},
		map[string]string{
			"X-CSRF-Token":      csrfTrusted,
			"X-Forwarded-Proto": "https",
		},
	)
	if status != http.StatusCreated {
		t.Fatalf("expected account creation success with trusted proxy, got %d body=%s", status, string(body))
	}
	if sessionCookie := findSetCookie(headers, "session"); sessionCookie == "" {
		t.Fatalf("expected session cookie in response")
	} else if !strings.Contains(sessionCookie, "; Secure") {
		t.Fatalf("expected secure session cookie when forwarded proto comes from trusted proxy")
	}
	if csrfCookie := findSetCookie(headers, "csrf_token"); csrfCookie == "" {
		t.Fatalf("expected csrf cookie in response")
	} else if !strings.Contains(csrfCookie, "; Secure") {
		t.Fatalf("expected secure csrf cookie when forwarded proto comes from trusted proxy")
	}
}

func newTestHTTPServer(t *testing.T) *httptest.Server {
	return newTestHTTPServerWithTrustedProxies(t, "")
}

func newTestHTTPServerWithTrustedProxies(t *testing.T, trustedProxies string) *httptest.Server {
	t.Helper()

	sessionSecret := strings.Repeat("a", 32)
	session.SetSecret(sessionSecret)
	session.SetTrustedProxies(trustedProxies)
	allowedOrigins, err := parseAllowedOrigins(testOrigin)
	if err != nil {
		t.Fatalf("failed to parse test origin: %v", err)
	}
	handler.SetAllowedOrigins(allowedOrigins)

	dbPath := filepath.Join(t.TempDir(), "integration.db")
	database, err := db.New(dbPath)
	if err != nil {
		t.Fatalf("failed to initialize database: %v", err)
	}
	t.Cleanup(func() {
		_ = database.Close()
	})

	middleware.SetCSRFDatabase(database)
	middleware.SetAuthDatabase(database)

	wsHandler := handler.NewWSHandler(database)
	authHandler := &handler.AuthHandler{DB: database, WS: wsHandler}
	roomHandler := &handler.RoomHandler{DB: database}

	ctx := t.Context()
	rateLimiter := middleware.NewRateLimiter(ctx, 1000, time.Minute)
	sensitiveLimiter := middleware.NewRateLimiter(ctx, 1000, time.Minute)
	csrfBootstrapLimiter := middleware.NewRateLimiter(ctx, 1000, time.Minute)

	mux := http.NewServeMux()
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

	server := httptest.NewServer(bodyLimitMiddleware(corsMiddleware(mux, allowedOrigins)))
	t.Cleanup(server.Close)
	return server
}

func newTestClient(t *testing.T) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("failed to create cookie jar: %v", err)
	}
	return &http.Client{Jar: jar}
}

func newTestUser(t *testing.T, username, password string) *testUser {
	t.Helper()

	ecdhPrivate, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDH key: %v", err)
	}
	publicKey, err := x509.MarshalPKIXPublicKey(&ecdhPrivate.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal ECDH public key: %v", err)
	}

	signingPrivate, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA signing key: %v", err)
	}
	signingKey, err := x509.MarshalPKIXPublicKey(&signingPrivate.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal ECDSA signing key: %v", err)
	}

	return &testUser{
		Username:       username,
		Password:       password,
		PublicKey:      publicKey,
		SigningKey:     signingKey,
		SigningPrivate: signingPrivate,
	}
}

func doJSONRequest(
	t *testing.T,
	client *http.Client,
	method, endpoint string,
	body any,
	headers map[string]string,
) (int, http.Header, []byte) {
	t.Helper()

	var reqBody io.Reader
	if body != nil {
		payload, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("failed to marshal request body: %v", err)
		}
		reqBody = bytes.NewReader(payload)
	}

	req, err := http.NewRequest(method, endpoint, reqBody)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read response body: %v", err)
	}

	return resp.StatusCode, resp.Header.Clone(), respBody
}

func fetchCSRFToken(t *testing.T, client *http.Client, baseURL string) string {
	t.Helper()
	status, headers, _ := doJSONRequest(t, client, http.MethodGet, baseURL+"/api/auth/me", nil, nil)
	if status != http.StatusOK && status != http.StatusUnauthorized {
		t.Fatalf("unexpected status when fetching csrf token: %d", status)
	}

	if token := headers.Get("X-CSRF-Token"); token != "" {
		return token
	}

	token := getCookieValue(t, client, baseURL, "csrf_token")
	if token == "" {
		t.Fatalf("csrf token not found in response headers or cookie jar")
	}
	return token
}

func getCookieValue(t *testing.T, client *http.Client, baseURL, name string) string {
	t.Helper()
	parsedURL, err := url.Parse(baseURL)
	if err != nil {
		t.Fatalf("invalid base url: %v", err)
	}
	for _, cookie := range client.Jar.Cookies(parsedURL) {
		if cookie.Name == name {
			return cookie.Value
		}
	}
	return ""
}

func createAccount(t *testing.T, client *http.Client, baseURL string, user *testUser, csrfToken string) string {
	t.Helper()
	status, _, body := doJSONRequest(
		t,
		client,
		http.MethodPost,
		baseURL+"/api/auth/create",
		map[string]any{
			"username":    user.Username,
			"password":    user.Password,
			"public_key":  user.PublicKey,
			"signing_key": user.SigningKey,
		},
		map[string]string{"X-CSRF-Token": csrfToken},
	)
	if status != http.StatusCreated {
		t.Fatalf("expected account creation success, got %d body=%s", status, string(body))
	}

	var resp struct {
		ID string `json:"id"`
	}
	unmarshalJSON(t, body, &resp)
	if resp.ID == "" {
		t.Fatalf("expected account id in create response")
	}
	return resp.ID
}

func createRoom(t *testing.T, client *http.Client, baseURL, name string, isPrivate bool) roomResponse {
	t.Helper()
	csrfToken := fetchCSRFToken(t, client, baseURL)
	status, _, body := doJSONRequest(
		t,
		client,
		http.MethodPost,
		baseURL+"/api/rooms",
		map[string]any{"name": name, "is_private": isPrivate},
		map[string]string{"X-CSRF-Token": csrfToken},
	)
	if status != http.StatusOK {
		t.Fatalf("expected room creation success, got %d body=%s", status, string(body))
	}
	var room roomResponse
	unmarshalJSON(t, body, &room)
	if room.ID == "" {
		t.Fatalf("expected room id in create room response")
	}
	if room.CurrentEpoch < 1 {
		t.Fatalf("expected room current_epoch >= 1, got %d", room.CurrentEpoch)
	}
	return room
}

func login(t *testing.T, client *http.Client, baseURL, csrfToken, username, password string) challengeResponse {
	t.Helper()
	status, _, body := doJSONRequest(
		t,
		client,
		http.MethodPost,
		baseURL+"/api/auth/login",
		map[string]any{"username": username, "password": password},
		map[string]string{"X-CSRF-Token": csrfToken},
	)
	if status != http.StatusOK {
		t.Fatalf("expected login challenge success, got %d body=%s", status, string(body))
	}

	var challenge challengeResponse
	unmarshalJSON(t, body, &challenge)
	if challenge.Nonce == "" || challenge.UserID == "" {
		t.Fatalf("expected nonce and user_id in login challenge response")
	}
	return challenge
}

func signChallenge(t *testing.T, privateKey *ecdsa.PrivateKey, nonce, userID string) []byte {
	t.Helper()
	payload := []byte(nonce + ":" + userID)
	hash := sha256.Sum256(payload)
	return signP1363(t, privateKey, hash[:])
}

func signChatPayload(
	t *testing.T,
	privateKey *ecdsa.PrivateKey,
	roomID string,
	iv any,
	ciphertext any,
	timestamp int64,
	generation int,
	messageNum int,
) []byte {
	t.Helper()

	payload := struct {
		RoomID     string `json:"room_id"`
		IV         any    `json:"iv"`
		Ciphertext any    `json:"ciphertext"`
		Timestamp  int64  `json:"timestamp"`
		Generation int    `json:"generation"`
		MessageNum int    `json:"message_num"`
	}{
		RoomID:     roomID,
		IV:         iv,
		Ciphertext: ciphertext,
		Timestamp:  timestamp,
		Generation: generation,
		MessageNum: messageNum,
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("failed to marshal websocket payload: %v", err)
	}
	hash := sha256.Sum256(payloadBytes)
	return signP1363(t, privateKey, hash[:])
}

func signRatchetStatePayload(
	t *testing.T,
	privateKey *ecdsa.PrivateKey,
	roomID, targetUserID string,
	state map[string]any,
	epoch int,
	reason string,
	timestamp int64,
) []byte {
	t.Helper()

	payload := struct {
		RoomID    string         `json:"room_id"`
		UserID    string         `json:"user_id"`
		State     map[string]any `json:"state"`
		Epoch     int            `json:"epoch"`
		Reason    string         `json:"reason"`
		Timestamp int64          `json:"timestamp"`
	}{
		RoomID:    roomID,
		UserID:    targetUserID,
		State:     state,
		Epoch:     epoch,
		Reason:    reason,
		Timestamp: timestamp,
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("failed to marshal ratchet state payload: %v", err)
	}
	hash := sha256.Sum256(payloadBytes)
	return signP1363(t, privateKey, hash[:])
}

func dialWebSocket(t *testing.T, baseURL string, client *http.Client) *websocket.Conn {
	t.Helper()

	httpURL, err := url.Parse(baseURL)
	if err != nil {
		t.Fatalf("failed to parse base URL: %v", err)
	}

	var cookieHeader []string
	for _, c := range client.Jar.Cookies(httpURL) {
		cookieHeader = append(cookieHeader, c.Name+"="+c.Value)
	}

	wsURL := "ws" + strings.TrimPrefix(baseURL, "http") + "/ws"
	headers := http.Header{}
	headers.Set("Origin", testOrigin)
	if len(cookieHeader) > 0 {
		headers.Set("Cookie", strings.Join(cookieHeader, "; "))
	}

	conn, _, err := websocket.DefaultDialer.Dial(wsURL, headers)
	if err != nil {
		t.Fatalf("failed to dial websocket: %v", err)
	}
	return conn
}

func writeWSJSON(t *testing.T, conn *websocket.Conn, payload any) {
	t.Helper()
	conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	if err := conn.WriteJSON(payload); err != nil {
		t.Fatalf("failed to write websocket payload: %v", err)
	}
}

func waitForWSMessageType(conn *websocket.Conn, msgType string, timeout time.Duration) (map[string]any, error) {
	deadline := time.Now().Add(timeout)
	for {
		conn.SetReadDeadline(deadline)
		_, data, err := conn.ReadMessage()
		if err != nil {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				return nil, fmt.Errorf("timeout waiting for websocket message type %q", msgType)
			}
			return nil, err
		}

		var msg map[string]any
		if err := json.Unmarshal(data, &msg); err != nil {
			continue
		}
		if msg["type"] == msgType {
			return msg, nil
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("timeout waiting for websocket message type %q", msgType)
		}
	}
}

func requireWSStringField(t *testing.T, msg map[string]any, field, expected string) {
	t.Helper()
	value, ok := msg[field]
	if !ok {
		t.Fatalf("expected websocket message field %q to exist", field)
	}
	actual, ok := value.(string)
	if !ok {
		t.Fatalf("expected websocket message field %q to be string, got %T", field, value)
	}
	if actual != expected {
		t.Fatalf("expected websocket field %q=%q, got %q", field, expected, actual)
	}
}

func hasMember(members []roomMember, userID string) bool {
	for _, member := range members {
		if member.ID == userID {
			return true
		}
	}
	return false
}

func unmarshalJSON(t *testing.T, data []byte, out any) {
	t.Helper()
	if err := json.Unmarshal(data, out); err != nil {
		t.Fatalf("failed to unmarshal json %q: %v", string(data), err)
	}
}

func findSetCookie(headers http.Header, cookieName string) string {
	prefix := cookieName + "="
	for _, value := range headers.Values("Set-Cookie") {
		if strings.HasPrefix(value, prefix) {
			return value
		}
	}
	return ""
}

func mutateTokenCase(token string) (string, bool) {
	runes := []rune(token)
	for i, r := range runes {
		switch {
		case 'a' <= r && r <= 'z':
			runes[i] = r - ('a' - 'A')
			return string(runes), true
		case 'A' <= r && r <= 'Z':
			runes[i] = r + ('a' - 'A')
			return string(runes), true
		}
	}
	return token, false
}
