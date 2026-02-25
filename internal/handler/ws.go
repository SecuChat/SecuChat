package handler

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"secuchat/internal/db"
	"secuchat/internal/models"
)

const (
	writeWait         = 10 * time.Second
	pongWait          = 60 * time.Second
	pingPeriod        = (pongWait * 9) / 10
	sessionCheckTick  = 5 * time.Second
	maxMessageSize    = 16384
	MaxConnsPerUser   = 5
	maxMessagesPerSec = 10
	maxMessageAge     = 5 * time.Minute
	maxTimestampSkew  = 30 * time.Second
	replayStateTTL    = 24 * time.Hour
	replayCleanupTick = 15 * time.Minute
	signingKeyTTL     = 6 * time.Hour
	signingKeyMax     = 4096
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin:     checkOrigin,
}

func checkOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if len(allowedOrigins) == 0 || origin == "" {
		return false
	}

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

type WSClient struct {
	ConnID       string
	Conn         *websocket.Conn
	SessionID    string
	UserID       string
	Username     string
	Rooms        map[string]bool
	roomsMu      sync.RWMutex
	Send         chan []byte
	messageCount int
	lastReset    time.Time
}

func (c *WSClient) joinRoom(roomID string) {
	c.roomsMu.Lock()
	defer c.roomsMu.Unlock()
	c.Rooms[roomID] = true
}

func (c *WSClient) leaveRoom(roomID string) {
	c.roomsMu.Lock()
	defer c.roomsMu.Unlock()
	delete(c.Rooms, roomID)
}

func (c *WSClient) inRoom(roomID string) bool {
	c.roomsMu.RLock()
	defer c.roomsMu.RUnlock()
	return c.Rooms[roomID]
}

type messageReplayState struct {
	LastGeneration int
	LastMessageNum int
	LastTimestamp  int64
	LastSeenAt     time.Time
}

type cachedSigningKey struct {
	Key        []byte
	LastUsedAt time.Time
}

type WSHandler struct {
	DB            *db.Database
	Clients       map[string]*WSClient
	UserConnCount map[string]int
	UserReplayMu  sync.RWMutex
	ReplayState   map[string]map[string]messageReplayState
	lastReplayGC  time.Time
	mu            sync.RWMutex
	signingKeys   map[string]cachedSigningKey
	lastKeyGC     time.Time
	keysMu        sync.RWMutex
}

func NewWSHandler(database *db.Database) *WSHandler {
	now := time.Now()
	return &WSHandler{
		DB:            database,
		Clients:       make(map[string]*WSClient),
		UserConnCount: make(map[string]int),
		ReplayState:   make(map[string]map[string]messageReplayState),
		lastReplayGC:  now,
		signingKeys:   make(map[string]cachedSigningKey),
		lastKeyGC:     now,
	}
}

func (h *WSHandler) HandleWebSocket(w http.ResponseWriter, r *http.Request) {
	sessionID, userID, username := getSessionFromCookie(r)
	if sessionID == "" || userID == "" {
		http.Error(w, "Not authenticated", http.StatusUnauthorized)
		return
	}

	valid, err := h.DB.ValidateSession(sessionID, userID)
	if err != nil || !valid {
		slog.Warn("WebSocket session validation failed", "user_id", userID, "error", err)
		http.Error(w, "Session expired or invalid", http.StatusUnauthorized)
		return
	}

	h.mu.Lock()
	if h.UserConnCount[userID] >= MaxConnsPerUser {
		h.mu.Unlock()
		http.Error(w, "Maximum connections exceeded", http.StatusTooManyRequests)
		slog.Warn("WebSocket connection limit exceeded", "user_id", userID, "username", username)
		return
	}
	h.UserConnCount[userID]++
	h.mu.Unlock()

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		slog.Error("WebSocket upgrade error", "error", err)
		h.mu.Lock()
		h.UserConnCount[userID]--
		if h.UserConnCount[userID] <= 0 {
			delete(h.UserConnCount, userID)
		}
		h.mu.Unlock()
		return
	}

	connID := uuid.New().String()
	client := &WSClient{
		ConnID:       connID,
		Conn:         conn,
		SessionID:    sessionID,
		UserID:       userID,
		Username:     username,
		Rooms:        make(map[string]bool),
		Send:         make(chan []byte, 256),
		messageCount: 0,
		lastReset:    time.Now(),
	}

	h.mu.Lock()
	h.Clients[connID] = client
	h.mu.Unlock()

	slog.Info("WebSocket connected", "conn_id", connID, "user_id", userID, "username", username)

	go h.writePump(client)
	h.readPump(client)
}

func (h *WSHandler) readPump(client *WSClient) {
	defer func() {
		h.mu.Lock()
		delete(h.Clients, client.ConnID)
		h.UserConnCount[client.UserID]--
		if h.UserConnCount[client.UserID] <= 0 {
			delete(h.UserConnCount, client.UserID)
		}
		h.mu.Unlock()
		close(client.Send)
		client.Conn.Close()
		slog.Info("WebSocket disconnected", "conn_id", client.ConnID, "user_id", client.UserID, "username", client.Username)
	}()

	client.Conn.SetReadLimit(maxMessageSize)
	client.Conn.SetReadDeadline(time.Now().Add(pongWait))
	client.Conn.SetPongHandler(func(string) error {
		client.Conn.SetReadDeadline(time.Now().Add(pongWait))
		return nil
	})

	for {
		_, message, err := client.Conn.ReadMessage()
		if err != nil {
			break
		}

		if !h.validateClientSession(client) {
			return
		}

		if time.Since(client.lastReset) > time.Second {
			client.messageCount = 0
			client.lastReset = time.Now()
		}
		client.messageCount++
		if client.messageCount > maxMessagesPerSec {
			slog.Warn("WebSocket rate limit exceeded", "user_id", client.UserID)
			return
		}

		var msg models.Message
		if err := json.Unmarshal(message, &msg); err != nil {
			continue
		}

		if msg.RoomID == "" && msg.Type != "pong" {
			slog.Warn("WebSocket message missing room_id", "user_id", client.UserID, "type", msg.Type)
			continue
		}

		msg.SenderID = client.UserID
		msg.Sender = client.Username

		switch msg.Type {
		case "join":
			if msg.RoomID == "" {
				continue
			}
			inviteCode, ok := parseInviteCode(msg.Content)
			if !ok {
				slog.Warn("Malformed join payload", "room_id", msg.RoomID, "user_id", client.UserID)
				continue
			}

			canJoin, err := h.canJoinRoom(msg.RoomID, inviteCode)
			if err != nil {
				slog.Warn("Room join check failed", "room_id", msg.RoomID, "user_id", client.UserID, "error", err)
				continue
			}
			if !canJoin {
				slog.Warn("Unauthorized room join attempt", "room_id", msg.RoomID, "user_id", client.UserID)
				continue
			}
			memberCount, err := h.DB.CountRoomMembers(msg.RoomID)
			if err != nil {
				slog.Warn("Failed to count room members on join", "room_id", msg.RoomID, "user_id", client.UserID, "error", err)
				continue
			}
			isMemberAlready, _ := h.DB.IsRoomMember(msg.RoomID, client.UserID)
			if !isMemberAlready && memberCount >= MaxMembersPerRoom {
				slog.Warn("Room full, rejecting join", "room_id", msg.RoomID, "user_id", client.UserID, "count", memberCount)
				continue
			}
			client.joinRoom(msg.RoomID)
			if err := h.DB.AddRoomMember(msg.RoomID, client.UserID); err != nil {
				slog.Warn("Failed to persist room membership on join", "room_id", msg.RoomID, "user_id", client.UserID, "error", err)
			}
			if err := h.DB.TouchRoomActivity(msg.RoomID); err != nil {
				slog.Warn("Failed to update room activity on join", "room_id", msg.RoomID, "user_id", client.UserID, "error", err)
			}
			h.broadcastMessageToRoom(msg.RoomID, models.Message{
				Type:     "join",
				RoomID:   msg.RoomID,
				SenderID: client.UserID,
				Sender:   client.Username,
			}, client.UserID)
			h.sendMemberList(msg.RoomID)
			slog.Debug("User joined room", "room_id", msg.RoomID, "user_id", client.UserID)

		case "leave":
			if msg.RoomID == "" {
				continue
			}
			client.leaveRoom(msg.RoomID)
			if err := h.DB.RemoveRoomMember(msg.RoomID, client.UserID); err != nil {
				slog.Warn("Failed to remove room membership on leave", "room_id", msg.RoomID, "user_id", client.UserID, "error", err)
			}
			h.broadcastMessageToRoom(msg.RoomID, models.Message{
				Type:     "leave",
				RoomID:   msg.RoomID,
				SenderID: client.UserID,
				Sender:   client.Username,
			}, client.UserID)
			h.sendMemberList(msg.RoomID)
			slog.Debug("User left room", "room_id", msg.RoomID, "user_id", client.UserID)

		case "message":
			if !client.inRoom(msg.RoomID) {
				slog.Warn("Message from room not joined", "room_id", msg.RoomID, "user_id", client.UserID)
				continue
			}
			isMember, err := h.DB.IsRoomMember(msg.RoomID, client.UserID)
			if err != nil {
				slog.Warn("Failed to verify room membership for message", "room_id", msg.RoomID, "user_id", client.UserID, "error", err)
				continue
			}
			if !isMember {
				client.leaveRoom(msg.RoomID)
				slog.Warn("Rejected message from non-member socket", "room_id", msg.RoomID, "user_id", client.UserID)
				continue
			}

			payload, ok := h.parseMessagePayload(&msg)
			if !ok {
				slog.Warn("Malformed message payload", "room_id", msg.RoomID, "user_id", client.UserID)
				continue
			}
			roomEpoch, err := h.DB.GetRoomEpoch(msg.RoomID)
			if err != nil {
				slog.Warn("Failed to read room epoch for message", "room_id", msg.RoomID, "user_id", client.UserID, "error", err)
				continue
			}
			if payload.Generation < roomEpoch {
				slog.Warn("Rejected message below room epoch", "room_id", msg.RoomID, "user_id", client.UserID, "generation", payload.Generation, "required_epoch", roomEpoch)
				continue
			}

			if !h.validateMessageTimestamp(payload.Timestamp) {
				slog.Warn("Message timestamp out of range", "room_id", msg.RoomID, "user_id", client.UserID, "timestamp", payload.Timestamp)
				continue
			}

			if !h.verifyMessageSignature(client.UserID, &msg, payload) {
				slog.Warn("Message signature verification failed", "room_id", msg.RoomID, "user_id", client.UserID)
				continue
			}

			if !h.validateMessageReplayState(client.UserID, msg.RoomID, payload) {
				slog.Warn("Message replay detected", "room_id", msg.RoomID, "user_id", client.UserID, "message_num", payload.MessageNum)
				continue
			}

			if err := h.DB.TouchRoomActivity(msg.RoomID); err != nil {
				slog.Warn("Failed to update room activity on message", "room_id", msg.RoomID, "user_id", client.UserID, "error", err)
			}
			h.broadcastMessageToRoom(msg.RoomID, models.Message{
				Type:       "message",
				RoomID:     msg.RoomID,
				SenderID:   client.UserID,
				Sender:     client.Username,
				Content:    msg.Content,
				Signature:  msg.Signature,
				Timestamp:  msg.Timestamp,
				Generation: msg.Generation,
				MessageNum: msg.MessageNum,
			}, client.UserID)

		case "room_key":
			if !client.inRoom(msg.RoomID) {
				continue
			}
			isMember, err := h.DB.IsRoomMember(msg.RoomID, client.UserID)
			if err != nil || !isMember {
				client.leaveRoom(msg.RoomID)
				continue
			}
			h.broadcastMessageToRoom(msg.RoomID, models.Message{
				Type:     "room_key",
				RoomID:   msg.RoomID,
				SenderID: client.UserID,
				Sender:   client.Username,
				Content:  msg.Content,
			}, client.UserID)

		case "key_exchange":
			if !client.inRoom(msg.RoomID) {
				continue
			}
			isMember, err := h.DB.IsRoomMember(msg.RoomID, client.UserID)
			if err != nil || !isMember {
				client.leaveRoom(msg.RoomID)
				continue
			}
			h.broadcastMessageToRoom(msg.RoomID, models.Message{
				Type:     "key_exchange",
				RoomID:   msg.RoomID,
				SenderID: client.UserID,
				Sender:   client.Username,
				Content:  msg.Content,
			}, client.UserID)

		case "key_request":
			if !client.inRoom(msg.RoomID) {
				continue
			}
			isMember, err := h.DB.IsRoomMember(msg.RoomID, client.UserID)
			if err != nil || !isMember {
				client.leaveRoom(msg.RoomID)
				continue
			}
			// Server-assisted key master: only forward key_request to the room creator
			room, err := h.DB.GetRoomByID(msg.RoomID)
			if err != nil {
				slog.Warn("Failed to look up room for key_request", "room_id", msg.RoomID, "error", err)
				continue
			}
			h.sendMessageToUser(room.CreatedBy, models.Message{
				Type:     "key_request",
				RoomID:   msg.RoomID,
				SenderID: client.UserID,
				Sender:   client.Username,
				Content:  msg.Content,
			})
			slog.Debug("Key request forwarded to room creator", "room_id", msg.RoomID, "user_id", client.UserID, "creator", room.CreatedBy)

		case "ratchet_state":
			if !client.inRoom(msg.RoomID) {
				continue
			}
			isMember, err := h.DB.IsRoomMember(msg.RoomID, client.UserID)
			if err != nil || !isMember {
				client.leaveRoom(msg.RoomID)
				continue
			}
			var content ratchetStateContent
			if err := json.Unmarshal(msg.Content, &content); err != nil {
				slog.Warn("Malformed ratchet state payload", "room_id", msg.RoomID, "from", client.UserID, "error", err)
				continue
			}
			if content.UserID == "" || len(content.State) == 0 {
				slog.Warn("Ratchet state missing required fields", "room_id", msg.RoomID, "from", client.UserID)
				continue
			}
			if !validateEncryptedPayload(content.State) {
				slog.Warn("Ratchet state payload is not base64 encoded", "room_id", msg.RoomID, "from", client.UserID, "to", content.UserID)
				continue
			}
			if content.Epoch <= 0 || content.Timestamp <= 0 || len(content.Signature) == 0 {
				slog.Warn("Ratchet state missing signature metadata", "room_id", msg.RoomID, "from", client.UserID, "to", content.UserID)
				continue
			}
			roomEpoch, err := h.DB.GetRoomEpoch(msg.RoomID)
			if err != nil {
				slog.Warn("Failed to read room epoch for ratchet_state", "room_id", msg.RoomID, "from", client.UserID, "to", content.UserID, "error", err)
				continue
			}
			if content.Epoch < roomEpoch {
				slog.Warn("Rejected ratchet_state below room epoch", "room_id", msg.RoomID, "from", client.UserID, "to", content.UserID, "epoch", content.Epoch, "required_epoch", roomEpoch)
				continue
			}
			if !h.validateMessageTimestamp(content.Timestamp) {
				slog.Warn("Ratchet state timestamp out of range", "room_id", msg.RoomID, "from", client.UserID, "to", content.UserID)
				continue
			}
			if !h.verifyRatchetStateSignature(client.UserID, msg.RoomID, &content) {
				slog.Warn("Ratchet state signature verification failed", "room_id", msg.RoomID, "from", client.UserID, "to", content.UserID)
				continue
			}

			isTargetMember, err := h.DB.IsRoomMember(msg.RoomID, content.UserID)
			if err != nil {
				slog.Warn("Failed to validate ratchet state target membership", "room_id", msg.RoomID, "from", client.UserID, "to", content.UserID, "error", err)
				continue
			}
			if !isTargetMember {
				slog.Warn("Rejected ratchet state to non-member target", "room_id", msg.RoomID, "from", client.UserID, "to", content.UserID)
				continue
			}

			h.sendMessageToUser(content.UserID, models.Message{
				Type:     "ratchet_state",
				RoomID:   msg.RoomID,
				SenderID: client.UserID,
				Sender:   client.Username,
				Content:  msg.Content,
			})
			slog.Debug("Ratchet state sent", "room_id", msg.RoomID, "from", client.UserID, "to", content.UserID)
		}
	}
}

func parseInviteCode(content json.RawMessage) (string, bool) {
	if len(content) == 0 || string(content) == "null" {
		return "", true
	}

	var payload struct {
		InviteCode string `json:"invite_code"`
	}
	if err := json.Unmarshal(content, &payload); err != nil {
		return "", false
	}

	return strings.TrimSpace(payload.InviteCode), true
}

func (h *WSHandler) canJoinRoom(roomID, inviteCode string) (bool, error) {
	room, err := h.DB.GetRoomByID(roomID)
	if err != nil {
		return false, err
	}

	if !room.IsPrivate {
		return true, nil
	}

	if inviteCode == "" {
		return false, nil
	}

	return subtle.ConstantTimeCompare([]byte(inviteCode), []byte(room.InviteCode)) == 1, nil
}

func (h *WSHandler) writePump(client *WSClient) {
	ticker := time.NewTicker(pingPeriod)
	sessionTicker := time.NewTicker(sessionCheckTick)
	defer func() {
		ticker.Stop()
		sessionTicker.Stop()
		client.Conn.Close()
	}()

	for {
		select {
		case message, ok := <-client.Send:
			client.Conn.SetWriteDeadline(time.Now().Add(writeWait))
			if !ok {
				client.Conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			w, err := client.Conn.NextWriter(websocket.TextMessage)
			if err != nil {
				return
			}
			w.Write(message)

			if err := w.Close(); err != nil {
				return
			}

		case <-ticker.C:
			client.Conn.SetWriteDeadline(time.Now().Add(writeWait))
			if err := client.Conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		case <-sessionTicker.C:
			if !h.validateClientSession(client) {
				return
			}
		}
	}
}

func (h *WSHandler) broadcastToRoom(roomID string, message []byte, senderID string) {
	clients := h.snapshotRoomClients(roomID, senderID)

	for _, client := range clients {
		select {
		case client.Send <- message:
		default:
		}
	}
}

func (h *WSHandler) broadcastMessageToRoom(roomID string, msg models.Message, senderID string) {
	message, err := json.Marshal(msg)
	if err != nil {
		slog.Warn("Failed to marshal websocket room message", "room_id", roomID, "type", msg.Type, "error", err)
		return
	}
	h.broadcastToRoom(roomID, message, senderID)
}

func (h *WSHandler) sendToUser(userID string, message []byte) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	for _, client := range h.Clients {
		if client.UserID == userID {
			select {
			case client.Send <- message:
			default:
			}
		}
	}
}

func (h *WSHandler) sendMessageToUser(userID string, msg models.Message) {
	message, err := json.Marshal(msg)
	if err != nil {
		slog.Warn("Failed to marshal websocket user message", "user_id", userID, "type", msg.Type, "error", err)
		return
	}
	h.sendToUser(userID, message)
}

func (h *WSHandler) sendMemberList(roomID string) {
	members, err := h.DB.GetRoomMembers(roomID)
	if err != nil {
		return
	}
	roomEpoch, err := h.DB.GetRoomEpoch(roomID)
	if err != nil {
		roomEpoch = 1
	}
	if roomEpoch < 1 {
		roomEpoch = 1
	}

	msg := models.Message{
		Type:       "members",
		RoomID:     roomID,
		Content:    mustMarshal(members),
		Generation: roomEpoch,
	}

	message, _ := json.Marshal(msg)

	clients := h.snapshotRoomClients(roomID, "")
	for _, client := range clients {
		select {
		case client.Send <- message:
		default:
		}
	}
}

func (h *WSHandler) DisconnectSession(sessionID string) {
	if sessionID == "" {
		return
	}

	clients := h.snapshotSessionClients(sessionID)
	for _, client := range clients {
		h.closeClient(client, websocket.ClosePolicyViolation, "session invalidated")
	}
}

func (h *WSHandler) validateClientSession(client *WSClient) bool {
	valid, err := h.DB.ValidateSession(client.SessionID, client.UserID)
	if err != nil || !valid {
		slog.Warn("Closing websocket with invalid session", "conn_id", client.ConnID, "user_id", client.UserID, "error", err)
		h.closeClient(client, websocket.ClosePolicyViolation, "session invalidated")
		return false
	}
	return true
}

func (h *WSHandler) closeClient(client *WSClient, code int, reason string) {
	if client == nil || client.Conn == nil {
		return
	}
	deadline := time.Now().Add(writeWait)
	_ = client.Conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(code, reason), deadline)
	_ = client.Conn.Close()
}

func (h *WSHandler) snapshotRoomClients(roomID, senderID string) []*WSClient {
	h.mu.RLock()
	defer h.mu.RUnlock()

	clients := make([]*WSClient, 0, len(h.Clients))
	for _, client := range h.Clients {
		if client.UserID == senderID {
			continue
		}
		if client.inRoom(roomID) {
			clients = append(clients, client)
		}
	}
	return clients
}

func (h *WSHandler) snapshotSessionClients(sessionID string) []*WSClient {
	h.mu.RLock()
	defer h.mu.RUnlock()

	clients := make([]*WSClient, 0, len(h.Clients))
	for _, client := range h.Clients {
		if client.SessionID == sessionID {
			clients = append(clients, client)
		}
	}
	return clients
}

func mustMarshal(v interface{}) json.RawMessage {
	data, err := json.Marshal(v)
	if err != nil {
		slog.Error("Failed to marshal JSON", "error", err)
		return []byte("null")
	}
	return data
}

func decodeBase64JSONString(raw json.RawMessage) ([]byte, bool) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, false
	}

	var encoded string
	if err := json.Unmarshal(raw, &encoded); err != nil {
		return nil, false
	}

	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		decoded, err = base64.RawStdEncoding.DecodeString(encoded)
		if err != nil {
			return nil, false
		}
	}
	return decoded, true
}

func validateEncryptedPayload(raw json.RawMessage) bool {
	var payload struct {
		IV         json.RawMessage `json:"iv"`
		Ciphertext json.RawMessage `json:"ciphertext"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return false
	}

	iv, ok := decodeBase64JSONString(payload.IV)
	if !ok || len(iv) == 0 {
		return false
	}

	ct, ok := decodeBase64JSONString(payload.Ciphertext)
	if !ok || len(ct) == 0 {
		return false
	}

	return true
}

type messagePayload struct {
	RoomID     string          `json:"room_id"`
	IV         json.RawMessage `json:"iv"`
	Ciphertext json.RawMessage `json:"ciphertext"`
	Timestamp  int64           `json:"timestamp"`
	Generation int             `json:"generation"`
	MessageNum int             `json:"message_num"`
}

type ratchetStateContent struct {
	UserID    string             `json:"user_id"`
	State     json.RawMessage    `json:"state"`
	Epoch     int                `json:"epoch"`
	Reason    string             `json:"reason"`
	Timestamp int64              `json:"timestamp"`
	Signature models.Base64Bytes `json:"signature"`
}

type ratchetStateSignaturePayload struct {
	RoomID    string          `json:"room_id"`
	UserID    string          `json:"user_id"`
	State     json.RawMessage `json:"state"`
	Epoch     int             `json:"epoch"`
	Reason    string          `json:"reason"`
	Timestamp int64           `json:"timestamp"`
}

func (h *WSHandler) getSigningKey(userID string) ([]byte, error) {
	h.keysMu.Lock()
	defer h.keysMu.Unlock()

	now := time.Now()
	if key, ok := h.signingKeys[userID]; ok && !key.LastUsedAt.IsZero() && now.Sub(key.LastUsedAt) <= signingKeyTTL {
		key.LastUsedAt = now
		h.signingKeys[userID] = key
		return key.Key, nil
	}

	// DB fetch while holding lock — acceptable because:
	// - SQLite reads are fast (indexed lookup)
	// - signing key lookups are infrequent (cached for 6h)
	user, err := h.DB.GetUserByID(userID)
	if err != nil {
		return nil, err
	}

	if now.Sub(h.lastKeyGC) >= replayCleanupTick {
		h.cleanupSigningKeysLocked(now)
		h.lastKeyGC = now
	}
	if len(h.signingKeys) >= signingKeyMax {
		h.evictOldestSigningKeyLocked()
	}
	h.signingKeys[userID] = cachedSigningKey{Key: user.SigningKey, LastUsedAt: now}
	return user.SigningKey, nil
}

func (h *WSHandler) parseMessagePayload(msg *models.Message) (*messagePayload, bool) {
	var content struct {
		IV         json.RawMessage `json:"iv"`
		Ciphertext json.RawMessage `json:"ciphertext"`
	}
	if err := json.Unmarshal(msg.Content, &content); err != nil {
		return nil, false
	}

	iv, ok := decodeBase64JSONString(content.IV)
	if !ok || len(iv) == 0 {
		return nil, false
	}

	ct, ok := decodeBase64JSONString(content.Ciphertext)
	if !ok || len(ct) == 0 {
		return nil, false
	}

	return &messagePayload{
		RoomID:     msg.RoomID,
		IV:         content.IV,
		Ciphertext: content.Ciphertext,
		Timestamp:  msg.Timestamp,
		Generation: msg.Generation,
		MessageNum: msg.MessageNum,
	}, true
}

func (h *WSHandler) validateMessageTimestamp(timestamp int64) bool {
	now := time.Now().UnixMilli()
	if timestamp <= 0 {
		return false
	}
	if now-timestamp > int64(maxMessageAge/time.Millisecond) {
		return false
	}
	if timestamp-now > int64(maxTimestampSkew/time.Millisecond) {
		return false
	}
	return true
}

func (h *WSHandler) validateMessageReplayState(userID, roomID string, payload *messagePayload) bool {
	now := time.Now()

	h.UserReplayMu.Lock()
	defer h.UserReplayMu.Unlock()

	if now.Sub(h.lastReplayGC) >= replayCleanupTick {
		h.cleanupReplayStateLocked(now)
		h.lastReplayGC = now
	}

	roomState, ok := h.ReplayState[userID]
	if !ok {
		roomState = make(map[string]messageReplayState)
		h.ReplayState[userID] = roomState
	}

	state, ok := roomState[roomID]
	if !ok {
		roomState[roomID] = messageReplayState{
			LastGeneration: payload.Generation,
			LastMessageNum: payload.MessageNum,
			LastTimestamp:  payload.Timestamp,
			LastSeenAt:     now,
		}
		return true
	}

	if payload.Generation < state.LastGeneration {
		return false
	}
	if payload.Generation == state.LastGeneration && payload.MessageNum <= state.LastMessageNum {
		return false
	}
	if payload.Timestamp < state.LastTimestamp {
		return false
	}

	state.LastGeneration = payload.Generation
	state.LastMessageNum = payload.MessageNum
	state.LastTimestamp = payload.Timestamp
	state.LastSeenAt = now
	roomState[roomID] = state
	return true
}

func (h *WSHandler) cleanupReplayStateLocked(now time.Time) {
	for userID, roomState := range h.ReplayState {
		for roomID, state := range roomState {
			if state.LastSeenAt.IsZero() || now.Sub(state.LastSeenAt) > replayStateTTL {
				delete(roomState, roomID)
			}
		}
		if len(roomState) == 0 {
			delete(h.ReplayState, userID)
		}
	}
}

func (h *WSHandler) cleanupSigningKeysLocked(now time.Time) {
	for userID, cached := range h.signingKeys {
		if cached.LastUsedAt.IsZero() || now.Sub(cached.LastUsedAt) > signingKeyTTL {
			delete(h.signingKeys, userID)
		}
	}
}

func (h *WSHandler) evictOldestSigningKeyLocked() {
	var oldestUserID string
	var oldestTime time.Time
	first := true

	for userID, cached := range h.signingKeys {
		if first || cached.LastUsedAt.Before(oldestTime) {
			oldestUserID = userID
			oldestTime = cached.LastUsedAt
			first = false
		}
	}

	if !first {
		delete(h.signingKeys, oldestUserID)
	}
}

func (h *WSHandler) InvalidateSigningKeyCache(userID string) {
	h.keysMu.Lock()
	delete(h.signingKeys, userID)
	h.keysMu.Unlock()
}

func (h *WSHandler) DisconnectUser(userID string) {
	h.mu.RLock()
	clients := make([]*WSClient, 0)
	for _, client := range h.Clients {
		if client.UserID == userID {
			clients = append(clients, client)
		}
	}
	h.mu.RUnlock()

	for _, client := range clients {
		h.closeClient(client, websocket.CloseNormalClosure, "account deleted")
	}
}

func (h *WSHandler) BroadcastToUserRooms(roomIDs []string, msg models.Message) {
	message, err := json.Marshal(msg)
	if err != nil {
		slog.Warn("Failed to marshal broadcast message", "type", msg.Type, "error", err)
		return
	}
	for _, roomID := range roomIDs {
		h.broadcastToRoom(roomID, message, "")
	}
}

func (h *WSHandler) CleanupUserReplayState(userID string) {
	h.UserReplayMu.Lock()
	delete(h.ReplayState, userID)
	h.UserReplayMu.Unlock()
}

func (h *WSHandler) verifyRatchetStateSignature(userID, roomID string, content *ratchetStateContent) bool {
	if content == nil {
		return false
	}
	if content.UserID == "" || len(content.State) == 0 || content.Epoch <= 0 || content.Timestamp <= 0 || len(content.Signature) == 0 {
		return false
	}

	signingKey, err := h.getSigningKey(userID)
	if err != nil {
		return false
	}

	payloadBytes, err := json.Marshal(ratchetStateSignaturePayload{
		RoomID:    roomID,
		UserID:    content.UserID,
		State:     content.State,
		Epoch:     content.Epoch,
		Reason:    content.Reason,
		Timestamp: content.Timestamp,
	})
	if err != nil {
		return false
	}

	return verifySignatureRaw(signingKey, payloadBytes, []byte(content.Signature))
}

func (h *WSHandler) verifyMessageSignature(userID string, msg *models.Message, payload *messagePayload) bool {
	if len(msg.Signature) == 0 {
		return false
	}

	signingKey, err := h.getSigningKey(userID)
	if err != nil {
		return false
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return false
	}

	return verifySignatureRaw(signingKey, payloadBytes, []byte(msg.Signature))
}

func verifySignatureRaw(publicKeySPKI, message, signature []byte) bool {
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
