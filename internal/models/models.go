package models

import (
	"encoding/json"
	"time"
)

type User struct {
	ID           string    `json:"id"`
	Username     string    `json:"username"`
	PasswordHash string    `json:"-"`
	PublicKey    []byte    `json:"public_key"`
	SigningKey   []byte    `json:"signing_key"`
	CreatedAt    time.Time `json:"created_at"`
}

type Room struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	IsPrivate    bool      `json:"is_private"`
	InviteCode   string    `json:"invite_code,omitempty"`
	CreatedBy    string    `json:"created_by"`
	CreatedAt    time.Time `json:"created_at"`
	CurrentEpoch int       `json:"current_epoch"`
}

type RoomMember struct {
	RoomID   string    `json:"room_id"`
	UserID   string    `json:"user_id"`
	JoinedAt time.Time `json:"joined_at"`
}

type Message struct {
	Type       string          `json:"type"`
	RoomID     string          `json:"room_id"`
	SenderID   string          `json:"sender_id"`
	Sender     string          `json:"sender,omitempty"`
	Content    json.RawMessage `json:"content"`
	Signature  Base64Bytes     `json:"signature,omitempty"`
	Timestamp  int64           `json:"timestamp"`
	Generation int             `json:"generation,omitempty"`
	MessageNum int             `json:"message_num,omitempty"`
}

type EncryptedRoomKey struct {
	UserID string `json:"user_id"`
	Key    []byte `json:"key"`
}

type Challenge struct {
	Nonce     string `json:"nonce"`
	ExpiresAt int64  `json:"expires_at"`
}

type ErrorResponse struct {
	Error string `json:"error"`
	Code  string `json:"code,omitempty"`
}
