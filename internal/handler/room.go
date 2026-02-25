package handler

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"secuchat/internal/db"
)

type RoomHandler struct {
	DB *db.Database
}

type CreateRoomRequest struct {
	Name      string `json:"name"`
	IsPrivate bool   `json:"is_private"`
}

type JoinRoomRequest struct {
	InviteCode string `json:"invite_code"`
}

func generateInviteCode() string {
	return uuid.New().String()
}

func sanitizeName(name string) string {
	name = strings.TrimSpace(name)
	var b strings.Builder
	b.Grow(len(name))
	for _, r := range name {
		if r < 32 || r == 0x7F { // control characters
			continue
		}
		if r == '<' || r == '>' || r == '&' || r == '"' || r == '\'' {
			continue // HTML-sensitive chars
		}
		b.WriteRune(r)
	}
	return b.String()
}

func (h *RoomHandler) ListRooms(w http.ResponseWriter, r *http.Request) {
	_, userID, _ := getSessionFromCookie(r)
	if userID == "" {
		writeJSONError(w, "Not authenticated", "UNAUTHORIZED", http.StatusUnauthorized)
		return
	}

	limit := 50
	offset := 0
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			limit = n
		}
	}
	if v := r.URL.Query().Get("offset"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			offset = n
		}
	}

	rooms, err := h.DB.ListPublicRooms(limit, offset)
	if err != nil {
		writeJSONError(w, "Failed to list rooms", "INTERNAL_ERROR", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(rooms)
}

func (h *RoomHandler) CreateRoom(w http.ResponseWriter, r *http.Request) {
	_, userID, _ := getSessionFromCookie(r)
	if userID == "" {
		writeJSONError(w, "Not authenticated", "UNAUTHORIZED", http.StatusUnauthorized)
		return
	}

	count, err := h.DB.CountUserRooms(userID)
	if err != nil {
		writeJSONError(w, "Failed to verify room limit", "INTERNAL_ERROR", http.StatusInternalServerError)
		return
	}
	if count >= MaxRoomsPerUser {
		writeJSONError(w, "Maximum room limit reached (256 rooms)", "ROOM_LIMIT_EXCEEDED", http.StatusForbidden)
		return
	}

	var req CreateRoomRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, "Invalid request body", "INVALID_REQUEST", http.StatusBadRequest)
		return
	}

	name := sanitizeName(req.Name)
	if name == "" {
		writeJSONError(w, "Room name is required", "INVALID_ROOM_NAME", http.StatusBadRequest)
		return
	}
	if len(name) > 64 {
		writeJSONError(w, "Room name must be 64 characters or less", "INVALID_ROOM_NAME", http.StatusBadRequest)
		return
	}

	roomID := uuid.New().String()
	var inviteCode string
	if req.IsPrivate {
		inviteCode = generateInviteCode()
	}

	if err := h.DB.CreateRoomWithCreator(roomID, name, req.IsPrivate, inviteCode, userID); err != nil {
		writeJSONError(w, "Failed to create room", "INTERNAL_ERROR", http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"id":            roomID,
		"name":          name,
		"is_private":    req.IsPrivate,
		"current_epoch": 1,
	}
	if inviteCode != "" {
		response["invite_code"] = inviteCode
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (h *RoomHandler) GetRoom(w http.ResponseWriter, r *http.Request) {
	_, userID, _ := getSessionFromCookie(r)
	if userID == "" {
		writeJSONError(w, "Not authenticated", "UNAUTHORIZED", http.StatusUnauthorized)
		return
	}

	roomID := r.PathValue("id")
	if roomID == "" {
		writeJSONError(w, "Room ID required", "INVALID_REQUEST", http.StatusBadRequest)
		return
	}

	room, err := h.DB.GetRoomByID(roomID)
	if err != nil {
		writeJSONError(w, "Room not found", "ROOM_NOT_FOUND", http.StatusNotFound)
		return
	}

	isMember, err := h.DB.IsRoomMember(roomID, userID)
	if err != nil {
		writeJSONError(w, "Failed to verify room membership", "INTERNAL_ERROR", http.StatusInternalServerError)
		return
	}
	if !isMember {
		writeJSONError(w, "Not authorized to access room", "FORBIDDEN", http.StatusForbidden)
		return
	}

	members, err := h.DB.GetRoomMembers(roomID)
	if err != nil {
		writeJSONError(w, "Failed to get members", "INTERNAL_ERROR", http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"id":            room.ID,
		"name":          room.Name,
		"is_private":    room.IsPrivate,
		"created_by":    room.CreatedBy,
		"created_at":    room.CreatedAt,
		"current_epoch": room.CurrentEpoch,
		"members":       members,
	}

	if room.CreatedBy == userID {
		response["invite_code"] = room.InviteCode
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (h *RoomHandler) JoinRoom(w http.ResponseWriter, r *http.Request) {
	_, userID, _ := getSessionFromCookie(r)
	if userID == "" {
		writeJSONError(w, "Not authenticated", "UNAUTHORIZED", http.StatusUnauthorized)
		return
	}

	roomID := r.PathValue("id")
	if roomID == "" {
		writeJSONError(w, "Room ID required", "INVALID_REQUEST", http.StatusBadRequest)
		return
	}

	room, err := h.DB.GetRoomByID(roomID)
	if err != nil {
		writeJSONError(w, "Room not found", "ROOM_NOT_FOUND", http.StatusNotFound)
		return
	}

	if room.IsPrivate {
		var req JoinRoomRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONError(w, "Invalid request body", "INVALID_REQUEST", http.StatusBadRequest)
			return
		}

		if req.InviteCode == "" || subtle.ConstantTimeCompare([]byte(req.InviteCode), []byte(room.InviteCode)) != 1 {
			writeJSONError(w, "Invalid or missing invite code", "INVALID_INVITE_CODE", http.StatusForbidden)
			return
		}
	}

	isMember, err := h.DB.IsRoomMember(roomID, userID)
	if err != nil {
		writeJSONError(w, "Failed to check membership", "INTERNAL_ERROR", http.StatusInternalServerError)
		return
	}

	if !isMember {
		memberCount, err := h.DB.CountRoomMembers(roomID)
		if err != nil {
			writeJSONError(w, "Failed to check member count", "INTERNAL_ERROR", http.StatusInternalServerError)
			return
		}
		if memberCount >= MaxMembersPerRoom {
			writeJSONError(w, "Room is full", "ROOM_FULL", http.StatusForbidden)
			return
		}
		if err := h.DB.AddRoomMember(roomID, userID); err != nil {
			writeJSONError(w, "Failed to join room", "INTERNAL_ERROR", http.StatusInternalServerError)
			return
		}
	}

	members, err := h.DB.GetRoomMembers(roomID)
	if err != nil {
		writeJSONError(w, "Failed to get room members", "INTERNAL_ERROR", http.StatusInternalServerError)
		return
	}
	currentEpoch, err := h.DB.GetRoomEpoch(roomID)
	if err != nil {
		writeJSONError(w, "Failed to read room epoch", "INTERNAL_ERROR", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"room_id":       roomID,
		"members":       members,
		"current_epoch": currentEpoch,
	})
}

func (h *RoomHandler) JoinRoomByCode(w http.ResponseWriter, r *http.Request) {
	_, userID, _ := getSessionFromCookie(r)
	if userID == "" {
		writeJSONError(w, "Not authenticated", "UNAUTHORIZED", http.StatusUnauthorized)
		return
	}

	var req JoinRoomRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, "Invalid request body", "INVALID_REQUEST", http.StatusBadRequest)
		return
	}

	if req.InviteCode == "" {
		writeJSONError(w, "Invite code required", "INVALID_REQUEST", http.StatusBadRequest)
		return
	}

	room, err := h.DB.GetRoomByInviteCode(req.InviteCode)
	if err != nil {
		writeJSONError(w, "Invalid invite code", "INVALID_INVITE_CODE", http.StatusNotFound)
		return
	}

	isMember, err := h.DB.IsRoomMember(room.ID, userID)
	if err != nil {
		writeJSONError(w, "Failed to check membership", "INTERNAL_ERROR", http.StatusInternalServerError)
		return
	}

	if !isMember {
		memberCount, err := h.DB.CountRoomMembers(room.ID)
		if err != nil {
			writeJSONError(w, "Failed to check member count", "INTERNAL_ERROR", http.StatusInternalServerError)
			return
		}
		if memberCount >= MaxMembersPerRoom {
			writeJSONError(w, "Room is full", "ROOM_FULL", http.StatusForbidden)
			return
		}
		if err := h.DB.AddRoomMember(room.ID, userID); err != nil {
			writeJSONError(w, "Failed to join room", "INTERNAL_ERROR", http.StatusInternalServerError)
			return
		}
	}

	members, err := h.DB.GetRoomMembers(room.ID)
	if err != nil {
		writeJSONError(w, "Failed to get room members", "INTERNAL_ERROR", http.StatusInternalServerError)
		return
	}
	currentEpoch, err := h.DB.GetRoomEpoch(room.ID)
	if err != nil {
		writeJSONError(w, "Failed to read room epoch", "INTERNAL_ERROR", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"room_id":       room.ID,
		"name":          room.Name,
		"members":       members,
		"current_epoch": currentEpoch,
	})
}

func (h *RoomHandler) LeaveRoom(w http.ResponseWriter, r *http.Request) {
	_, userID, _ := getSessionFromCookie(r)
	if userID == "" {
		writeJSONError(w, "Not authenticated", "UNAUTHORIZED", http.StatusUnauthorized)
		return
	}

	roomID := r.PathValue("id")
	if roomID == "" {
		writeJSONError(w, "Room ID required", "INVALID_REQUEST", http.StatusBadRequest)
		return
	}

	if err := h.DB.RemoveRoomMember(roomID, userID); err != nil {
		writeJSONError(w, "Failed to leave room", "INTERNAL_ERROR", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "left"})
}

func (h *RoomHandler) GetRoomMembers(w http.ResponseWriter, r *http.Request) {
	_, userID, _ := getSessionFromCookie(r)
	if userID == "" {
		writeJSONError(w, "Not authenticated", "UNAUTHORIZED", http.StatusUnauthorized)
		return
	}

	roomID := r.PathValue("id")
	if roomID == "" {
		writeJSONError(w, "Room ID required", "INVALID_REQUEST", http.StatusBadRequest)
		return
	}

	if _, err := h.DB.GetRoomByID(roomID); err != nil {
		writeJSONError(w, "Room not found", "ROOM_NOT_FOUND", http.StatusNotFound)
		return
	}

	isMember, err := h.DB.IsRoomMember(roomID, userID)
	if err != nil {
		writeJSONError(w, "Failed to verify room membership", "INTERNAL_ERROR", http.StatusInternalServerError)
		return
	}
	if !isMember {
		writeJSONError(w, "Not authorized to access room members", "FORBIDDEN", http.StatusForbidden)
		return
	}

	members, err := h.DB.GetRoomMembers(roomID)
	if err != nil {
		writeJSONError(w, "Failed to get members", "INTERNAL_ERROR", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(members)
}

func (h *RoomHandler) RegenerateInviteCode(w http.ResponseWriter, r *http.Request) {
	_, userID, _ := getSessionFromCookie(r)
	if userID == "" {
		writeJSONError(w, "Not authenticated", "UNAUTHORIZED", http.StatusUnauthorized)
		return
	}

	roomID := r.PathValue("id")
	if roomID == "" {
		writeJSONError(w, "Room ID required", "INVALID_REQUEST", http.StatusBadRequest)
		return
	}

	room, err := h.DB.GetRoomByID(roomID)
	if err != nil {
		writeJSONError(w, "Room not found", "ROOM_NOT_FOUND", http.StatusNotFound)
		return
	}

	if room.CreatedBy != userID {
		writeJSONError(w, "Only room creator can regenerate invite code", "FORBIDDEN", http.StatusForbidden)
		return
	}

	newCode := generateInviteCode()
	if err := h.DB.RegenerateInviteCode(roomID, newCode); err != nil {
		writeJSONError(w, "Failed to regenerate invite code", "INTERNAL_ERROR", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"invite_code": newCode,
	})
}
