package db

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"secuchat/internal/models"

	_ "modernc.org/sqlite"
)

var ErrUserExists = errors.New("user already exists")

const currentSchemaVersion = 2

type Database struct {
	*sql.DB
}

func New(dataSourceName string) (*Database, error) {
	db, err := sql.Open("sqlite", dataSourceName)
	if err != nil {
		return nil, err
	}

	db.SetMaxOpenConns(4) // SQLite is single-writer; more connections waste FDs and increase lock contention
	db.SetMaxIdleConns(2)
	db.SetConnMaxLifetime(5 * time.Minute)
	db.SetConnMaxIdleTime(2 * time.Minute)

	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		return nil, err
	}
	if _, err := db.Exec("PRAGMA busy_timeout=5000"); err != nil {
		return nil, err
	}
	if _, err := db.Exec("PRAGMA foreign_keys=ON"); err != nil {
		return nil, err
	}

	if err := db.Ping(); err != nil {
		return nil, err
	}

	if err := runMigrations(db); err != nil {
		return nil, err
	}

	return &Database{db}, nil
}

func runMigrations(db *sql.DB) error {
	var version int
	if err := db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		return err
	}
	if version > currentSchemaVersion {
		return fmt.Errorf("database schema version %d is newer than supported version %d", version, currentSchemaVersion)
	}

	if version < 1 {
		tx, err := db.Begin()
		if err != nil {
			return err
		}
		defer tx.Rollback()
		if err := createTablesInTx(tx); err != nil {
			return err
		}
		if _, err := tx.Exec("PRAGMA user_version = 1"); err != nil {
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
		version = 1
	}

	if version < 2 {
		tx, err := db.Begin()
		if err != nil {
			return err
		}
		defer tx.Rollback()
		if err := migrateToV2InTx(tx); err != nil {
			return err
		}
		if _, err := tx.Exec("PRAGMA user_version = 2"); err != nil {
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
		version = 2
	}

	return nil
}

func migrateToV2InTx(tx *sql.Tx) error {
	if _, err := tx.Exec("ALTER TABLE rooms ADD COLUMN current_epoch INTEGER NOT NULL DEFAULT 1"); err != nil {
		// Ignore duplicate-column errors for idempotency on partially migrated databases.
		if !strings.Contains(strings.ToLower(err.Error()), "duplicate column name") {
			return err
		}
	}
	_, err := tx.Exec("UPDATE rooms SET current_epoch = 1 WHERE current_epoch IS NULL OR current_epoch < 1")
	return err
}

func createTablesInTx(tx *sql.Tx) error {
	_, err := tx.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id TEXT PRIMARY KEY,
			username TEXT UNIQUE NOT NULL,
			password_hash TEXT NOT NULL DEFAULT '',
			public_key BLOB NOT NULL,
			signing_key BLOB NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);

		CREATE TABLE IF NOT EXISTS sessions (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			expires_at DATETIME NOT NULL
		);

		CREATE TABLE IF NOT EXISTS rooms (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			is_private INTEGER DEFAULT 0,
			invite_code TEXT UNIQUE,
			created_by TEXT REFERENCES users(id),
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			last_activity_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			current_epoch INTEGER NOT NULL DEFAULT 1
		);

		CREATE TABLE IF NOT EXISTS room_members (
			room_id TEXT REFERENCES rooms(id) ON DELETE CASCADE,
			user_id TEXT REFERENCES users(id) ON DELETE CASCADE,
			joined_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (room_id, user_id)
		);

		CREATE TABLE IF NOT EXISTS challenges (
			nonce TEXT PRIMARY KEY,
			user_id TEXT NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);

		CREATE TABLE IF NOT EXISTS csrf_tokens (
			token TEXT PRIMARY KEY,
			session_id TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);

		CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
		CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);
		CREATE INDEX IF NOT EXISTS idx_rooms_invite_code ON rooms(invite_code);
		CREATE INDEX IF NOT EXISTS idx_rooms_created_by ON rooms(created_by);
		CREATE INDEX IF NOT EXISTS idx_rooms_last_activity ON rooms(last_activity_at);
		CREATE INDEX IF NOT EXISTS idx_challenges_created_at ON challenges(created_at);
		CREATE INDEX IF NOT EXISTS idx_csrf_created_at ON csrf_tokens(created_at);
		CREATE INDEX IF NOT EXISTS idx_csrf_session_id ON csrf_tokens(session_id);
	`)
	return err
}

func (db *Database) CreateUser(id, username, passwordHash string, publicKey, signingKey []byte) error {
	_, err := db.Exec(
		"INSERT INTO users (id, username, password_hash, public_key, signing_key, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		id, username, passwordHash, publicKey, signingKey, time.Now(),
	)
	return err
}

func (db *Database) CreateUserIfNotExists(id, username, passwordHash string, publicKey, signingKey []byte) error {
	result, err := db.Exec(
		"INSERT OR IGNORE INTO users (id, username, password_hash, public_key, signing_key, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		id, username, passwordHash, publicKey, signingKey, time.Now(),
	)
	if err != nil {
		return err
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rowsAffected == 0 {
		return ErrUserExists
	}
	return nil
}

func (db *Database) GetUserByUsername(username string) (*models.User, error) {
	user := &models.User{}
	err := db.QueryRow(
		"SELECT id, username, password_hash, public_key, signing_key, created_at FROM users WHERE username = ?",
		username,
	).Scan(&user.ID, &user.Username, &user.PasswordHash, &user.PublicKey, &user.SigningKey, &user.CreatedAt)
	if err != nil {
		return nil, err
	}
	return user, nil
}

func (db *Database) GetUserByID(id string) (*models.User, error) {
	user := &models.User{}
	err := db.QueryRow(
		"SELECT id, username, password_hash, public_key, signing_key, created_at FROM users WHERE id = ?",
		id,
	).Scan(&user.ID, &user.Username, &user.PasswordHash, &user.PublicKey, &user.SigningKey, &user.CreatedAt)
	if err != nil {
		return nil, err
	}
	return user, nil
}

func (db *Database) CreateRoom(id, name string, isPrivate bool, inviteCode, createdBy string) error {
	_, err := db.Exec(
		"INSERT INTO rooms (id, name, is_private, invite_code, created_by, created_at, current_epoch) VALUES (?, ?, ?, ?, ?, ?, ?)",
		id, name, isPrivate, inviteCode, createdBy, time.Now(), 1,
	)
	return err
}

func (db *Database) CreateRoomWithCreator(id, name string, isPrivate bool, inviteCode, createdBy string) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	now := time.Now()
	if _, err := tx.Exec(
		"INSERT INTO rooms (id, name, is_private, invite_code, created_by, created_at, current_epoch) VALUES (?, ?, ?, ?, ?, ?, ?)",
		id, name, isPrivate, inviteCode, createdBy, now, 1,
	); err != nil {
		return err
	}

	if _, err := tx.Exec(
		"INSERT INTO room_members (room_id, user_id, joined_at) VALUES (?, ?, ?)",
		id, createdBy, now,
	); err != nil {
		return err
	}

	return tx.Commit()
}

func (db *Database) GetRoomByID(id string) (*models.Room, error) {
	room := &models.Room{}
	var isPrivate int
	err := db.QueryRow(
		"SELECT id, name, is_private, invite_code, created_by, created_at, current_epoch FROM rooms WHERE id = ?",
		id,
	).Scan(&room.ID, &room.Name, &isPrivate, &room.InviteCode, &room.CreatedBy, &room.CreatedAt, &room.CurrentEpoch)
	if err != nil {
		return nil, err
	}
	room.IsPrivate = isPrivate == 1
	return room, nil
}

func (db *Database) GetRoomByInviteCode(code string) (*models.Room, error) {
	room := &models.Room{}
	var isPrivate int
	err := db.QueryRow(
		"SELECT id, name, is_private, invite_code, created_by, created_at, current_epoch FROM rooms WHERE invite_code = ?",
		code,
	).Scan(&room.ID, &room.Name, &isPrivate, &room.InviteCode, &room.CreatedBy, &room.CreatedAt, &room.CurrentEpoch)
	if err != nil {
		return nil, err
	}
	room.IsPrivate = isPrivate == 1
	return room, nil
}

func (db *Database) ListRooms() ([]models.Room, error) {
	rows, err := db.Query("SELECT id, name, is_private, invite_code, created_by, created_at, current_epoch FROM rooms ORDER BY created_at DESC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rooms []models.Room
	for rows.Next() {
		var room models.Room
		var isPrivate int
		var inviteCode sql.NullString
		if err := rows.Scan(&room.ID, &room.Name, &isPrivate, &inviteCode, &room.CreatedBy, &room.CreatedAt, &room.CurrentEpoch); err != nil {
			return nil, err
		}
		room.IsPrivate = isPrivate == 1
		if inviteCode.Valid {
			room.InviteCode = inviteCode.String
		}
		rooms = append(rooms, room)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return rooms, nil
}

func (db *Database) ListPublicRooms(limit, offset int) ([]models.Room, error) {
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}
	rows, err := db.Query(
		"SELECT id, name, is_private, invite_code, created_by, created_at, current_epoch FROM rooms WHERE is_private = 0 ORDER BY created_at DESC LIMIT ? OFFSET ?",
		limit, offset,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rooms []models.Room
	for rows.Next() {
		var room models.Room
		var isPrivate int
		var inviteCode sql.NullString
		if err := rows.Scan(&room.ID, &room.Name, &isPrivate, &inviteCode, &room.CreatedBy, &room.CreatedAt, &room.CurrentEpoch); err != nil {
			return nil, err
		}
		room.IsPrivate = isPrivate == 1
		rooms = append(rooms, room)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return rooms, nil
}

func (db *Database) CountUserRooms(userID string) (int, error) {
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM rooms WHERE created_by = ?", userID).Scan(&count)
	return count, err
}

func (db *Database) RegenerateInviteCode(roomID, newCode string) error {
	_, err := db.Exec("UPDATE rooms SET invite_code = ? WHERE id = ?", newCode, roomID)
	return err
}

func bumpRoomEpochTx(tx *sql.Tx, roomID string) error {
	if tx == nil || roomID == "" {
		return nil
	}
	_, err := tx.Exec(
		"UPDATE rooms SET current_epoch = CASE WHEN current_epoch IS NULL OR current_epoch < 1 THEN 2 ELSE current_epoch + 1 END WHERE id = ?",
		roomID,
	)
	return err
}

func (db *Database) AddRoomMember(roomID, userID string) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	result, err := tx.Exec(
		"INSERT OR IGNORE INTO room_members (room_id, user_id, joined_at) VALUES (?, ?, ?)",
		roomID, userID, time.Now(),
	)
	if err != nil {
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rowsAffected > 0 {
		if err := bumpRoomEpochTx(tx, roomID); err != nil {
			return err
		}
	}

	return tx.Commit()
}

func (db *Database) RemoveRoomMember(roomID, userID string) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	result, err := tx.Exec(
		"DELETE FROM room_members WHERE room_id = ? AND user_id = ?",
		roomID, userID,
	)
	if err != nil {
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rowsAffected > 0 {
		if err := bumpRoomEpochTx(tx, roomID); err != nil {
			return err
		}
	}

	return tx.Commit()
}

func (db *Database) GetRoomMembers(roomID string) ([]models.User, error) {
	rows, err := db.Query(`
		SELECT u.id, u.username, u.public_key, u.signing_key, u.created_at
		FROM users u
		JOIN room_members rm ON u.id = rm.user_id
		WHERE rm.room_id = ?`,
		roomID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []models.User
	for rows.Next() {
		var user models.User
		if err := rows.Scan(&user.ID, &user.Username, &user.PublicKey, &user.SigningKey, &user.CreatedAt); err != nil {
			return nil, err
		}
		users = append(users, user)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return users, nil
}

func (db *Database) CountRoomMembers(roomID string) (int, error) {
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM room_members WHERE room_id = ?", roomID).Scan(&count)
	return count, err
}

func (db *Database) IsRoomMember(roomID, userID string) (bool, error) {
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM room_members WHERE room_id = ? AND user_id = ?", roomID, userID).Scan(&count)
	return count > 0, err
}

func (db *Database) GetRoomEpoch(roomID string) (int, error) {
	var epoch int
	err := db.QueryRow("SELECT current_epoch FROM rooms WHERE id = ?", roomID).Scan(&epoch)
	if err != nil {
		return 0, err
	}
	if epoch < 1 {
		epoch = 1
	}
	return epoch, nil
}

func (db *Database) DeleteRoom(roomID string) error {
	_, err := db.Exec("DELETE FROM rooms WHERE id = ?", roomID)
	return err
}

func (db *Database) CreateChallenge(nonce, userID string) error {
	_, err := db.Exec(
		"INSERT INTO challenges (nonce, user_id, created_at) VALUES (?, ?, ?)",
		nonce, userID, time.Now(),
	)
	return err
}

func (db *Database) CountUserChallenges(userID string) (int, error) {
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM challenges WHERE user_id = ?", userID).Scan(&count)
	return count, err
}

func (db *Database) GetAndDeleteChallenge(nonce string) (userID string, createdAt time.Time, err error) {
	tx, err := db.Begin()
	if err != nil {
		return "", time.Time{}, err
	}
	defer tx.Rollback()

	err = tx.QueryRow("SELECT user_id, created_at FROM challenges WHERE nonce = ?", nonce).Scan(&userID, &createdAt)
	if err != nil {
		return "", time.Time{}, err
	}

	_, err = tx.Exec("DELETE FROM challenges WHERE nonce = ?", nonce)
	if err != nil {
		return "", time.Time{}, err
	}

	return userID, createdAt, tx.Commit()
}

func (db *Database) CleanupChallenges(olderThan time.Duration) (int64, error) {
	result, err := db.Exec("DELETE FROM challenges WHERE created_at < ?", time.Now().Add(-olderThan))
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

func (db *Database) CreateCSRFToken(token string) error {
	_, err := db.Exec(
		"INSERT INTO csrf_tokens (token, created_at) VALUES (?, ?)",
		token, time.Now(),
	)
	return err
}

func (db *Database) CreateCSRFTokenWithSession(token, sessionID string) error {
	_, err := db.Exec(
		"INSERT INTO csrf_tokens (token, session_id, created_at) VALUES (?, ?, ?)",
		token, sessionID, time.Now(),
	)
	return err
}

func (db *Database) ValidateAndDeleteCSRFToken(token string) (bool, error) {
	tx, err := db.Begin()
	if err != nil {
		return false, err
	}
	defer tx.Rollback()

	var exists int
	err = tx.QueryRow("SELECT 1 FROM csrf_tokens WHERE token = ?", token).Scan(&exists)
	if err == sql.ErrNoRows {
		return false, tx.Commit()
	}
	if err != nil {
		return false, err
	}

	_, err = tx.Exec("DELETE FROM csrf_tokens WHERE token = ?", token)
	if err != nil {
		return false, err
	}

	return true, tx.Commit()
}

func (db *Database) ValidateAndDeleteCSRFTokenWithSession(token, sessionID string) (bool, error) {
	tx, err := db.Begin()
	if err != nil {
		return false, err
	}
	defer tx.Rollback()

	var storedSessionID sql.NullString
	err = tx.QueryRow("SELECT session_id FROM csrf_tokens WHERE token = ?", token).Scan(&storedSessionID)
	if err == sql.ErrNoRows {
		return false, tx.Commit()
	}
	if err != nil {
		return false, err
	}

	if storedSessionID.Valid && storedSessionID.String != sessionID {
		return false, tx.Commit()
	}

	_, err = tx.Exec("DELETE FROM csrf_tokens WHERE token = ?", token)
	if err != nil {
		return false, err
	}

	return true, tx.Commit()
}

func (db *Database) DeleteSessionCSRFTokens(sessionID string) error {
	_, err := db.Exec("DELETE FROM csrf_tokens WHERE session_id = ?", sessionID)
	return err
}

func (db *Database) CleanupCSRFTokens(olderThan time.Duration) (int64, error) {
	result, err := db.Exec("DELETE FROM csrf_tokens WHERE created_at < ?", time.Now().Add(-olderThan))
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

func (db *Database) GetUserSessionValidation(userID string) (username string, err error) {
	err = db.QueryRow("SELECT username FROM users WHERE id = ?", userID).Scan(&username)
	return username, err
}

const MaxSessionsPerUser = 10

func (db *Database) CreateSession(sessionID, userID string, expiresAt time.Time) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.Exec(
		"INSERT INTO sessions (id, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
		sessionID, userID, time.Now(), expiresAt,
	); err != nil {
		return err
	}

	// Evict oldest sessions beyond the cap
	if _, err := tx.Exec(`
		DELETE FROM sessions WHERE id IN (
			SELECT id FROM sessions
			WHERE user_id = ?
			ORDER BY created_at DESC
			LIMIT -1 OFFSET ?
		)`, userID, MaxSessionsPerUser,
	); err != nil {
		return err
	}

	return tx.Commit()
}

func (db *Database) ValidateSession(sessionID, userID string) (bool, error) {
	var storedUserID string
	var expiresAt time.Time
	err := db.QueryRow(
		"SELECT user_id, expires_at FROM sessions WHERE id = ?",
		sessionID,
	).Scan(&storedUserID, &expiresAt)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if storedUserID != userID {
		return false, nil
	}
	if time.Now().After(expiresAt) {
		return false, nil
	}
	return true, nil
}

func (db *Database) DeleteSession(sessionID string) error {
	_, err := db.Exec("DELETE FROM sessions WHERE id = ?", sessionID)
	return err
}

func (db *Database) DeleteUserSessions(userID string) error {
	_, err := db.Exec("DELETE FROM sessions WHERE user_id = ?", userID)
	return err
}

func (db *Database) CleanupExpiredSessions() (int64, error) {
	result, err := db.Exec("DELETE FROM sessions WHERE expires_at < ?", time.Now())
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

func (db *Database) TouchRoomActivity(roomID string) error {
	_, err := db.Exec(
		"UPDATE rooms SET last_activity_at = ? WHERE id = ?",
		time.Now(), roomID,
	)
	return err
}

func (db *Database) CleanupInactiveRooms(olderThan time.Duration) (int64, error) {
	result, err := db.Exec(
		"DELETE FROM rooms WHERE last_activity_at < ?",
		time.Now().Add(-olderThan),
	)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

func (db *Database) GetSessionUserID(sessionID string) (string, error) {
	var userID string
	err := db.QueryRow(
		"SELECT user_id FROM sessions WHERE id = ? AND expires_at > ?",
		sessionID, time.Now(),
	).Scan(&userID)
	if err != nil {
		return "", err
	}
	return userID, nil
}

func (db *Database) GetUserRoomIDs(userID string) ([]string, error) {
	rows, err := db.Query("SELECT room_id FROM room_members WHERE user_id = ?", userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var roomIDs []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		roomIDs = append(roomIDs, id)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return roomIDs, nil
}

func (db *Database) GetRoomsCreatedByUser(userID string) ([]string, error) {
	rows, err := db.Query("SELECT id FROM rooms WHERE created_by = ?", userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var roomIDs []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		roomIDs = append(roomIDs, id)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return roomIDs, nil
}

func (db *Database) DeleteUser(userID string) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Membership removals in surviving rooms require an epoch bump for revocation.
	rows, err := tx.Query(`
		SELECT DISTINCT rm.room_id
		FROM room_members rm
		JOIN rooms r ON r.id = rm.room_id
		WHERE rm.user_id = ? AND r.created_by <> ?`,
		userID, userID,
	)
	if err != nil {
		return err
	}
	affectedRoomIDs := make([]string, 0)
	for rows.Next() {
		var roomID string
		if err := rows.Scan(&roomID); err != nil {
			rows.Close()
			return err
		}
		affectedRoomIDs = append(affectedRoomIDs, roomID)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()

	// Delete rooms created by user (cascades their room_members)
	if _, err := tx.Exec("DELETE FROM rooms WHERE created_by = ?", userID); err != nil {
		return err
	}
	// Delete challenges for user
	if _, err := tx.Exec("DELETE FROM challenges WHERE user_id = ?", userID); err != nil {
		return err
	}
	// Delete CSRF tokens for user's sessions
	if _, err := tx.Exec("DELETE FROM csrf_tokens WHERE session_id IN (SELECT id FROM sessions WHERE user_id = ?)", userID); err != nil {
		return err
	}
	// Delete sessions for user
	if _, err := tx.Exec("DELETE FROM sessions WHERE user_id = ?", userID); err != nil {
		return err
	}
	// Delete remaining room_members for user
	if _, err := tx.Exec("DELETE FROM room_members WHERE user_id = ?", userID); err != nil {
		return err
	}
	for _, roomID := range affectedRoomIDs {
		if err := bumpRoomEpochTx(tx, roomID); err != nil {
			return err
		}
	}
	// Delete user record
	if _, err := tx.Exec("DELETE FROM users WHERE id = ?", userID); err != nil {
		return err
	}

	return tx.Commit()
}

func (db *Database) UpdateUserKeys(userID string, publicKey, signingKey []byte) error {
	_, err := db.Exec("UPDATE users SET public_key = ?, signing_key = ? WHERE id = ?", publicKey, signingKey, userID)
	return err
}
