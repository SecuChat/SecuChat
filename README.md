# SecuChat

A secure, end-to-end encrypted group chat application designed for privacy-conscious users. Messages are encrypted client-side using modern cryptographic primitives with Signal-style ratcheting for perfect forward secrecy.

Author: **Mounir IDRASSI**

## Table of Contents

- [Overview](#overview)
- [Security Model](#security-model)
- [Architecture](#architecture)
- [API Reference](#api-reference)
- [WebSocket Protocol](#websocket-protocol)
- [Cryptographic Implementation](#cryptographic-implementation)
- [Deployment](#deployment)
- [Usage Guide](#usage-guide)
- [Limitations](#limitations)
- [Development](#development)

---

## Overview

### Features

- **End-to-End Encryption**: All messages encrypted client-side using AES-256-GCM
- **Perfect Forward Secrecy**: Signal-style ratchet provides forward secrecy for all messages
- **Challenge-Response Authentication**: Two-factor authentication using password + ECDSA signature
- **Private & Public Rooms**: Create public rooms or private rooms with invite codes
- **Invite Code System**: UUID-based invite codes with 128-bit entropy for private room access
- **CSRF Protection**: Double-submit cookie pattern with database-backed token validation
- **Rate Limiting**: IP-based request throttling with trusted proxy support, plus WebSocket message rate limiting
- **Connection Limits**: Maximum 5 concurrent WebSocket connections per user
- **Room Limits**: Maximum 256 rooms per user
- **Ephemeral Messaging**: Messages not stored on server (live delivery only)
- **Real-time Communication**: WebSocket-based instant messaging
- **Strong Password Policy**: Requires uppercase, lowercase, digit, and special character

### Technology Stack

| Component | Technology |
|-----------|------------|
| Backend | Go 1.25+ |
| Database | SQLite (modernc.org/sqlite - pure Go) |
| Frontend | Vanilla JavaScript (ES6+) |
| Real-time | WebSocket (gorilla/websocket) |
| Cryptography | Web Crypto API (browser-native) |
| Password Hashing | bcrypt (cost 12) |
| Key Storage | IndexedDB (encrypted with PBKDF2 + AES-GCM) |

---

## Security Model

### Threat Model

SecuChat is designed to protect against:

| Threat | Protection |
|--------|------------|
| Server reading messages | Client-side encryption with keys never sent to server |
| Network interception | TLS encryption (when deployed with HTTPS) |
| Message tampering | AES-GCM provides authenticated encryption |
| Replay attacks | Per-user, per-room sequence checks (generation/message_num), bounded server-validated timestamps, and unique IVs |
| Account takeover | Password + cryptographic signature required |
| CSRF attacks | Double-submit cookie pattern |
| Rate limiting bypass | Trusted proxy validation for X-Forwarded-For |
| Unauthorized room access | Private rooms and room-scoped key lookup require membership checks |
| Key compromise | Ratchet provides forward secrecy for past messages |

### Security Features

| Feature | Implementation |
|---------|----------------|
| Authentication | Challenge-response with bcrypt password + ECDSA signature |
| Session Management | Server-side sessions in database, HMAC-signed cookies, 24-hour expiry, max 10 sessions per user, immediate WebSocket teardown on invalidation |
| CSRF Protection | Double-submit cookie with database-backed token validation, session-bound tokens, exact case-sensitive constant-time token compare |
| Security Headers | CSP (no unsafe-inline, connect-src 'self'), HSTS preload, X-Frame-Options, X-Content-Type-Options, Referrer-Policy |
| Rate Limiting | 10 requests/minute per IP, 5/minute for sensitive endpoints, 10 messages/second per WebSocket, trusted proxy aware |
| Connection Limits | Maximum 5 concurrent WebSocket connections per user |
| Room Limits | Maximum 256 rooms per user, auto-deletion after 30 days inactivity |
| Input Validation | Username format, password complexity (uppercase/lowercase/digit/special), room name sanitization |
| Database | SQLite with WAL mode for concurrency, foreign key constraints |
| Invite Codes | UUID v4 format with 128-bit entropy |

### What SecuChat Does NOT Protect Against

- **Metadata analysis**: Server knows who communicates with whom and when
- **Endpoint compromise**: If your device is compromised, encryption keys can be extracted
- **Social engineering**: Attacker could trick you into sharing invite codes
- **Denial of service**: Server can refuse to relay messages
- **Cross-connection replay continuity**: Replay state is tracked per user/room across reconnects to block replayed messages with stale generation/message_num ordering

### Trust Assumptions

1. Server is honest-but-curious (will follow protocol but may try to read messages)
2. Users' browsers are not compromised
3. TLS certificates are valid (for HTTPS deployment)
4. Invite codes are shared only with intended recipients

---

## Architecture

### System Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                           Client (Browser)                           │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐ │
│  │   app.js    │──│   ws.js     │──│  crypto.js  │──│   api.js    │ │
│  │  UI Logic   │  │  WebSocket  │  │  Encryption │  │  REST API   │ │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘ │
│         │                │                               │           │
│         └────────────────┴───────────────────────────────┘           │
│                              │                                       │
│                    WebCrypto API + IndexedDB + WebSocket             │
└──────────────────────────────│──────────────────────────────────────┘
                               │
                               │ HTTPS / WSS
                               │
┌──────────────────────────────│──────────────────────────────────────┐
│                         Server (Go)                                   │
│  ┌─────────────────────────────────────────────────────────────────┐ │
│  │                         main.go                                  │ │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐              │ │
│  │  │HTTP Handler │  │  WebSocket  │  │   Static    │              │ │
│  │  │  (mux)      │  │    Hub      │  │   Files     │              │ │
│  │  └─────────────┘  └─────────────┘  └─────────────┘              │ │
│  │         │                │                                       │ │
│  │         └────────────────┼───────────────────────┐               │ │
│  │                          │                       │               │ │
│  │  ┌───────────────────────┴───────────────────┐  │               │ │
│  │  │           Middleware Layer                 │  │               │ │
│  │  │  ┌──────────┐ ┌──────────┐ ┌──────────┐   │  │               │ │
│  │  │  │ auth.go  │ │ csrf.go  │ │ratelimit │   │  │               │ │
│  │  │  └──────────┘ └──────────┘ └──────────┘   │  │               │ │
│  │  └───────────────────────┬───────────────────┘  │               │ │
│  │                          │                       │               │ │
│  │  ┌───────────────────────┴───────────────────┐  │               │ │
│  │  │              Handlers                      │  │               │ │
│  │  │  ┌──────────┐ ┌──────────┐ ┌──────────┐   │  │               │ │
│  │  │  │  auth.go │ │ room.go  │ │  ws.go   │   │  │               │ │
│  │  │  └──────────┘ └──────────┘ └──────────┘   │  │               │ │
│  │  └───────────────────────┬───────────────────┘  │               │ │
│  │                          │                       │               │ │
│  │  ┌───────────────────────┴───────────────────┐  │               │ │
│  │  │              db/db.go                      │◄─┘               │ │
│  │  │         (SQLite Operations)                │                  │ │
│  │  └───────────────────────┬───────────────────┘                  │ │
│  └──────────────────────────┼──────────────────────────────────────┘ │
│                             │                                        │
│                    ┌────────┴────────┐                               │
│                    │   secuchat.db   │                               │
│                    │    (SQLite)     │                               │
│                    └─────────────────┘                               │
└───────────────────────────────────────────────────────────────────────┘
```

### Component Description

#### Backend Components

| File | Purpose |
|------|---------|
| `cmd/server/main.go` | Entry point, HTTP routing, middleware setup, security headers |
| `internal/handler/auth.go` | Challenge-response authentication, password hashing, session management |
| `internal/handler/room.go` | Room CRUD operations, private rooms, invite codes, membership management |
| `internal/handler/ws.go` | WebSocket hub, message broadcasting, connection limits, ratchet state routing |
| `internal/middleware/auth.go` | Authentication middleware for protected routes |
| `internal/middleware/csrf.go` | CSRF token generation and validation |
| `internal/middleware/ratelimit.go` | IP-based rate limiting with trusted proxy support |
| `internal/session/session.go` | Shared session utilities (cookie parsing, HMAC signing, trusted proxy checks) |
| `internal/db/db.go` | SQLite database operations, migrations |
| `internal/models/models.go` | Data structure definitions |

#### Frontend Components

| File | Purpose |
|------|---------|
| `web/index.html` | Single-page application markup |
| `web/css/style.css` | Dark theme styling |
| `web/js/crypto.js` | Cryptographic operations, ratchet implementation, IndexedDB storage |
| `web/js/api.js` | REST API client with CSRF handling |
| `web/js/ws.js` | WebSocket client with reconnection logic |
| `web/js/app.js` | Main application logic and UI management |

### Data Flow

#### User Registration Flow

```
User                Browser                  Server                Database
 │                     │                        │                      │
 │  Enter username     │                        │                      │
 │  & password         │                        │                      │
 ├────────────────────►│                        │                      │
 │                     │  Generate ECDH keypair │                      │
 │                     │  Generate ECDSA keypair│                      │
 │                     ├───────────────────────►│                      │
 │                     │                        │                      │
 │                     │  POST /api/auth/create │                      │
 │                     │  {username, password,  │                      │
 │                     │   public_key,          │                      │
 │                     │   signing_key}         │                      │
 │                     ├───────────────────────►│                      │
 │                     │                        │  Hash password       │
 │                     │                        │  (bcrypt)            │
 │                     │                        ├─────────────────────►│
 │                     │                        │  INSERT user         │
 │                     │                        │  INSERT challenge    │
 │                     │                        │  INSERT csrf_token   │
 │                     │                        │                      │
 │                     │                        │  Set session cookie  │
 │                     │◄───────────────────────┤                      │
 │                     │  {id, username}        │                      │
 │                     │                        │                      │
 │                     │  Store keypairs in     │                      │
 │                     │  IndexedDB (encrypted  │                      │
 │                     │  with key password)    │                      │
```

#### Message Sending Flow with Ratchet

```
Sender               Sender Browser            Server              Receiver Browser
 │                       │                        │                      │
 │  Type message         │                        │                      │
 ├──────────────────────►│                        │                      │
 │                       │  Get next message key  │                      │
 │                       │  from ratchet chain    │                      │
 │                       │                        │                      │
 │                       │  Encrypt with          │                      │
 │                       │  message key           │                      │
 │                       │                        │                      │
 │                       │  Sign payload          │                      │
 │                       ├───────────────────────►│                      │
 │                       │                        │                      │
 │                       │  WS: {type:message,    │                      │
 │                       │      room_id, content, │                      │
 │                       │      generation,       │                      │
 │                       │      message_num,      │                      │
 │                       │      signature}        │                      │
 │                       ├───────────────────────►│                      │
 │                       │                        │  Verify signature    │
 │                       │                        │  Verify room access  │
 │                       │                        │  Broadcast to room   │
 │                       │                        ├─────────────────────►│
 │                       │                        │                      │  Verify signature
 │                       │                        │                      │  Decrypt with
 │                       │                        │                      │  ratchet state
```

---

## API Reference

### Authentication

**CSRF Token Flow**

- Fetch an initial CSRF token via `GET /api/auth/me` (cookie `csrf_token` + response header `X-CSRF-Token`).
- Include `X-CSRF-Token` for CSRF-protected write requests (`POST`/`PUT`).
- The header token must exactly match the cookie token (case-sensitive).
- After each successful CSRF-protected write request, the server rotates the token and returns a new `csrf_token` cookie and `X-CSRF-Token` header.

#### POST /api/auth/create

Create a new account with password and cryptographic keys.

**Request:**
```json
{
  "username": "alice",
  "password": "SecurePass123!",
  "public_key": "BASE64_SPKI_ECDH_P256",
  "signing_key": "BASE64_SPKI_ECDSA_P256"
}
```

**Requirements:**
- Username: 3-32 characters, alphanumeric and underscores only
- Password: minimum 8 characters, must contain uppercase, lowercase, digit, and special character
- Public key: base64-encoded SPKI ECDH P-256 public key (for key exchange)
- Signing key: base64-encoded SPKI ECDSA P-256 public key (for authentication)

**Response:** `201 Created`
```json
{
  "id": "a1b2c3d4e5f6...",
  "username": "alice"
}
```

**Errors:**
| Code | Status | Description |
|------|--------|-------------|
| `INVALID_REQUEST` | 400 | Invalid request body or username already exists |
| `INVALID_USERNAME` | 400 | Username format invalid |
| `INVALID_PASSWORD` | 400 | Password does not meet complexity requirements |
| `MISSING_PUBLIC_KEY` | 400 | ECDH public key not provided |
| `MISSING_SIGNING_KEY` | 400 | ECDSA signing key not provided |

**Cookies:** Sets `session` and `csrf_token` cookies

---

#### POST /api/auth/login

Initiate login by verifying password and receiving a challenge.

**Headers:** Requires `X-CSRF-Token` header

**Request:**
```json
{
  "username": "alice",
  "password": "SecurePass123!"
}
```

**Response:** `200 OK`
```json
{
  "nonce": "base64-encoded-random-nonce",
  "expires_at": 1705312200,
  "user_id": "a1b2c3d4e5f6..."
}
```

Sign the verification payload as `nonce:user_id` using your ECDSA private key before calling `/api/auth/verify`.

**Errors:**
| Code | Status | Description |
|------|--------|-------------|
| `INVALID_CREDENTIALS` | 401 | Wrong username or password |

---

#### POST /api/auth/verify

Complete login by signing the challenge with ECDSA private key.

**Headers:** Requires `X-CSRF-Token` header

**Request:**
```json
{
  "username": "alice",
  "nonce": "base64-encoded-nonce-from-login",
  "signature": "BASE64_ECDSA_SIGNATURE"
}
```

**Signature Format:** base64-encoded ECDSA signature bytes over the SHA-256 hash of `nonce:userID`. DER-encoded ASN.1 signatures are supported (WebCrypto default); raw 64-byte `r || s` is also accepted.

**Response:** `200 OK`
```json
{
  "id": "a1b2c3d4e5f6...",
  "username": "alice"
}
```

**Errors:**
| Code | Status | Description |
|------|--------|-------------|
| `INVALID_CHALLENGE` | 401 | Challenge expired or invalid |
| `INVALID_CREDENTIALS` | 401 | User mismatch |
| `INVALID_SIGNATURE` | 401 | Signature verification failed |

---

#### GET /api/auth/me

Get current authenticated user.

Also refreshes/sets the CSRF token cookie and `X-CSRF-Token` response header.

**Response:** `200 OK`
```json
{
  "id": "a1b2c3d4e5f6...",
  "username": "alice"
}
```

**Errors:**
| Code | Status | Description |
|------|--------|-------------|
| `UNAUTHORIZED` | 401 | Not authenticated |

---

#### POST /api/auth/logout

Clear session cookie.

**Headers:** Requires `X-CSRF-Token` header

**Response:** `200 OK`

---

### Users

#### GET /api/users/{id}/key

Get a user's public key for encryption. Requires authentication.

When requesting another user's key, pass `room_id` so the server can verify both users are members of that room.

**Query Parameters**
- `room_id` (optional): required when requesting a key for a user other than the authenticated account

**Response:** `200 OK`
```json
{
  "id": "a1b2c3d4e5f6...",
  "username": "alice",
  "public_key": "BASE64_SPKI_ECDH_P256",
  "signing_key": "BASE64_SPKI_ECDSA_P256"
}
```

**Errors:**
| Code | Status | Description |
|------|--------|-------------|
| `INVALID_REQUEST` | 400 | `room_id` required when requesting another user |
| `UNAUTHORIZED` | 401 | Not authenticated |
| `FORBIDDEN` | 403 | Not authorized to access this room or target user |
| `USER_NOT_FOUND` | 404 | User not found |

---

### Rooms

#### GET /api/rooms

List public rooms (paginated). Requires authentication.

**Query Parameters:**
- `limit` (optional): Maximum rooms to return (default: 50, max: 100)
- `offset` (optional): Number of rooms to skip (default: 0)

**Response:** `200 OK`
```json
[
  {
    "id": "room-uuid-1",
    "name": "General Chat",
    "is_private": false,
    "created_by": "user-id-1",
    "created_at": "2024-01-15T10:30:00Z"
  }
]
```

---

#### POST /api/rooms

Create a new room. Requires authentication and CSRF token.

**Headers:** Requires `X-CSRF-Token` header

**Request:**
```json
{
  "name": "My Secret Room",
  "is_private": true
}
```

**Response:** `200 OK`
```json
{
  "id": "new-room-uuid",
  "name": "My Secret Room",
  "is_private": true,
  "invite_code": "550e8400-e29b-41d4-a716-446655440000"
}
```

**Errors:**
| Code | Status | Description |
|------|--------|-------------|
| `UNAUTHORIZED` | 401 | Not authenticated |
| `INVALID_ROOM_NAME` | 400 | Missing or invalid room name |
| `ROOM_LIMIT_EXCEEDED` | 403 | Maximum 256 rooms per user |

---

#### GET /api/rooms/{id}

Get room details including members. Requires authentication and room membership.

**Response:** `200 OK`
```json
{
  "id": "room-uuid",
  "name": "My Room",
  "is_private": true,
  "invite_code": "550e8400-e29b-41d4-a716-446655440000",
  "created_by": "user-id",
  "created_at": "2024-01-15T10:30:00Z",
  "members": [
    {
      "id": "user-id-1",
      "username": "alice",
      "public_key": "BASE64_SPKI_ECDH_P256",
      "signing_key": "BASE64_SPKI_ECDSA_P256",
      "created_at": "2024-01-15T10:00:00Z"
    }
  ]
}
```

**Note:** `invite_code` is only included if the requester is the room creator.

**Errors:**
| Code | Status | Description |
|------|--------|-------------|
| `UNAUTHORIZED` | 401 | Not authenticated |
| `ROOM_NOT_FOUND` | 404 | Room not found |
| `FORBIDDEN` | 403 | Not a member of the room |

---

#### POST /api/rooms/{id}/join

Join a room. Requires authentication and CSRF token.

**Headers:** Requires `X-CSRF-Token` header

**Request (for private rooms):**
```json
{
  "invite_code": "550e8400-e29b-41d4-a716-446655440000"
}
```

**Response:** `200 OK`
```json
{
  "room_id": "room-uuid",
  "members": [...]
}
```

**Errors:**
| Code | Status | Description |
|------|--------|-------------|
| `UNAUTHORIZED` | 401 | Not authenticated |
| `ROOM_NOT_FOUND` | 404 | Room not found |
| `INVALID_INVITE_CODE` | 403 | Missing or invalid invite code for private room |

---

#### POST /api/rooms/join-by-code

Join a private room using only the invite code. Requires authentication and CSRF token.

**Headers:** Requires `X-CSRF-Token` header

**Rate Limit:** 5 requests per minute (stricter than standard endpoints to prevent brute force)

**Request:**
```json
{
  "invite_code": "550e8400-e29b-41d4-a716-446655440000"
}
```

**Response:** `200 OK`
```json
{
  "room_id": "room-uuid",
  "name": "Room Name",
  "members": [...]
}
```

---

#### POST /api/rooms/{id}/leave

Leave a room. Requires authentication and CSRF token.

**Headers:** Requires `X-CSRF-Token` header

**Response:** `200 OK`

---

#### GET /api/rooms/{id}/members

Get list of room members. Requires authentication and room membership.

**Response:** `200 OK`
```json
[
  {
    "id": "user-id-1",
    "username": "alice",
    "public_key": "BASE64_SPKI_ECDH_P256",
    "signing_key": "BASE64_SPKI_ECDSA_P256",
    "created_at": "2024-01-15T10:00:00Z"
  }
]
```

**Errors:**
| Code | Status | Description |
|------|--------|-------------|
| `UNAUTHORIZED` | 401 | Not authenticated |
| `ROOM_NOT_FOUND` | 404 | Room not found |
| `FORBIDDEN` | 403 | Not a member of the room |

---

#### POST /api/rooms/{id}/regenerate-code

Generate a new invite code for a private room. Requires authentication and CSRF token. Only room creator can regenerate.

**Headers:** Requires `X-CSRF-Token` header

**Response:** `200 OK`
```json
{
  "invite_code": "660e8400-e29b-41d4-a716-446655440001"
}
```

**Errors:**
| Code | Status | Description |
|------|--------|-------------|
| `UNAUTHORIZED` | 401 | Not authenticated |
| `ROOM_NOT_FOUND` | 404 | Room not found |
| `FORBIDDEN` | 403 | Only room creator can regenerate |

---

### Health Check

#### GET /health

Check server and database health.

**Response:** `200 OK`
```json
{
  "status": "healthy"
}
```

**Response:** `503 Service Unavailable`
```json
{
  "status": "unhealthy",
  "database": "disconnected",
  "error": "connection refused"
}
```

---

## WebSocket Protocol

### Connection

Connect to `ws://host/ws` or `wss://host/ws` (requires authentication cookie).

**Connection Limits:** Maximum 5 concurrent connections per user.
**Message Limits:** Maximum 10 messages/sec per connection; further messages close the socket with policy violation.
**Session Lifecycle:** Session validity is checked at upgrade, during message handling, and on a periodic timer. Invalidated sessions are disconnected immediately (e.g., logout).
**Validation:** Messages are rejected if `room_id` is missing (except `pong` control frames), the sender is not a member of that room, signature validation fails, timestamp is outside the accepted window, or replay/state checks fail. Room fanout also re-checks session + membership, so revoked members stop receiving immediately.

### Message Format

All messages are JSON with the following base structure:

```typescript
interface Message {
  type: string;
  room_id: string;
  sender_id?: string;
  sender?: string;
  content: any;
  signature?: string;
  timestamp?: number;
  generation?: number;
  message_num?: number;
}
```

### Client → Server Messages

#### Join Room
```json
{
  "type": "join",
  "room_id": "room-uuid"
}
```

**Authorization:** Server verifies room membership before applying `join` effects.

#### Leave Room
```json
{
  "type": "leave",
  "room_id": "room-uuid"
}
```

#### Chat Message
```json
{
  "type": "message",
  "room_id": "room-uuid",
  "content": {
    "iv": "BASE64_IV",
    "ciphertext": "BASE64_CIPHERTEXT"
  },
  "signature": "BASE64_ECDSA_SIGNATURE",
  "timestamp": 1705312200000,
  "generation": 3,
  "message_num": 42
}
```

The signature is computed over the SHA-256 hash of the JSON-encoded payload containing room_id, iv, ciphertext, timestamp, generation, and message_num.

Server validation also enforces:

- Timestamp window: no more than 30 seconds future skew and no more than 5 minutes old
- Message ordering: monotonically increasing (`generation`, then `message_num`) per user/room replay state
- Signature format: raw 64-byte `r || s` or DER-encoded ASN.1 ECDSA signatures are accepted

#### Key Request
```json
{
  "type": "key_request",
  "room_id": "room-uuid"
}
```

Sent when a new member joins and needs the current ratchet state. All existing members will receive this.

#### Ratchet State Distribution
```json
{
  "type": "ratchet_state",
  "room_id": "room-uuid",
  "content": {
    "user_id": "recipient-user-id",
    "state": {
      "iv": "BASE64_IV",
      "ciphertext": "BASE64_CIPHERTEXT"
    },
    "epoch": 3,
    "reason": "membership_change",
    "timestamp": 1705312200000,
    "signature": "BASE64_ECDSA_SIGNATURE"
  }
}
```

Sent directly to a specific user with the encrypted ratchet state.

### Server → Client Messages

#### Chat Message (Broadcast)
```json
{
  "type": "message",
  "room_id": "room-uuid",
  "sender_id": "sender-user-id",
  "sender": "alice",
  "content": {
    "iv": "BASE64_IV",
    "ciphertext": "BASE64_CIPHERTEXT"
  },
  "signature": "BASE64_ECDSA_SIGNATURE",
  "timestamp": 1705312200000,
  "generation": 3,
  "message_num": 42
}
```

#### User Joined
```json
{
  "type": "join",
  "room_id": "room-uuid",
  "sender_id": "new-user-id",
  "sender": "bob"
}
```

#### User Left
```json
{
  "type": "leave",
  "room_id": "room-uuid",
  "sender_id": "leaving-user-id",
  "sender": "bob"
}
```

#### Members Update
```json
{
  "type": "members",
  "room_id": "room-uuid",
  "content": [
    {"id": "user-id", "username": "alice", "public_key": "BASE64_SPKI_ECDH_P256", "signing_key": "BASE64_SPKI_ECDSA_P256", "created_at": "..."}
  ]
}
```

---

## Cryptographic Implementation

### Algorithms Used

| Purpose | Algorithm | Key Size |
|---------|-----------|----------|
| Key Exchange | ECDH (P-256) | 256-bit |
| Message Encryption | AES-GCM | 256-bit |
| Message Key Derivation | HKDF-SHA256 | 256-bit |
| Challenge Signing | ECDSA (P-256) | 256-bit |
| Password Hashing | bcrypt | cost 12 |
| Session Signing | HMAC-SHA256 | - |
| Key Storage Encryption | PBKDF2 + AES-GCM | 256-bit |
| Key Serialization | SPKI (public), raw (symmetric), JWK (private) | - |

### Room Ratchet (Signal-Style)

Each room maintains a ratchet state that provides perfect forward secrecy:

```
┌─────────────────────────────────────────────────────────────┐
│                    Room Ratchet State                        │
├─────────────────────────────────────────────────────────────┤
│  generation: 3                                               │
│  rootKey: [32 bytes HKDF root]                               │
│  chainKey: [32 bytes current chain]                          │
│  messageNum: 42                                              │
│  skippedKeys: Map<messageNum, key> (for out-of-order msgs)   │
└─────────────────────────────────────────────────────────────┘
```

#### Ratchet Operations

**Initialization:**
```javascript
async init() {
    const rootKey = window.crypto.getRandomValues(new Uint8Array(32));
    this.rootKey = rootKey;
    this.chainKey = await this.hkdf(rootKey, new Uint8Array(0), 'chain');
    this.messageNum = 0;
    this.generation++;
}
```

**Sending Message:**
```javascript
async nextMessageKey() {
    const messageKey = await this.hkdf(this.chainKey, new Uint8Array(0), 'msg');
    this.chainKey = await this.hkdf(this.chainKey, new Uint8Array(0), 'next');
    this.messageNum++;
    return messageKey;
}
```

**Ratchet Step (on member join):**
```javascript
async ratchetStep(additionalEntropy) {
    const input = concat(this.rootKey, additionalEntropy, randomBytes(32));
    this.rootKey = await this.hkdf(input, new Uint8Array(0), 'ratchet');
    this.chainKey = await this.hkdf(this.rootKey, new Uint8Array(0), 'chain');
    this.generation++;
    this.messageNum = 0;
    this.skippedKeys.clear();
}
```

#### Ratchet State Distribution

When a new member joins:
1. An existing member (key master) performs a ratchet step with the new member's public key as entropy
2. The new ratchet state is encrypted with ECDH-derived key for each member
3. State is sent directly to the new member via `ratchet_state` message

### Key Generation

Each user generates two key pairs on registration:

```javascript
// ECDH key pair for key exchange (ratchet state distribution)
async generateKeyPair() {
    return await window.crypto.subtle.generateKey(
        {
            name: 'ECDH',
            namedCurve: 'P-256'
        },
        true,
        ['deriveKey', 'deriveBits']
    );
}

// ECDSA key pair for authentication (challenge and message signing)
async generateSigningKeyPair() {
    return await window.crypto.subtle.generateKey(
        {
            name: 'ECDSA',
            namedCurve: 'P-256'
        },
        true,
        ['sign', 'verify']
    );
}
```

**Important:** The ECDH and ECDSA keys are separate. ECDH is used only for deriving shared secrets, while ECDSA is used only for signing.

### Challenge-Response Authentication

1. **Login Request**: Client sends username and password
2. **Password Verification**: Server verifies bcrypt hash (constant-time comparison)
3. **Challenge Issued**: Server stores nonce in database and returns it with expiry
4. **Signature**: Client signs `SHA-256(nonce:userID)` with ECDSA private key
5. **Verification**: Server verifies ECDSA signature against stored public key

### Message Encryption

```javascript
async encryptMessage(roomId, plaintext) {
    const ratchet = this.roomRatchets[roomId];
    const messageKey = await ratchet.nextMessageKey();
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const encoded = new TextEncoder().encode(plaintext);
    
    const ciphertext = await window.crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: iv },
        messageKey,
        encoded
    );
    
    return {
        iv: Array.from(iv),
        ciphertext: Array.from(new Uint8Array(ciphertext))
    };
}
```

### Key Storage

Keys are stored locally in browser IndexedDB, encrypted with a user-provided password using PBKDF2 (600,000 iterations) and AES-GCM.

**Storage Format (Version 4):**
```json
{
  "salt": [...],
  "iv": [...],
  "data": [...],
  "iterations": 600000,
  "version": 4
}
```

The encrypted `data` contains:
- ECDH private key (JWK format)
- ECDH public key (SPKI format)
- ECDSA private key (JWK format)
- ECDSA public key (SPKI format)

**Important:** Each browser/device stores its own keys. Users cannot log in from a different browser without creating a new account.

### Security Properties

| Property | Implementation |
|----------|----------------|
| Confidentiality | AES-256-GCM encryption |
| Integrity | GCM authentication tag |
| Authenticity | ECDSA signatures on chat payloads; control frames are server-authenticated by session + room membership checks |
| Forward Secrecy | HKDF chain ratchet, new generation on member join |
| Post-Compromise Security | Ratchet step with new entropy on member join |
| Authentication | Challenge-response signature |

### Message Signing

All chat messages are signed by the sender using ECDSA P-256:

1. **Client-side signing**: Before sending, the client signs the message payload (room_id, iv, ciphertext, timestamp, generation, message_num) with their ECDSA private key
2. **Server verification**: The server verifies the signature against the sender's stored public key before broadcasting
3. **Client verification**: Receivers verify the signature to ensure the message genuinely came from the claimed sender

---

## Deployment

### Requirements

- Go 1.25 or higher
- A domain name (recommended)
- TLS certificate (for HTTPS, strongly recommended)

### Building

```bash
# Clone or download the project
cd SecuChat

# Build the server
go build -o secuchat ./cmd/server

# On Windows
go build -o secuchat.exe ./cmd/server
```

### Upgrading from Previous Versions

This version introduces breaking changes to the cryptographic protocol:
- Signal-style ratchet for forward secrecy
- Message format includes generation and message_num
- IndexedDB instead of localStorage
- UUID invite codes
- Database schema versioning via `PRAGMA user_version`

**Fresh Install (Required):**

Delete the existing database and let the server create a new one:
```bash
rm secuchat.db  # On Windows: del secuchat.db
./secuchat
```

**Note:** All existing users will need to create new accounts as the key storage format has changed.

**Schema Compatibility Note:**
- The server tracks schema with `PRAGMA user_version`.
- Newer database schema versions are rejected by older binaries at startup.
- Upgrade binaries before running against a database created by a newer release.

### Running

```bash
# Required environment variables
export SESSION_SECRET="your-random-32-character-secret-here"
export ALLOWED_ORIGINS="https://chat.yourdomain.com"

# Optional environment variables
export DB_PATH="/var/lib/secuchat/secuchat.db"
export TRUSTED_PROXIES="10.0.0.1,192.168.1.0/24"

# Default port 8080
./secuchat

# Custom port
PORT=3000 ./secuchat

# On Windows (PowerShell)
$env:SESSION_SECRET="your-random-32-character-secret-here"
$env:ALLOWED_ORIGINS="https://chat.yourdomain.com"
$env:TRUSTED_PROXIES="127.0.0.1,::1"
$env:PORT="3000"
.\secuchat.exe
```

#### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `SESSION_SECRET` | Yes | Secret key for signing session cookies (min 32 characters) |
| `ALLOWED_ORIGINS` | Yes | Comma-separated list of full **HTTPS** origins only (e.g., `https://example.com,https://www.example.com`). Wildcards, bare hosts, and non-HTTPS origins are rejected at startup. |
| `TRUSTED_PROXIES` | No | Comma-separated list of trusted proxy IPs/CIDRs for X-Forwarded-For header |
| `DB_PATH` | No | Path to SQLite database file (default: `secuchat.db` in working directory) |
| `PORT` | No | Server port (default: 8080) |

### Production Deployment with Nginx

#### 1. Systemd Service

Create `/etc/systemd/system/secuchat.service`:

```ini
[Unit]
Description=SecuChat Server
After=network.target

[Service]
Type=simple
User=secuchat
Group=secuchat
WorkingDirectory=/opt/secuchat
ExecStart=/opt/secuchat/secuchat
Restart=on-failure
RestartSec=5
Environment=PORT=8080
Environment=SESSION_SECRET=your-random-32-character-secret-here
Environment=ALLOWED_ORIGINS=https://chat.yourdomain.com
Environment=TRUSTED_PROXIES=127.0.0.1,::1
Environment=DB_PATH=/opt/secuchat/secuchat.db

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl enable secuchat
sudo systemctl start secuchat
```

#### 2. Nginx Reverse Proxy

Create `/etc/nginx/sites-available/secuchat`:

```nginx
server {
    listen 80;
    server_name chat.yourdomain.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name chat.yourdomain.com;

    ssl_certificate /etc/letsencrypt/live/chat.yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/chat.yourdomain.com/privkey.pem;

    # SSL configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;
    ssl_prefer_server_ciphers off;

    # Security headers (application also sets these)
    add_header X-Content-Type-Options nosniff;
    add_header X-Frame-Options DENY;
    add_header X-XSS-Protection "1; mode=block";

    client_max_body_size 1M;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        # Sanitize X-Forwarded-For to prevent client spoofing.
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;

        # WebSocket timeout
        proxy_read_timeout 86400;
    }
}
```

Enable:
```bash
sudo ln -s /etc/nginx/sites-available/secuchat /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

If Nginx is itself behind another trusted load balancer, configure Nginx `real_ip` settings first and keep `TRUSTED_PROXIES` limited to addresses that can reach SecuChat directly.

#### 3. TLS Certificate (Let's Encrypt)

```bash
sudo apt install certbot python3-certbot-nginx
sudo certbot --nginx -d chat.yourdomain.com
```

### Production Readiness Checklist

- Environment
  - Set `SESSION_SECRET` to a random >=32 character value and rotate with a planned migration.
  - Set `ALLOWED_ORIGINS` to exact full HTTPS origins only (for example `https://chat.example.com`). Wildcards, bare hosts, and `http://` are rejected.
  - Set `TRUSTED_PROXIES` only for real reverse-proxy IPs/CIDRs.
- Process and service
  - Run SecuChat behind a reverse proxy with HTTPS termination.
  - Run the service as an unprivileged user with least-privilege access to `/opt/secuchat`.
  - Enable log rotation and disk alerts for logs and `secuchat.db`.
- Data and security
  - Back up `secuchat.db` and test restore on a staging copy before release.
  - Run `go test ./...` in CI for every release candidate.
  - Smoke check: `/health`, `/api/auth/create`, `/api/auth/login`, `/api/auth/verify`, `/api/auth/me`.
- Runtime verification
  - Verify room/member ACLs are enforced for `/api/users/{id}/key`, `/api/rooms/{id}`, and `/api/rooms/{id}/members`.
  - Verify WebSocket validation rejects missing room_id, invalid signatures, bad timestamps, and replay/order violations.
  - Verify session invalidation/logouts immediately close active WebSocket connections.
  - Verify revoked room members stop receiving room broadcasts on existing sockets.
  - Verify HTTP and WebSocket rate limits are enforced under load.
- Deployment
  - Validate frontend artifacts are deployed from the expected build/tag and match server version.
  - Perform room join + key fetch + message exchange end-to-end before opening production traffic.

### Firewall Configuration

```bash
# Allow only HTTP/HTTPS externally
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw enable
```

### File Structure on Server

```
/opt/secuchat/
├── secuchat          # Binary
├── secuchat.db       # Database (created automatically)
└── web/              # Static files
    ├── index.html
    ├── css/
    │   └── style.css
    └── js/
        ├── app.js
        ├── api.js
        ├── crypto.js
        └── ws.js
```

---

## Usage Guide

### Creating an Account

1. Open the SecuChat URL in your browser
2. Enter a unique username (3-32 characters, letters, numbers, underscores)
3. Enter a password (minimum 8 characters, must include uppercase, lowercase, digit, and special character)
4. Click "Create Account"
5. Create a key password to protect your encryption keys locally

**Important:** 
- Your keys are stored in browser IndexedDB, encrypted with your key password
- **You must use the same browser to log in** - switching browsers or clearing data requires creating a new account
- You won't be able to decrypt old messages if you lose your keys
- The server stores only your public keys; private keys never leave your browser

### Logging In

1. Enter your username and password
2. Click "Login"
3. Enter your key password to decrypt your encryption keys

### Starting a Chat

1. After logging in, click "+ New Room"
2. Enter a room name (max 64 characters)
3. Check "Private Room" if you want to restrict access
4. Click "Create"
5. For private rooms, share the invite code (UUID format) with friends

### Joining a Room

**Public Rooms:**
1. Click "Refresh" to see available rooms
2. Click on a room to join
3. The room's ratchet state will be received from existing members

**Private Rooms (with invite code):**
1. Click "Join by Code"
2. Enter the invite code (UUID format: `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`)
3. Click "Join"

### Managing Private Rooms

- **Copy Invite Code**: Click "Copy" next to the invite code
- **Regenerate Code**: Click "Regenerate" to create a new code (old code becomes invalid)
- Only the room creator can regenerate invite codes

### Sending Messages

1. Type your message in the input field
2. Press Enter or click "Send"
3. Messages are encrypted with the current ratchet state before leaving your browser

### Leaving a Room

1. Click "Leave" button in the room header
2. You will stop receiving messages from that room

### Logging Out

1. Click the X button next to your username
2. Your session is cleared and keys are deleted from memory (encrypted keys remain stored locally for future login)

---

## Limitations

### Current Limitations

1. **No Message Persistence**: Messages are only delivered to online users
2. **No File Sharing**: Only text messages supported
3. **No Read Receipts**: No indication if messages were read
4. **Single Device**: No multi-device support for same account
5. **No User Search**: Must know exact room names or have invite codes

### Security Considerations

1. **Trust On First Use (TOFU)**: First time key exchange is trusted
2. **No Identity Verification**: Server assigns usernames
3. **Metadata Visibility**: Server sees who talks to whom

### Security Features Implemented

1. **Challenge-Response Authentication**: Password + ECDSA signature verification
2. **Server-Side Sessions**: Sessions stored in database with validation on every request and immediate WebSocket teardown on invalidation
3. **CSRF Protection**: Double-submit cookie with database-backed, session-bound token validation and exact case-sensitive token matching
4. **Security Headers**: CSP (no unsafe-inline, connect-src 'self'), HSTS preload, X-Frame-Options, X-Content-Type-Options, Referrer-Policy
5. **Rate Limiting**: IP-based rate limiting (10/min, 5/min for sensitive endpoints), WebSocket message limiting (10/sec)
6. **Private Rooms**: UUID invite codes with 128-bit entropy
7. **Connection Limits**: Maximum 5 concurrent WebSocket connections per user
8. **Room Limits**: Maximum 256 rooms per user
9. **Room Auto-Deletion**: Inactive rooms automatically deleted after 30 days
10. **Input Validation**: Username format, password complexity, room name sanitization
11. **Request Limits**: 64KB maximum request body size, 16KB WebSocket message size
12. **Database Security**: SQLite WAL mode, foreign key constraints, automatic cleanup
13. **Perfect Forward Secrecy**: Signal-style ratchet with HKDF chain
14. **Message Signing**: Chat payloads are signed with ECDSA P-256 and verified by server and clients
15. **Constant-Time Operations**: User existence checks, password comparison
16. **WebSocket Validation**: Per-message room membership checks, fanout-time session/membership revalidation, timestamp bounds, and per-user/per-room anti-replay ordering on `generation/message_num`

---

## Development

### Project Structure

```
SecuChat/
├── cmd/
│   └── server/
│       └── main.go
├── internal/
│   ├── db/
│   │   └── db.go
│   ├── handler/
│   │   ├── auth.go
│   │   ├── room.go
│   │   └── ws.go
│   ├── middleware/
│   │   ├── auth.go
│   │   ├── csrf.go
│   │   └── ratelimit.go
│   ├── session/
│   │   └── session.go
│   └── models/
│       └── models.go
├── web/
│   ├── index.html
│   ├── css/
│   │   └── style.css
│   └── js/
│       ├── api.js
│       ├── app.js
│       ├── crypto.js
│       └── ws.js
├── go.mod
├── go.sum
└── README.md
```

### Running in Development

```bash
# Start server with auto-reload (using air)
go install github.com/cosmtrek/air@latest
air

# Or manually
go run ./cmd/server
```

### Testing the API

```bash
# Create user (first get CSRF token from a GET request)
curl -X GET http://localhost:8080/api/auth/me -c cookies.txt

# Create user with CSRF token (keys must be generated client-side)
curl -X POST http://localhost:8080/api/auth/create \
  -H "Content-Type: application/json" \
  -H "X-CSRF-Token: $(grep csrf_token cookies.txt | awk '{print $7}')" \
  -b cookies.txt \
  -d '{"username":"test","password":"Password123!","public_key":"BASE64_SPKI_ECDH_P256","signing_key":"BASE64_SPKI_ECDSA_P256"}'

# Login - step 1: get challenge
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -H "X-CSRF-Token: $(grep csrf_token cookies.txt | awk '{print $7}')" \
  -b cookies.txt \
  -c cookies.txt \
  -d '{"username":"test","password":"Password123!"}'

# Login - step 2: verify with ECDSA signature (signature must be generated client-side)
curl -X POST http://localhost:8080/api/auth/verify \
  -H "Content-Type: application/json" \
  -H "X-CSRF-Token: $(grep csrf_token cookies.txt | awk '{print $7}')" \
  -b cookies.txt \
  -c cookies.txt \
  -d '{"username":"test","nonce":"received-nonce","signature":"BASE64_ECDSA_SIGNATURE"}'

# List rooms (with session cookie)
curl -X GET http://localhost:8080/api/rooms \
  -b cookies.txt

# Health check
curl http://localhost:8080/health
```

### Browser E2E Ratchet Recovery Plan

Use isolated browser profiles (or separate browsers) for users `A`, `B`, and `C`.

1. Create user `A`, create a room, and send a test message.
2. Join user `B` to the room and verify `A` ↔ `B` message exchange works.
3. Close `A` (no active key-holder online), keep room membership for `A` intact.
4. Join user `C` to the same room.
5. Confirm `C` shows ratchet state retries and then the recovery confirmation prompt after max retries.
6. Click `Cancel` in the prompt and verify:
   - message send is blocked for `C`
   - `C` sees a system message explaining recovery was canceled.
7. Leave/rejoin with `C`, then confirm recovery prompt again and click `OK`.
8. Verify `C` can now send messages and sees the recovery initialization system message.
9. Reopen `A` and rejoin the room; verify `A` receives ratchet state and can exchange new messages with `C`.
10. Repeat step 9 for `B` if `B` was offline during recovery.

Expected outcomes:
- No automatic room-key reset occurs without explicit user confirmation.
- Reconnects do not auto-trigger key recovery while WebSocket is disconnected.
- Recovery path remains usable when existing DB members are offline.

### Adding New Features

1. **Backend**: Add handlers in `internal/handler/`, register routes in `main.go`
2. **Frontend**: Add UI elements in `index.html`, logic in `app.js`
3. **Database**: Add migrations in `db.go` `createTables()`
4. **Middleware**: Add middleware in `internal/middleware/`

### Configuration Constants

Key constants can be found in the code:

| Constant | Value | Location |
|----------|-------|----------|
| `BcryptCost` | 12 | `internal/handler/auth.go` |
| `ChallengeExpiry` | 5 minutes | `internal/handler/auth.go` |
| `MaxRoomsPerUser` | 256 | `internal/handler/auth.go` |
| `MaxConnsPerUser` | 5 | `internal/handler/ws.go` |
| `maxMessagesPerSec` | 10 | `internal/handler/ws.go` |
| `maxMessageSize` | 16KB | `internal/handler/ws.go` |
| `SessionExpiry` | 24 hours | `internal/handler/auth.go` |
| `MaxSessionsPerUser` | 10 | `internal/db/db.go` |
| `CSRFExpiry` | 24 hours | `internal/middleware/csrf.go` |
| `maxBodySize` | 64KB | `cmd/server/main.go` |
| `InactiveRoomExpiryDays` | 30 | `cmd/server/main.go` |
| `PBKDF2_ITERATIONS` | 600,000 | `web/js/crypto.js` |
| `MAX_SKIPPED` (ratchet) | 100 | `web/js/crypto.js` |
| `KEY_REQUEST_TIMEOUT` | 5 seconds | `web/js/app.js` |
| `MAX_KEY_RETRIES` | 3 | `web/js/app.js` |

---

## License

MIT License - Use freely for personal and commercial projects.

---

## Contributing

Contributions welcome! Please ensure:

1. All crypto changes are reviewed for security implications
2. New features don't compromise the security model
3. Code follows existing patterns and conventions
4. All tests pass before submitting PRs
