# CSEDS Specification

**Client-Side Encrypted Data Synchronization**
*A server-mediated multi-device sync architecture with client-side key derivation and local credential escrow*

Version: 1.0
License: Apache 2.0

---

## 1. Introduction

CSEDS defines an architecture for synchronizing user data across multiple devices where the server acts as an encrypted blob store with no ability to read user content. Encryption and decryption occur exclusively on the client. The server is cryptographically blind.

CSEDS is designed for small-to-medium data payloads where full-blob synchronization is practical. Per-record synchronization is explicitly out of scope.

### 1.1 Design Goals

- Server stores only ciphertext — never plaintext user data
- Multi-device access via credential-derived encryption key
- Password recovery on known devices without server involvement
- Minimal server-side infrastructure requirements
- Simplicity over theoretical cryptographic purity

### 1.2 Non-Goals

See `THREAT-MODEL.md` for explicit non-goals and limitations.

---

## 2. Architecture Overview

```
┌─────────────────────────────────┐
│           CLIENT DEVICE          │
│                                  │
│  ┌──────────────┐                │
│  │  Credentials │                │
│  │  (username + │                │
│  │   password)  │                │
│  └──────┬───────┘                │
│         │ Argon2 KDF             │
│         ├──────────────────────┐ │
│         │                      │ │
│         ▼                      ▼ │
│  ┌─────────────┐   ┌─────────────┐│
│  │  Auth Token │   │ Encrypt Key ││
│  │  (server)   │   │ (local only)││
│  └──────┬──────┘   └──────┬──────┘│
│         │                 │       │
│  ┌──────▼──────────────────▼─────┐│
│  │     Local Credential Escrow   ││
│  │        (IndexedDB #2)         ││
│  └───────────────────────────────┘│
│                                   │
│  ┌───────────────────────────────┐│
│  │        User Data Store        ││
│  │        (IndexedDB #1)         ││
│  │     Encrypted before sync     ││
│  └───────────────┬───────────────┘│
└──────────────────┼─────────────────┘
                   │ Encrypted blob only
                   ▼
┌─────────────────────────────────┐
│              SERVER              │
│                                  │
│  ┌───────────────────────────┐   │
│  │   Auth Token Store        │   │
│  │   (hashed, bcrypt)        │   │
│  └───────────────────────────┘   │
│                                  │
│  ┌───────────────────────────┐   │
│  │   Encrypted Blob Store    │   │
│  │   (opaque ciphertext)     │   │
│  │   + server timestamp      │   │
│  │   + blob size             │   │
│  └───────────────────────────┘   │
│                                  │
│  ┌───────────────────────────┐   │
│  │   Active Session Store    │   │
│  │   (single session token   │   │
│  │    per user enforced)     │   │
│  └───────────────────────────┘   │
└─────────────────────────────────┘
```

---

## 3. Key Derivation

### 3.1 Algorithm

CSEDS mandates **Argon2id** for all key derivation operations. Argon2id provides resistance against both side-channel and GPU-based brute-force attacks.

### 3.2 Parameters (Minimum Recommended)

| Parameter | Minimum Value | Notes |
|---|---|---|
| Memory | 64 MB | Increase for higher security |
| Iterations | 3 | Balance security vs. UX latency |
| Parallelism | 1 | Single-threaded client context |
| Output length | 64 bytes | Split into two 32-byte keys |
| Salt | 16 bytes random | Generated at registration, stored server-side (not secret) |

### 3.3 Key Branching

A single Argon2id invocation produces 64 bytes of output, split into two independent 32-byte keys:

```
Argon2id(password, salt, params) → [bytes 0-31 | bytes 32-63]
                                         │               │
                                    Auth Key        Encryption Key
                                  (server auth)    (never leaves client)
```

**Auth Key:** Sent to server during authentication (after bcrypt hashing server-side).
**Encryption Key:** Used exclusively for client-side AES-256-GCM encryption. Never transmitted.

### 3.4 Salt Management

- Salt is generated randomly (16 bytes, CSPRNG) at registration
- Salt is NOT secret — stored server-side, retrieved by username at login
- Salt is NOT the password — knowledge of salt without password provides no advantage
- Salt ensures the same password produces different keys for different users

---

## 4. Authentication Flow

### 4.1 Registration

```
1. User provides username + password
2. Client generates random 16-byte salt via CSPRNG
3. Client derives [AuthKey | EncryptKey] via Argon2id(password, salt)
4. Client sends to server: { username, bcrypt(AuthKey), salt }
5. Server stores: { username, bcrypt(AuthKey), salt, created_at }
6. Client stores locally in IndexedDB #2 (Credential Escrow):
   { username, password }  ← cleartext, see Section 7
7. Client initializes empty encrypted blob, uploads to server
```

### 4.2 Login (Known Device)

```
1. User provides username + password
2. Client retrieves salt from server by username (unauthenticated endpoint)
3. Client derives [AuthKey | EncryptKey] via Argon2id(password, salt)
4. Client sends AuthKey to server for verification
5. Server compares bcrypt(AuthKey) — success or failure
6. Server issues session token, invalidates any existing session (see Section 6)
7. Client stores EncryptKey in memory for session duration only
8. Client populates IndexedDB #2 with cleartext credentials
```

### 4.3 Login (New Device)

Identical to 4.2. Credentials must be known — no server-side recovery path exists for new devices without prior credential knowledge.

---

## 5. Data Synchronization

### 5.1 Sync Trigger

Synchronization is triggered on:
- Login (inbound sync — retrieve latest blob from server)
- User data modification (outbound sync — push updated blob to server)
- Explicit user-initiated sync request

### 5.2 Sync Direction Logic

**Server timestamp is the sole source of truth for recency.** Client timestamps MUST NOT be used for sync direction decisions. This eliminates clock drift and timezone issues.

```
On login:
1. Client requests server blob metadata: { server_timestamp, blob_size }
2. Client compares server_timestamp to local IndexedDB #1 last_modified
3. If server is newer → decrypt server blob → overwrite local IndexedDB #1
4. If local is newer → encrypt local IndexedDB #1 → push to server
5. If equal → no action required
```

### 5.3 Blob Construction

The entire IndexedDB #1 user data store is serialized, encrypted, and transmitted as a single blob.

```
serialize(IndexedDB #1) → JSON string
encrypt(JSON string, EncryptKey) → { iv, ciphertext, auth_tag }
blob = base64({ iv, ciphertext, auth_tag })
```

### 5.4 Encryption Algorithm

**AES-256-GCM** is mandated for blob encryption.

| Parameter | Value |
|---|---|
| Algorithm | AES-256-GCM |
| Key size | 256 bits (32 bytes from Argon2id output) |
| IV | 12 bytes, random per encryption operation |
| Auth tag | 128 bits |

The IV MUST be unique per encryption operation. The IV is stored with the ciphertext blob (not secret).

### 5.5 Server Blob Metadata

Server stores alongside each blob:

| Field | Type | Notes |
|---|---|---|
| user_id | string | Internal identifier |
| blob | binary | Encrypted ciphertext |
| server_timestamp | epoch (ms) | Server-assigned on upload — client value ignored |
| blob_size | integer | Bytes, used for sync decision optimization |
| version | integer | Monotonically increasing — future conflict detection |

---

## 6. Session Management

### 6.1 Single Active Session Enforcement

CSEDS enforces **one active session per user** at all times. This eliminates the simultaneous multi-device write conflict problem entirely.

```
On new login:
1. Server checks for existing active session token for user
2. If exists → invalidate immediately
3. Issue new session token to current device
4. Previously active device receives 401 on next API call
5. Previously active device displays: "You have been logged out because
   your account was accessed on another device."
```

### 6.2 Session Token Properties

- Cryptographically random (minimum 32 bytes)
- Server-side storage only — never derived from credentials
- Expiry: implementation-defined (recommended: 24 hours idle timeout)
- Transmitted via Authorization header, never URL parameter

---

## 7. Local Credential Escrow

### 7.1 Purpose

The Local Credential Escrow enables password recovery on devices where the user has previously authenticated, without any server-side recovery mechanism.

### 7.2 Storage

Implemented as a separate IndexedDB database (IndexedDB #2), distinct from user data storage (IndexedDB #1).

```
IndexedDB #2 schema:
{
  username: string,   // cleartext
  password: string    // cleartext
}
```

### 7.3 Cleartext Rationale

Credentials are stored cleartext deliberately. The threat model accepts this tradeoff because:

- The device is within the user's physical control
- Browser storage access requires either physical device access or malware
- Both scenarios represent a compromised device — a threat boundary CSEDS does not claim to protect against
- Encryption of the escrow with a PIN or secondary password is a valid implementation extension but is not mandated by this specification

### 7.4 Recovery Flow

```
User clicks "Forgot credentials" on a previously bootstrapped device:
1. Client reads IndexedDB #2
2. Credentials displayed to user
3. User re-authenticates normally
```

### 7.5 Escrow Population

IndexedDB #2 is populated on every successful login. If a user changes their password, the escrow is updated at that time.

---

## 8. Password Change

Password change requires re-encryption of all user data due to key derivation from password.

```
1. User provides current password + new password
2. Client verifies current password against server (normal auth flow)
3. Client derives new EncryptKey from new password + new salt
4. Client decrypts existing blob with old EncryptKey
5. Client re-encrypts blob with new EncryptKey
6. Client sends to server: { bcrypt(new AuthKey), new salt, new blob }
7. Server updates auth record and blob atomically
8. Client updates IndexedDB #2 with new credentials
```

---

## 9. API Endpoints (Minimal Server Requirements)

| Endpoint | Auth | Purpose |
|---|---|---|
| GET /salt/{username} | None | Retrieve salt for key derivation |
| POST /register | None | Register new user |
| POST /login | AuthKey | Authenticate, receive session token |
| GET /blob | Session token | Retrieve encrypted blob + metadata |
| PUT /blob | Session token | Upload encrypted blob |
| POST /logout | Session token | Invalidate session |
| PUT /password | Session token | Change password + re-encrypted blob |

The server requires no knowledge of encryption keys, plaintext data, or key derivation parameters beyond salt storage.

---

## 10. Conformance

A conforming CSEDS implementation MUST:

- Use Argon2id for all key derivation
- Use AES-256-GCM for all blob encryption
- Never transmit the encryption key to the server
- Use server-assigned timestamps exclusively for sync direction
- Enforce single active session per user
- Generate a unique IV per encryption operation
- Store salt server-side and retrieve before key derivation

A conforming CSEDS implementation SHOULD:

- Enforce minimum password complexity
- Implement idle session timeout
- Clear EncryptKey from memory on logout
- Display explicit notification on forced logout

---

## Revision History

| Version | Date | Notes |
|---|---|---|
| 1.0 | 2026-03-10 | Initial release |
