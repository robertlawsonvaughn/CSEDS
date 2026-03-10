# CSEDS Implementation Guide

*Language-agnostic guidance for implementing the CSEDS specification*

---

## 1. Prerequisites

Before implementing CSEDS, ensure your environment provides:

- **Argon2id** library (see Section 3)
- **AES-256-GCM** encryption (Web Crypto API in browsers, standard in most runtimes)
- **CSPRNG** (Cryptographically Secure Pseudo-Random Number Generator)
- **IndexedDB** or equivalent local key-value storage
- **HTTPS** — non-negotiable, all API calls must be over TLS

---

## 2. Implementation Sequence

Implement in this order to avoid rework:

1. Argon2id key derivation + key branching
2. AES-256-GCM encrypt/decrypt
3. Server API endpoints (minimal — see SPEC Section 9)
4. Registration flow
5. Login flow + session management
6. Blob sync logic
7. Local credential escrow
8. Password recovery UI
9. Password change flow
10. Forced logout handling

---

## 3. Argon2id Library Selection

### JavaScript / Browser
```
argon2-browser  — WASM-based, runs in browser
@node-rs/argon2 — Node.js native binding (server-side only)
```

### Python
```
argon2-cffi     — Well-maintained, recommended
```

### Perl
```
Crypt::Argon2   — CPAN module
```

Verify your chosen library supports Argon2**id** specifically — not just Argon2i or Argon2d.

---

## 4. Key Derivation Implementation Notes

### Salt Retrieval
Salt must be retrieved from the server **before** key derivation on login. The salt endpoint is unauthenticated by design — salt is not secret.

```
GET /salt/{username} → { salt: "hex or base64 encoded salt" }
```

If username does not exist, return an identical response with a dummy salt to prevent username enumeration via timing attacks.

### Key Branching
```
raw_output = argon2id(password, salt, params)  // 64 bytes output
auth_key   = raw_output[0:32]                  // first 32 bytes
encrypt_key = raw_output[32:64]                // second 32 bytes
```

### Parameter Storage
Argon2id parameters (memory, iterations, parallelism) should be stored server-side alongside the salt to allow future parameter upgrades without requiring all users to re-authenticate simultaneously.

---

## 5. AES-256-GCM Implementation Notes

### IV Generation
```
iv = CSPRNG(12 bytes)   // Must be unique per encryption operation
```

Never reuse an IV with the same key. Since the encryption key changes only on password change, and the blob is re-encrypted on every sync, IV reuse is naturally avoided in normal operation.

### Blob Format
Store IV alongside ciphertext — it is not secret:

```json
{
  "iv": "<base64 encoded 12 bytes>",
  "ciphertext": "<base64 encoded encrypted data>",
  "tag": "<base64 encoded 16 byte auth tag>"
}
```

Some implementations (e.g., Web Crypto API) append the auth tag to ciphertext automatically. Document your format explicitly in your implementation.

### Web Crypto API Example Pattern
```javascript
// Encrypt
const iv = crypto.getRandomValues(new Uint8Array(12));
const encrypted = await crypto.subtle.encrypt(
  { name: "AES-GCM", iv },
  cryptoKey,
  encodedData
);

// Decrypt
const decrypted = await crypto.subtle.decrypt(
  { name: "AES-GCM", iv },
  cryptoKey,
  encryptedData
);
```

---

## 6. IndexedDB Schema

### IndexedDB #1 — User Data Store
Application-specific. CSEDS treats this as an opaque serializable object. Implement according to your application's data model.

Recommended: store a `last_modified` epoch timestamp at the top level for local sync comparison, though server timestamp takes precedence for sync direction decisions.

### IndexedDB #2 — Credential Escrow
```javascript
// Database name suggestion: "cseds_escrow"
// Object store: "credentials"
{
  id: 1,                    // single record
  username: "string",       // cleartext
  password: "string"        // cleartext
}
```

Keep these as two completely separate IndexedDB databases with distinct names to minimize accidental cross-contamination and simplify selective clearing.

---

## 7. Server Implementation Notes

### Minimal Stack Requirements
CSEDS server requirements are intentionally minimal:
- User record storage (username, hashed auth token, salt, Argon2 params)
- Blob storage (binary, per user)
- Blob metadata (server_timestamp, blob_size, version)
- Session token storage (single active token per user)

Any database capable of binary blob storage is sufficient.

### Timestamp Discipline
```
// CORRECT — server assigns timestamp on receipt
server_timestamp = Date.now()  // server clock

// WRONG — never trust client-provided timestamps
server_timestamp = request.body.timestamp  // client clock
```

### Session Invalidation
```
On POST /login:
1. Look up existing session token for user
2. DELETE existing session token (if any)
3. Generate new session token (32 bytes CSPRNG)
4. Store new session token
5. Return new session token to client
```

The previously active device will receive a 401 on its next API call. Implement a client-side 401 handler that displays the forced logout message and clears local session state.

### Blob Versioning
The `version` field is a monotonically incrementing integer. Increment on every successful blob upload. This enables future optimistic concurrency control extensions without breaking the current specification.

---

## 8. Password Change Implementation Notes

The password change operation must be atomic from the server's perspective. If the blob upload fails after the auth record is updated, the user's data becomes inaccessible. Implement as a single atomic server operation:

```
PUT /password
{
  new_auth_key_hash: "bcrypt hash",
  new_salt: "hex",
  new_argon2_params: { ... },
  new_blob: "base64 encrypted blob"
}
```

Server should update auth record and blob in a single transaction.

---

## 9. Security Checklist

Before deployment verify:

- [ ] Argon2id parameters meet minimums specified in SPEC Section 3.2
- [ ] Encryption key is never logged, transmitted, or persisted beyond session memory
- [ ] IV is unique per encryption operation
- [ ] Server timestamps used exclusively for sync direction
- [ ] Single session enforcement tested with simultaneous login scenario
- [ ] 401 handler clears session state and displays forced logout message
- [ ] Salt endpoint returns identical response structure for unknown usernames
- [ ] Password change is atomic on server
- [ ] All API endpoints use HTTPS exclusively
- [ ] Session tokens are minimum 32 bytes CSPRNG
- [ ] bcrypt work factor is appropriate for your server hardware (minimum 12 recommended)

---

## 10. Common Implementation Mistakes

**Mistake:** Using client timestamp for sync direction
**Result:** Clock drift causes data overwrites
**Fix:** Server assigns all timestamps on blob receipt

**Mistake:** Storing encryption key in localStorage or IndexedDB
**Result:** Key persists beyond session, increases attack surface
**Fix:** Store encryption key in memory (JavaScript variable/closure) only

**Mistake:** Reusing IV across encryption operations
**Result:** AES-GCM security breaks catastrophically with IV reuse
**Fix:** Generate fresh CSPRNG IV for every encrypt call

**Mistake:** Returning 404 for unknown username on salt endpoint
**Result:** Username enumeration vulnerability
**Fix:** Return dummy salt with identical response structure and timing

**Mistake:** Non-atomic password change
**Result:** Auth updated but old blob retained — user locked out
**Fix:** Single server transaction for auth + blob update

---

## Revision History

| Version | Date | Notes |
|---|---|---|
| 1.0 | 2026-03-10 | Initial release |
