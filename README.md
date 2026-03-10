# CSEDS
## Client-Side Encrypted Data Synchronization
<img width="770" height="718" alt="image" src="https://github.com/user-attachments/assets/c8dc867f-b0d2-45cd-b2df-aef580885e21" />

*A server-mediated multi-device sync architecture with client-side key derivation and local credential escrow*

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Version](https://img.shields.io/badge/Version-1.0-green.svg)]()

---

## The Problem

Small startups and independent developers building multi-device applications face an uncomfortable tradeoff:

- **Store user data server-side in plaintext** — simple, but users must trust you completely
- **Pure client-side storage** — no trust required, but no portability across devices
- **Full zero-knowledge architecture** — strong privacy, but complex to implement and painful to recover from forgotten passwords

CSEDS is a practical middle ground designed for real-world constraints.

---

## What CSEDS Does

- User data is **encrypted on the client** before it ever leaves the device
- The server stores only **opaque ciphertext** — it cannot read user content
- The same credentials on any device derive the same encryption key — enabling **seamless multi-device sync**
- A **local credential escrow** on each bootstrapped device enables password recovery without any server-side recovery mechanism
- **Single active session enforcement** eliminates multi-device write conflicts entirely

---

## What CSEDS Does Not Do

- It is not a zero-knowledge proof system
- It does not protect against a compromised client device
- It does not support simultaneous multi-device editing
- It does not provide recovery for truly forgotten credentials on a new device

See [THREAT-MODEL.md](THREAT-MODEL.md) for full details.

---

## Core Design Decisions

### Argon2id for Key Derivation
A single Argon2id invocation produces two independent keys — an auth token for server authentication and an encryption key that never leaves the client. Knowing one does not yield the other.

### AES-256-GCM for Encryption
The entire user data store is serialized, encrypted as a single blob, and stored server-side. Simple, auditable, no per-record complexity.

### Server Timestamps Only
Client clock drift and timezone issues are eliminated by ignoring client timestamps entirely. The server stamps every blob upload — that timestamp is the sole source of sync direction truth.

### Local Credential Escrow
Each device stores cleartext credentials in a separate local IndexedDB after first login. "Forgot password" on a known unlocked device is a simple local read — no server involvement, no email recovery, no support ticket.

### Forced Single Session
Rather than attempting conflict resolution for simultaneous multi-device edits, CSEDS invalidates the previous session when a new login occurs. Clean, simple, well-understood by users from streaming service experience.

---

## Repository Contents

| File | Description |
|---|---|
| [SPEC.md](SPEC.md) | Full technical specification |
| [THREAT-MODEL.md](THREAT-MODEL.md) | Security assumptions and explicit limitations |
| [IMPLEMENTATION.md](IMPLEMENTATION.md) | Language-agnostic implementation guidance |
| [examples/javascript/](examples/javascript/) | JavaScript reference implementation |

---

## Quick Architecture Summary

```
Password → Argon2id → [ Auth Token | Encryption Key ]
                             │               │
                         Server auth    Never leaves client
                             │               │
                         IndexedDB #1 ← Encrypt/Decrypt
                         (user data)         │
                             │          IndexedDB #2
                         Sync blob      (credential escrow)
                             │
                          Server
                      (ciphertext only)
```

---

## Target Use Cases

CSEDS is well-suited for:
- Small-to-medium user data payloads (prompt libraries, notes, settings, preferences)
- Applications where users are privacy-conscious but not threat-model sophisticated
- Startups that want to offer data portability without becoming a trusted data custodian
- Single-user multi-device scenarios

CSEDS is **not** suited for:
- Large dataset synchronization (consider per-record sync architectures instead)
- Collaborative or multi-user shared data
- Regulatory compliance contexts without independent assessment

---

## License

Licensed under the [Apache License 2.0](LICENSE).

The Apache 2.0 license includes an explicit patent grant. Anyone implementing CSEDS receives a license to any patents that might cover this architecture from all contributors.

---

## Author

Published as an open architectural specification. Contributions and implementations welcome via pull request.
