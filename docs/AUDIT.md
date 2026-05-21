# Sesame External Audit Package

This file defines the review scope required before Sesame can be described as production-secure.

## Audit scope

Review these files as the cryptographic/security core:

- `src/auth.rs` — SPAKE2/Argon2 authentication, transcript proofs, salt exchange.
- `src/crypto.rs` — locked secret ownership, HKDF, Argon2, random generation, X25519 secret wrapper.
- `src/ratchet.rs` — chain evolution, DH ratchet, AEAD usage, replay checks.
- `src/peer.rs` — TLS exporter use, session transcript, wire frame codec, DoS limits.
- `src/protocol.rs` — length limits and padding codec.
- `src/tls.rs` — TLS verifier behavior, certificate-derived peer identity, exporter API.
- `src/session.rs` — session lifetime, duplicate/self rejection, cancellation.
- `src/os_hardening.rs` — core dump and process dumpability mitigation.

## Required audit questions

- Can a captured handshake be used as an offline password oracle?
- Are TLS exporter, peer IDs, salts, X25519 public keys, version, and roles bound to the same transcript?
- Can a frame from one peer/session/direction decrypt in another context?
- Is there any nonce reuse path for ChaCha20-Poly1305?
- Are message numbers, DH epochs, versions, and flags authenticated and rejected on replay/downgrade?
- Can malformed input cause panic, OOM, unbounded CPU, or unbounded task growth?
- Do all long-lived secrets have locked/zeroized ownership or equivalent guarantees?
- Does F12 terminate network/session tasks without sending a protocol-level goodbye?
- Are logs and user-visible errors free of secrets?

## Release gate

Do not mark Sesame production-secure until all critical/high audit findings are fixed or explicitly accepted in `SECURITY.md` with reduced claims.
