# Sesame Security Model

This document defines Sesame's security goals, threat model, operational limits, and hardening requirements. It is part of the protocol contract: features are not considered production-ready unless they satisfy this model or explicitly document a deviation.

## Security posture

Sesame aims for high-assurance ephemeral private chat between peers who already share a secret phrase and connect directly over IP. The design prioritizes:

- confidentiality of message contents;
- forward secrecy and post-compromise recovery where the ratchet permits it;
- no server-side trust anchor;
- minimal persistence;
 - rapid local shutdown through F12 (terminates the process immediately);
- reduced metadata leakage through padding and dummy traffic;
- explicit limits instead of implicit “secure by default” claims.

Sesame does not provide absolute security. A fully compromised live host, kernel, terminal, keyboard, or display can still observe secrets or plaintext.

## In scope

Sesame is designed to defend against:

- passive network observers;
- active network attackers attempting MITM, replay, downgrade, or frame mutation;
- peers that know IP:port but do not know the shared phrase;
- malformed network input attempting panics, OOM, or unbounded CPU/memory use;
- post-session disk/swap/core-dump recovery of key material, within OS limits;
 - accidental task leaks after panic shutdown (all Tokio tasks are aborted on F12);
- transcript rebinding between different peers, roles, or sessions.

## Partially in scope

These risks are mitigated but not eliminated:

- weak human phrases;
- a peer compromised after participating in a session;
- local malware without kernel-level control;
- memory disclosure after the process has been running;
- traffic analysis by a global observer;
- denial of service by many distributed IPs.

## Out of scope

Sesame does not claim protection against:

- compromised kernel, hypervisor, firmware, or privileged debugger during execution;
- live physical RAM capture while the app is running;
- compromised keyboard, terminal emulator, shell, screen recorder, clipboard, or display server;
- a coerced user revealing the real phrase;
- peers who legitimately know the phrase and intentionally leak plaintext;
- quantum attackers against current X25519 sessions;
- legal attribution guarantees. Plausible deniability is a protocol goal, not legal advice.

## Current guarantees

The implementation should maintain these properties:

| Property | Current mechanism | Notes |
|---|---|---|
| Transport encryption | TLS 1.3 | Certificates are ephemeral and self-signed. |
| Peer identity for a session | `PeerId = SHA256(cert DER)` | Ephemeral identity only; no long-term identity. |
| Phrase authentication | Argon2id-hardened SPAKE2 + transcript-bound challenge response | Prevents practical offline verification of captured phrase guesses. |
| E2EE message encryption | X25519-derived ratchet + ChaCha20-Poly1305 | Ratchet state is independent per peer. |
| Basic memory hardening | `LockedBytes`/`LockedKey`/`LockedDhSecret` + `mlock` + `zeroize` | Covers phrase bytes, 32-byte session/ratchet keys, and DH private keys. |
| Panic shutdown | F12 requests session cancellation and app exit | F12 terminates the process immediately with `exit(0)`. No identity rotation, no reconnect. |
| Frame allocation limit | `MAX_FRAME_SIZE` | Malformed frame input must fail closed. |
| JSON allocation limit | `MAX_JSON_SIZE` | Applies before deserialization. |

### Platform hardening

| Platform | Core dump hardening | Debugger attach hardening | Memory-lock check |
|---|---|---|---|
| Linux | `setrlimit(RLIMIT_CORE=0)` | `prctl(PR_SET_DUMPABLE=0)` | Warn if `RLIMIT_MEMLOCK < 4096` bytes. |
| macOS | `setrlimit(RLIMIT_CORE=0)` | `ptrace(PT_DENY_ATTACH, 0, 0, 0)` | Warn if `RLIMIT_MEMLOCK < 4096` bytes. |
| Windows | No in-process portable core-dump disable; use WER / Group Policy / external crash-dump policy. | No simple `ptrace` equivalent in this code path; stubbed intentionally. | No `RLIMIT_MEMLOCK`; use platform-specific working-set / policy controls externally. |

## Known gaps before production

These are not optional for a production security claim:

1. **External cryptographic review**
   - Sesame uses a custom protocol composition. It must not be marketed as production-secure before external review of the protocol and implementation. See [`docs/AUDIT.md`](docs/AUDIT.md) for the current audit scope and release gate.

2. **Continuous fuzzing/integration CI**
   - Unit-level adversarial tests and property tests exist, but long-running fuzzing and multi-process peer integration must run in CI before release.

3. **Platform hardening parity**
   - Linux and macOS have core-dump and debugger-attach mitigations. Windows hardening is documented as external-policy driven (WER / Group Policy) with no in-process portable equivalent in this release.

## Operational requirements

For safest operation:

- use high-entropy phrases, not memorable short passwords;
- prefer a hidden prompt or secure file descriptor over `--phrase` once implemented, because CLI arguments may appear in shell history or process listings;
- run on a system with swap disabled or with sufficient `mlock` limits;
- avoid debug logging in real sessions;
- avoid clipboard usage for secrets;
 - press F12 to terminate immediately under pressure (F12 ends the process, it does not rotate identity);
 - restart the app to enter real or decoy mode; F12 never switches mode in-process.

## Failure policy

Security-sensitive code must fail closed:

- unknown protocol version: reject;
- unknown frame flag: reject;
- oversized frame: reject;
- oversized JSON: reject;
- failed authentication: drop connection;
- duplicate session: keep existing session and reject new one;
- self-connection: reject;
- failed AEAD decrypt: drop frame;
- failed `mlock`: warn clearly and continue only if the threat model accepts reduced memory protection.

## Definition of production-ready security

Sesame can only claim production-ready security when all are true:

- `docs/SECURITY.md` and `plans/Genesis.md` agree on guarantees and limits;
- PAKE replaces offline-verifiable phrase authentication;
- phrase, session keys, ratchet chains, skipped keys, message keys, and DH private keys use locked/zeroized ownership or equivalent library guarantees;
- TLS exporter and full transcript binding are enforced;
- all frame-critical metadata is AEAD AAD;
- replay, reorder, stale-DH, downgrade, wrong-peer, and wrong-direction tests pass;
- fuzzers or equivalent adversarial CI run against frame, padding, and parser inputs;
- core dumps/log leaks are mitigated;
- external crypto review has no unresolved critical/high findings.

## What not to do

- Do not invent a custom PAKE.
- Do not implement X25519 arithmetic manually.
- Do not persist identity keys unless the project explicitly changes its ephemeral-identity model.
- Do not log phrases, salts, keys, plaintext, full ciphertext, or transcripts.
- Do not weaken tests to preserve current behavior.
- Do not treat `cargo check` as a security proof.
- Do not claim protection against a compromised live host.
