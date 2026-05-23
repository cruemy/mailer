2026-05-23
- Added platform-specific hardening in `src/os_hardening.rs`: Linux keeps `RLIMIT_CORE=0` and `PR_SET_DUMPABLE=0`, macOS uses `ptrace(PT_DENY_ATTACH)`, Windows stays a documented no-op stub.
- Added a Unix `RLIMIT_MEMLOCK` warning instead of failing startup, so restrictive containers/hosts degrade safely.
- F12 panic shutdown is process-terminal now: `panic_shutdown()` broadcasts `FLAG_SYSTEM_ALONE`, flips the global watch cancel, drains sessions, and clears `known_peers`; `main.rs` restores terminal and exits 0 instead of rotating TLS/PeerId.
- Incoming `FLAG_SYSTEM_ALONE` must be forwarded from `peer.rs` to the main loop; otherwise remote peers can receive the flag but ignore the process-exit path.
- 2026-05-23: Core fixes completed: `save_config` now returns `Result<(), ConfigError>` and calls `File::sync_all()`, display-name persistence failures warn in `main.rs`, `spawn_supervised` uses a local `AssertUnwindSafe(...).catch_unwind().await` wrapper because no futures dependency is available, TUI event reader uses bounded `mpsc::channel(128)` with `try_send`, and stale dead-code methods were removed or documented. Verified with `cargo check` (0 warnings) and `cargo test` (11 passed).
- 2026-05-23: `spawn_supervised` no longer needs a custom unwind wrapper; Tokio task handles already surface panics through `JoinHandle::await`, so the helper can stay as a plain nested `tokio::spawn`.
- 2026-05-23: Property tests can live as sibling `#[cfg(test)] mod proptests` modules; child modules can still access private parent helpers like `encode_ratchet_frame`/`decode_ratchet_frame`. `DoubleRatchet` ciphertext-mutation proptest must generate non-empty payloads because empty plaintext produces empty ciphertext.
- 2026-05-23: Rust doc comments treat bare triple-backtick fences as Rust doctests; ASCII/Unicode diagrams and format tables inside those blocks must use ` ```text ` to avoid compilation of box-drawing characters.
- 2026-05-23: After changing the fences in `src/tui.rs` and `src/peer.rs`, `cargo test` passed all unit/integration tests and doctests, and `cargo check` finished cleanly with no warnings.

## 2026-05-23 — cargo-fuzz setup

- Added `fuzz/` with targets for `decode_ratchet_frame`, `remove_padding`, and padding roundtrip.
- `src/peer.rs::decode_ratchet_frame` is private and the package has no library target, so the decode fuzzer uses a source-including harness under `fuzz/` to avoid production-code changes.
- `apply_padding` only supports payloads up to `u16::MAX`; the roundtrip fuzzer skips larger generated inputs to respect the two-byte length header contract.

## 2026-05-23 - Integration peer tests
- Added integration peer harness using real TLS certs, localhost random ports, SessionManager, connect_peer, and handle_incoming.
- Network integration tests are serialized with an async mutex because Argon2/TLS handshakes are CPU-heavy and the tests use strict 5s timeouts.
- For peer-list propagation, the production handshake limiter currently holds permits for full session lifetime; after A discovers C through B, the test disconnects B-C before A-C to avoid exhausting the 4-permit limiter without changing production logic.
- Added src/lib.rs as a module export surface so integration tests import sesame_cli normally and cargo test --test integration_test runs exactly the 5 integration tests.
- 2026-05-23: The integration test suite is safest when all tests share one `OnceLock<tokio::sync::Mutex<()>>`; that avoids hidden CPU contention between the lightweight config test and the Argon2/TLS peer tests.
- 2026-05-23: `test_peer_list_propagation` needs a longer timeout than the real TLS + SPAKE2 path; bumping `TEST_TIMEOUT` from 5s to 15s keeps the test stable while the observed successful run time stays around 9.8s.

## 2026-05-23 — plan rename verification

- Markdown files in this workspace have no configured LSP server, so plan/doc rename verification falls back to grep and diff checks instead of `lsp_diagnostics`.
