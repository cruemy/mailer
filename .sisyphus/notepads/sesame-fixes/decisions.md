2026-05-23
- Chose to keep hardening best-effort: warn on missing `RLIMIT_MEMLOCK` or unsupported platform controls rather than aborting process startup.
- Documented Windows hardening as external-policy driven (WER / Group Policy / crash-dump policy) instead of adding a dependency-heavy in-process solution.
- Replaced the previous F12 identity-rotation behavior with a full panic shutdown: no TLS certificate or PeerId regeneration on F12/`FLAG_SYSTEM_ALONE`; terminal restoration happens immediately before `std::process::exit(0)`.
- Simplified `spawn_supervised` to rely on Tokio's built-in panic reporting instead of the custom `CatchUnwind` future wrapper, removing unnecessary unsafe code.

## 2026-05-23 — fuzz harness import decision

- Kept production source unchanged per task constraint. Because `sesame_cli` is currently binary-only and `decode_ratchet_frame` is private, `fuzz/fuzz_targets/decode_ratchet_frame.rs` includes the required `src/` modules and exposes a local wrapper inside the harness module instead of adding `src/lib.rs` or changing visibility.

## 2026-05-23 — integration test serialization

- Collapsed the integration test sync points to one shared `OnceLock<tokio::sync::Mutex<()>>` so every test in `tests/integration_test.rs` runs one-at-a-time. This keeps the suite from competing for CPU during Argon2/TLS-heavy setup and removed the `test_peer_list_propagation` flake.

## 2026-05-23 — plan naming convention

- Standardized plan filenames to one-word biblical/Latin names (`Genesis`, `Turris`, `Evangelium`, `Nomen`, `Purgatio`) and updated `AGENTS.md` to treat that pattern as the repo convention.
