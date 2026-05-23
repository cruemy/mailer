
## 2026-05-23 — Evangelium/Turris analysis report

- Created `report.md` comparing `plans/Evangelium.md` and `plans/Turris.md` against current Genesis code.
- Key finding: both plans are the same architecture under different names; recommended fusion as `DiscoveryService`/`src/discovery.rs` with Turris security/timeout/API details.
- Critical implementation gotcha: `FLAG_CONN_REQUEST/ACCEPT/REJECT` cannot safely reuse values 8/9 because current `src/types.rs` already uses 8 for GOODBYE and 9 for DISPLAY_NAME.
- Critical protocol gotcha: connection request/accept/reject happens before PAKE/Double Ratchet, so it should be a TLS pre-auth control frame, not a normal post-ratchet `ChatMessage` flag.
- Verification: report structure validated at 1002 lines; `cargo check` passed; `cargo test` passed; `cargo clippy` exited with pre-existing warnings in untouched code.
