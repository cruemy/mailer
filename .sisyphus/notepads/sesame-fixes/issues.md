2026-05-23
- `lsp_diagnostics` for Rust initially failed because `rust-analyzer` was missing from the toolchain; installing the component resolved it.
- The workspace has no Markdown LSP configured, so `docs/SECURITY.md` could not be checked with `lsp_diagnostics`.
- 2026-05-23: `cargo clippy`/`cargo clippy --tests` exit successfully but report pre-existing warnings in production code (`auth.rs`, `protocol.rs`, `ratchet.rs`, `tui.rs`, and test-target dead code through `tests/../src/*`). These were not changed because the proptest task forbids production edits.
- 2026-05-23: Bare `/// ``` ` fences in `src/tui.rs` and `src/peer.rs` caused doctest compilation failures (`unknown start of token: \u{2518}` / `expected item, found '┌'`) until they were changed to `/// ```text `.

- Plan renames required repo-wide grep instead of LSP because `.md` files are unsupported by the configured language servers.
