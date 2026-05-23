# Fuzzing Sesame

Sesame uses [`cargo-fuzz`](https://github.com/rust-fuzz/cargo-fuzz) for basic libFuzzer coverage of parsing and padding helpers.

## Setup

```sh
cargo install cargo-fuzz
rustup toolchain install nightly
```

## Run

Run each target from the repository root:

```sh
cargo +nightly fuzz run decode_ratchet_frame
cargo +nightly fuzz run remove_padding
cargo +nightly fuzz run padding_roundtrip
```

For a bounded smoke run, pass libFuzzer options after `--`:

```sh
cargo +nightly fuzz run decode_ratchet_frame -- -max_total_time=5
```

The `decode_ratchet_frame` target exercises random bytes against the ratchet frame decoder. `remove_padding` accepts both successful and error results. `padding_roundtrip` checks that `apply_padding(payload)` followed by `remove_padding(...)` recovers the original payload.

Note: the main package currently exposes only a binary target, not a library target, and `decode_ratchet_frame` is private. To keep production code unchanged, fuzz targets import the needed source modules directly from `src/` instead of depending on a public `sesame_cli` library API.
