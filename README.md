# Sesame

**Sesame** is a peer-to-peer encrypted chat over TLS 1.3 with deniable authentication, traffic obfuscation, and a panic mode. No servers, no central authority — just a shared passphrase and direct connections.

## Features

- **End-to-end encryption** — Double Ratchet algorithm (Signal protocol) on top of TLS 1.3 mTLS
- **Deniable authentication** — Zero-knowledge proof of shared passphrase without revealing it
- **Peer-to-peer** — No servers, no accounts, no infrastructure. Connect directly via IP:port
- **Multi-peer mesh** — Three or more peers in a fully connected mesh. Peer discovery propagates addresses automatically
- **Traffic obfuscation** — Constant-rate dummy traffic, uniform frame padding, memory locking to prevent secrets from swapping to disk
- **Panic mode** — Start with `--decoy` to use a decoy passphrase; the UI shows a clear indicator
- **Encrypted group chat** — Every peer-to-peer link is independently ratcheted; messages are broadcast to all connected peers

## Security

See [`SECURITY.md`](docs/SECURITY.md) for the formal threat model, current guarantees, known production gaps, and operational requirements.

- **TLS 1.3 mutual authentication** with self-signed Ed25519 certificates (generated at each startup, never persisted)
- **Argon2id** for passphrase hashing (memory-hard, resistant to GPU/ASIC attacks)
- **HKDF-SHA256** for key derivation
- **ChaCha20-Poly1305** for authenticated encryption
- **X25519** for elliptic-curve Diffie-Hellman key exchange
- **mlock** on key material (Windows via `VirtualLock`) to prevent memory from being swapped to disk
- **Automatic memory zeroing** via `zeroize` on session keys and secrets

All cryptographic material lives **in RAM only** — nothing is written to disk.

## Build

### Prerequisites

- [Rust](https://rustup.rs/) 1.75+ (stable)

### Compile

```bash
git clone https://github.com/cruemy/mailer.git
cd mailer
cargo build --release
```

The binary will be at `target/release/sesame.exe` (Windows) or `target/release/sesame` (Linux/macOS).

### Run directly

```bash
cargo run --release -- --phrase "your passphrase"
```

For safer local handling, prefer passing the phrase through a file descriptor when possible:

```bash
printf '%s' "your passphrase" | cargo run --release -- --phrase-fd 0
```

## Quick start

### Two people

**Person A** (just listens):

```bash
cargo run --release -- --phrase "secret"
```

**Person B** (connects to A):

```bash
cargo run --release -- --peer 192.168.1.42:9000 --phrase "secret"
```

### Three or more people

Only one person needs to listen; everyone else connects to at least one other peer. Peer discovery propagates the rest.

```bash
# Person 1 (listener)
cargo run --release -- --phrase "secret"

# Person 2 (connects to 1)
cargo run --release -- --peer 192.168.1.42:9000 --phrase "secret"

# Person 3 (connects to 1)
cargo run --release -- --peer 192.168.1.42:9000 --phrase "secret"
```

### Resilience (bidirectional)

For automatic reconnection when anyone disconnects, have every peer point to each other:

```bash
# Each person lists all other known peers
cargo run --release -- --peer 192.168.1.99:9000 --peer 192.168.1.77:9000 --phrase "secret"
```

See [USAGE.md](docs/USAGE.md) for detailed scenarios and CLI reference.

## Windows Firewall

If another peer can't reach you (connection refused / timeout), Windows Firewall is usually the culprit.

**Step 1 — Allow inbound port** (PowerShell as Administrator):

```powershell
New-NetFirewallRule -DisplayName "Sesame P2P" -Direction Inbound -Protocol TCP -LocalPort 9000 -Action Allow
```

This creates a firewall rule allowing TCP traffic on port `9000`. Change the port if you used `--port` with a different value.

**Step 2 — Temporarily disable firewall for diagnostics** (PowerShell as Administrator):

```powershell
Set-NetFirewallProfile -Profile (Get-NetConnectionProfile).NetworkCategory -Enabled False
```

This turns off the firewall **only for your active network profile**. Test the connection; if it works, re-enable with `-Enabled True`. If it still fails with the firewall off, the issue is elsewhere (different subnet, wrong IP, etc.).

**Verify local connectivity:**

```powershell
Test-NetConnection -ComputerName 127.0.0.1 -Port 9000
```

If `TcpTestSucceeded` is `True`, sesame is listening. Then test from the other PC using the listener's IP instead of `127.0.0.1`.

## License

MIT
