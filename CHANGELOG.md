# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.1] - 2026-05-23

### Security

- **F12 panic shutdown completo del proceso** (Task 1). F12 ahora termina el proceso inmediatamente con `std::process::exit(0)` en vez de regenerar identidad TLS y continuar corriendo. Envía `FLAG_SYSTEM_ALONE` a los peers conectados, cancela todas las tareas, limpia sesiones y known_peers, restaura la terminal y sale. No hay identity rotation.
- **OS hardening multiplataforma** (Task 7). Agregado hardening específico por plataforma:
  - Linux: `setrlimit(RLIMIT_CORE=0)`, `prctl(PR_SET_DUMPABLE=0)`, y verificación de `RLIMIT_MEMLOCK` con warning si es menor a 4096 bytes.
  - macOS: `ptrace(PT_DENY_ATTACH, 0, 0, 0)` para prevenir attach de debugger.
  - Windows: stub documentado; el hardening de core dumps en Windows requiere políticas externas (WER / Group Policy).

### Fixed

- **`save_config` maneja errores con `Result`** (Task 2). `save_config` ahora retorna `Result<(), ConfigError>` en vez de silenciar errores con `let _ =`. Usa `std::fs::File` + `write_all` + `sync_all()` para persistencia robusta. Si falla guardar el display name, se muestra un warning en la TUI sin abortar el programa.
- **`spawn_supervised` simplificado sin unsafe** (Task 4). El helper de supervisión de tareas se simplificó para usar el reporte de panics built-in de Tokio en vez de un wrapper custom con `catch_unwind` y código unsafe.
- **Canales bounded en `event_reader`** (Task 5). Reemplazado `unbounded_channel` por `mpsc::channel(128)` en el lector de eventos del TUI. Si el buffer está lleno, se dropea el evento (no hay panic ni crash).
- **Limpieza de dead code** (Task 9). Eliminados warnings de código no usado; `peer_addr` ahora se usa en logs del timeout checker.

### Added

- **Tests de integración** (Task 3). Agregados 5 tests de integración en `tests/integration_test.rs`:
  - Conexión de 2 peers con la misma frase.
  - Rechazo de peers con frase distinta.
  - Propagación de lista de peers en mesh.
  - Panic shutdown (F12) envía `FLAG_SYSTEM_ALONE` al peer remoto.
  - Persistencia de display name a través de guardar y cargar config.
- **Fuzzing básico con `cargo-fuzz`** (Task 6). Agregados targets de fuzzing en `fuzz/`:
  - `decode_ratchet_frame`: fuzz de decodificación de frames del ratchet.
  - `remove_padding`: fuzz de remoción de padding.
  - `padding_roundtrip`: fuzz roundtrip de `apply_padding` + `remove_padding`.
- **Property tests con `proptest`** (Task 8). Agregados property tests para padding roundtrip, encrypt/decrypt roundtrip del ratchet, y rechazo de ciphertext/aad modificados.

### Changed

- **Documentación actualizada** (Task 10). `README.md`, `docs/USAGE.md`, `docs/SECURITY.md` y `docs/AUDIT.md` actualizados para reflejar los cambios de este release.

## [0.2.0] - 2026-05-20

### Added

- Release inicial con chat P2P encriptado, autenticación deniable, mesh multi-peer, modo pánico con frase señuelo, y UI de terminal.
