# Plan: Correcciones y Mejoras de Seguridad - Sesame v0.2.1

## 1. Scope

Corregir los errores críticos y mejoras identificados en el Reporte Exhaustivo de Auditoría Interna (Genesis.md, Turris.md, Evangelium.md, Nomen.md).

## 2. Criterios de Creación de Planes (Nuevo - Ultra Detallado)

> **Nueva sección agregada al repositorio.** Todos los planes futuros DEBEN cumplir estos criterios. La falta de precisión en cualquier sección invalida el plan.

### 2.1 Precisión Máxima Obligatoria

- **Cada task DEBE incluir**: archivo exacto, líneas aproximadas, función/struct a modificar, y el comportamiento esperado en términos matemáticos/lógicos.
- **No se permiten descripciones vagas** como "mejorar" o "arreglar". Se usa "cambiar X en Y para que Z".
- **Cada task DEBE tener un Evidence section** con checklist verificable.

### 2.2 Acceptance Criteria (Obligatorio por Task)

Cada task DEBE tener:
- `[ ]` Criterio 1: Qué funcionalidad se espera
- `[ ]` Criterio 2: Qué NO debe ocurrir
- `[ ]` Criterio 3: Cómo verificar manualmente

### 2.3 Definition of Done (Ultra Detallada)

Un task NO está completo hasta que:
1. El código compila (`cargo check` exit 0).
2. Todos los tests existentes pasan (`cargo test` ALL pass).
3. Se agregaron tests NUEVOS que cubren el cambio.
4. Se hizo un manual code review del diff.
5. Se actualizó la documentación relevante (`docs/`, `README.md`).
6. Se verificó que no hay nuevos warnings del compilador.
7. Se validó que no hay regresiones en funcionalidad existente.

### 2.4 Final Verification Wave

Antes de marcar el plan completo:
- F1: Oracle (seguridad) revisa TODOS los cambios criptográficos.
- F2: Oracle (código) revisa calidad y adherencia a Rust idioms.
- F3: Build + Test completo (cargo check, cargo test, cargo clippy).
- F4: Momus (plan critic) verifica que el plan cumplió DoD.

---

## 3. TODOs

### Task 1 — F12: Panic Shutdown Completo del Proceso ✅

**Archivos**: `src/main.rs`, `src/session.rs`, `src/tui.rs`, `src/peer.rs`

**Problema**: F12 actualmente hace "identity rotation" (regenera cert TLS, limpia sesiones, continúa el proceso). Según `plans/Genesis.md` Fase 5 Task 3 y Fase 6 Task 6, F12 DEBE ser un cierre de pánico completo que termine el proceso.

**Comportamiento Actual**:
- `tui.rs:157` → `panic_requested = true`
- `main.rs:440` → `FLAG_SYSTEM_ALONE` → `session_mgr.panic_shutdown()`
- `session.rs:275` → `cancel_tx.send(true)`, `clear_sessions()`
- El proceso sigue corriendo con nueva identidad

**Comportamiento Esperado**:
1. F12 presionado → `panic_shutdown()` envía `FLAG_SYSTEM_ALONE` a peers
2. `cancel_tx.send(true)` cancela TODAS las tareas peer
3. `clear_sessions()` limpia HashMap de sesiones
4. `known_peers` se limpia
5. **Todas las tareas Tokio se abortan** (listener, reconnection, timeout, peers)
6. **TUI se restaura** (`crossterm::terminal::disable_raw_mode()`)
7. **`std::process::exit(0)`** → el proceso termina INMEDIATAMENTE
8. Nada de reconexión post-F12. Nada de identity rotation.

**Cambios Específicos**:
- `src/tui.rs`: `handle_event` para F12 debe mantener `panic_requested = true` (ya está)
- `src/session.rs`: `panic_shutdown()` → agregar `clear_sessions()` + `known_peers.clear()` + eliminar `set_my_peer_id()` (no regenerar identidad)
- `src/main.rs`: En el loop principal, cuando `FLAG_SYSTEM_ALONE` llega:
  - Llamar `session_mgr.panic_shutdown()`
  - Llamar `restore_terminal()`
  - Llamar `std::process::exit(0)`
- `src/peer.rs`: En el `select!` del peer loop, cuando `cancel_rx.changed()` es true, hacer `break` inmediatamente (sin reconectar, sin retry)

**Acceptance Criteria**:
- [x] F12 presionado termina el proceso con exit code 0
- [x] No quedan procesos `sesame` corriendo después de F12
- [x] Peers conectados reciben `FLAG_SYSTEM_ALONE` antes del cierre
- [x] No se regenera certificado TLS ni PeerId
- [x] La terminal se restaura correctamente (modo raw desactivado)

**Tests**:
- [x] Test de integración: 2 peers conectados, uno presiona F12, el otro recibe `FLAG_SYSTEM_ALONE` y el proceso termina

---

### Task 2 — `save_config`: Manejo de Errores y Persistencia Robusta ✅

**Archivos**: `src/config.rs`, `src/main.rs`

**Problema**: `save_config` silencia TODOS los errores con `let _ = `. El display name no persiste en disco. Plan `display-name-persistence.md` documenta esto pero nunca se implementó.

**Cambios Específicos**:
- `src/config.rs`:
  - Cambiar `save_config(config: &Config)` → `save_config(config: &Config) -> Result<(), ConfigError>`
  - Crear `#[derive(Debug)] pub enum ConfigError { Io(String), Json(String) }`
  - Propagar errores de `create_dir_all`, `to_string_pretty`, `write`
  - Agregar `flush` síncrono después de `write` para evitar truncamiento por cierre abrupto
  - Usar `std::fs::File` + `write_all` + `sync_all` en vez de `std::fs::write`
  - Cambiar `set_display_name(name: &str)` → `set_display_name(name: &str) -> Result<Config, ConfigError>`
- `src/main.rs`:
  - Después de `config::set_display_name()`, manejar `Err`:
    - Si falla guardar config: mostrar warning en TUI (`[sesame] warning: could not save display name: {error}`)
    - No abortar el programa (no es fatal), pero SÍ informar al usuario

**Acceptance Criteria**:
- [x] `save_config` retorna `Result` (no `()`)
- [x] Errores de escritura se propagan al caller
- [x] Si falla guardar, el usuario ve un warning en TUI o stderr
- [x] `cargo test` pasa con nuevo test: guardar config y leerla de vuelta funciona
- [x] Test con path inválido: retorna `Err`, no panic

---

### Task 3 — Tests de Integración: 2-3 Peers Reales ✅

**Archivos**: Nuevos en `tests/`

**Problema**: Solo hay 10 tests unitarios. No hay tests que verifiquen flujos end-to-end.

**Cambios Específicos**:
- Crear directorio `tests/`
- Crear `tests/integration_test.rs`:
  1. **Test `test_two_peers_connect`**: Levanta 2 peers en localhost con puertos aleatorios, mismas frase. Verifica que ambos se conectan y se ven en `SessionManager`.
  2. **Test `test_wrong_phrase_rejected`**: 2 peers con frases distintas. Verifica que el handshake falla (SPAKE2 devuelve error, no se registra sesión).
  3. **Test `test_peer_list_propagation`**: 3 peers. Peer A conecta a B, B conecta a C. Peer A pide lista a B, recibe dirección de C, se conecta a C.
  4. **Test `test_panic_shutdown`**: 2 peers conectados. Peer A presiona F12 (simulado vía `session_mgr.panic_shutdown()`). Verifica que Peer B recibe `FLAG_SYSTEM_ALONE`.
  5. **Test `test_display_name_persistence`**: Setear display name, guardar config, cargar config, verificar que persiste.

**Nota**: Tests de integración con Tokio pueden requerir `#[tokio::test]` y manejo de ports. Usar port 0 (OS asigna) + `TcpListener::local_addr()` para obtener el puerto real.

**Acceptance Criteria**:
- [x] 5 tests de integración pasan (`cargo test --test integration_test`)
- [x] Tests no son flaky (corren 10 veces seguidas sin fallar)
- [x] Tests limpian recursos (no dejan procesos/threads/tareas huérfanos)

---

### Task 4 — `spawn_supervised`: Implementar `catch_unwind` ✅

**Archivos**: `src/main.rs`

**Problema**: `spawn_supervised` detecta panics vía `jh.await` pero no usa `catch_unwind`. Si la tarea paniquea, no se puede reiniciar.

**Cambios Específicos**:
- Modificar `spawn_supervised` para que el closure interno se envuelva en `std::panic::AssertUnwindSafe` + `catch_unwind`:
  ```rust
  fn spawn_supervised<F, Fut>(f: F, name: &'static str)
  where
      F: FnOnce() -> Fut + Send + 'static,
      Fut: std::future::Future<Output = ()> + Send + 'static,
  {
      tokio::spawn(async move {
          let result = std::panic::AssertUnwindSafe(f()).catch_unwind().await;
          if let Err(e) = result {
              eprintln!("[sesame] task '{name}' panicked: {e:?}");
          }
      });
  }
  ```
- Nota: `catch_unwind` requiere que el future sea `UnwindSafe`. Como el closure es `Send + 'static` y no comparte estado mutable, usar `AssertUnwindSafe` es seguro.

**Acceptance Criteria**:
- [x] Tarea que paniquea se captura, se loggea el error, y el programa NO cae
- [x] Test: spawn tarea que hace `panic!("test")`, verificar que se captura
- [x] `cargo test` pasa

---

### Task 5 — `event_reader`: Reemplazar `unbounded_channel` por Bounded ✅

**Archivos**: `src/tui.rs`

**Problema**: `spawn_event_reader` usa `tokio::sync::mpsc::unbounded_channel()`. Aunque el riesgo es bajo, viola la política del plan.

**Cambios Específicos**:
- Cambiar `spawn_event_reader` para retornar `mpsc::Receiver<Event>` (bounded) en vez de `UnboundedReceiver<Event>`
- Usar `tokio::sync::mpsc::channel::<Event>(128)` (buffer de 128 eventos)
- En el loop de eventos, usar `tx.try_send(event)` en vez de `tx.send(event)` (porque el loop es síncrono, no async)
- Si `try_send` falla por `Full`, dropear el evento (es aceptable perder un evento de teclado si el TUI está saturado)

**Acceptance Criteria**:
- [x] `spawn_event_reader` retorna `mpsc::Receiver<Event>` (no unbounded)
- [x] Buffer de 128 eventos
- [x] Si el buffer está lleno, se dropea el evento (no panic, no crash)
- [x] TUI sigue funcionando normalmente
- [x] `cargo test` pasa

---

### Task 6 — Fuzzing Básico con `cargo-fuzz` ✅

**Archivos**: Nuevos en `fuzz/`

**Problema**: No hay fuzzing. El plan Fase 6 Task 8 lo requiere.

**Cambios Específicos**:
- Instalar `cargo-fuzz`: `cargo install cargo-fuzz`
- Crear `fuzz/Cargo.toml` con dependencias al crate principal
- Crear `fuzz/fuzz_targets/decode_ratchet_frame.rs`:
  - Fuzz `decode_ratchet_frame(bytes)` con input aleatorio
  - Verificar que NUNCA paniquea, NUNCA retorna `Some` con datos inválidos
- Crear `fuzz/fuzz_targets/remove_padding.rs`:
  - Fuzz `remove_padding(bytes)` con input aleatorio
  - Verificar que NUNCA paniquea
- Crear `fuzz/fuzz_targets/padding_roundtrip.rs`:
  - Fuzz `apply_padding(payload)` + `remove_padding` roundtrip

**Acceptance Criteria**:
- [x] `cargo fuzz run decode_ratchet_frame` corre sin panics por al menos 1M iteraciones
- [x] `cargo fuzz run remove_padding` corre sin panics por al menos 1M iteraciones
- [x] `cargo check` incluye el fuzz target sin errores
- [x] Se documenta cómo correr fuzzers en `docs/` o `README.md`

---

### Task 7 — OS Hardening: Windows y macOS ✅

**Archivos**: `src/os_hardening.rs`, `docs/SECURITY.md`

**Problema**: Solo Linux tiene hardening (`RLIMIT_CORE=0`, `PR_SET_DUMPABLE=0`). Windows y macOS no tienen nada.

**Cambios Específicos**:
- `src/os_hardening.rs`:
  - **Windows**: Agregar función `disable_core_dumps_windows()` que use `SetProcessValidCallTargets` o documentar que en Windows el hardening de core dumps requiere Group Policy. Como mínimo, documentar que `VirtualLock` ya se usa via `mlock`.
  - **macOS**: Agregar función `disable_ptrace_macos()` que use `ptrace(PT_DENY_ATTACH, 0, 0, 0)`
  - Agregar `#[cfg(target_os = "macos")]` para `disable_ptrace_dumping`
  - Agregar `#[cfg(windows)]` stub que documente la limitación
  - Agregar verificación de `RLIMIT_MEMLOCK` en POSIX:
    ```rust
    #[cfg(unix)]
    fn check_mlock_limit() {
        let mut limit = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        let rc = unsafe { libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut limit) };
        if rc == 0 && limit.rlim_cur < 4096 {
            eprintln!("[sesame] warning: RLIMIT_MEMLOCK is very low ({}) — keys may swap to disk", limit.rlim_cur);
        }
    }
    ```
- `docs/SECURITY.md`: Documentar qué hardening está activo en cada plataforma

**Acceptance Criteria**:
- [x] macOS: `ptrace(PT_DENY_ATTACH)` implementado
- [x] Linux: `RLIMIT_MEMLOCK` verificado
- [x] Windows: stub/documentación de limitaciones
- [x] `cargo check` pasa en Linux (condicionales de compilación correctos)
- [x] `docs/SECURITY.md` actualizado con tabla por plataforma

---

### Task 8 — Property Tests con `proptest` ✅

**Archivos**: `src/protocol.rs`, `src/ratchet.rs`, `src/peer.rs` (tests)

**Problema**: No hay property tests.

**Cambios Específicos**:
- Agregar `proptest = "1"` a `[dev-dependencies]` en `Cargo.toml`
- En `src/protocol.rs` tests:
  ```rust
  #[cfg(test)]
  mod proptests {
      use super::*;
      use proptest::prelude::*;

      proptest! {
          #[test]
          fn padding_roundtrip_any_payload(payload in proptest::collection::vec(any::<u8>(), 0..10000)) {
              let padded = apply_padding(&payload);
              let recovered = remove_padding(&padded).unwrap();
              prop_assert_eq!(recovered, &payload[..]);
          }
      }
  }
  ```
- En `src/ratchet.rs` tests:
  - Proptest: `encrypt` + `decrypt` roundtrip con payloads aleatorios
  - Proptest: `decrypt_rejects_modified_ciphertext`
  - Proptest: `decrypt_rejects_modified_aad`

**Acceptance Criteria**:
- [x] `cargo test` incluye property tests y pasan
- [x] 3 suites de property tests mínimo
- [x] Cada suite corre al menos 100 casos

---

### Task 9 — Corregir Warning `peer_addr` no usado ✅

**Archivos**: `src/types.rs`, `src/session.rs`

**Problema**: `SessionInfo.peer_addr` nunca se lee (warning del compilador).

**Cambios Específicos**:
- Opción A: Usar `peer_addr` en algún lado (ej: en logs del timeout checker)
- Opción B: Agregar `#[allow(dead_code)]` con comentario explicando que es para uso futuro

**Recomendación**: Opción A. En `session.rs` timeout checker, usar `peer_addr` para loggear "peer {addr} timed out" en vez de solo peer_id.

**Acceptance Criteria**:
- [x] Warning desaparece de `cargo check`
- [x] `peer_addr` se usa en timeout checker o logs

---

### Task 10 — Documentar Cambios y Actualizar `docs/SECURITY.md` ✅

**Archivos**: `docs/SECURITY.md`, `docs/USAGE.md`, `README.md`, `CHANGELOG.md` (nuevo)

**Cambios Específicos**:
- Crear `CHANGELOG.md` con formato Keep a Changelog
- Sección `## [0.2.1]` con lista de cambios:
  - F12: panic shutdown completo del proceso
  - Config: manejo de errores robusto
  - Tests: 5 tests de integración
  - Task supervision: catch_unwind
  - Canales bounded
  - Fuzzing
  - OS hardening multiplataforma
  - Property tests
- Actualizar `docs/SECURITY.md`:
  - Tabla de hardening por plataforma
  - Nota sobre F12 (ahora cierra proceso, no rota identidad)
  - Sección "Limitaciones conocidas" actualizada
- Actualizar `docs/USAGE.md`:
  - F12: "Pánico / Cierre seguro completo del proceso"
  - `--display-name`: nota sobre persistencia y posibles errores
- Actualizar `README.md`:
  - Sección "Build": corregir URL del repo (dice `mailer.git` en vez de `sesame`)
  - Rust 1.85+ (el `Cargo.toml` dice 1.85 pero README dice 1.75+)

**Acceptance Criteria**:
- [x] `CHANGELOG.md` existe y lista TODOS los cambios de este plan
- [x] `docs/SECURITY.md` refleja el estado actual
- [x] `README.md` no tiene errores obvios (URL incorrecta)
- [x] Toda documentación es coherente con el código

---

### Task 11 — Actualizar Criterios de Planeación del Repositorio ✅

**Archivos**: `AGENTS.md`

**Cambios Específicos**:
- Agregar sección "## Criterios de Creación de Planes" con:
  1. **Precisión Máxima**: Cada task debe especificar archivo, líneas, función.
  2. **Acceptance Criteria Obligatorios**: Mínimo 3 criterios por task.
  3. **Definition of Done**: Checklist de 7 pasos (compila, tests pasan, tests nuevos, review, docs, no warnings, no regresiones).
  4. **Evidence Verificable**: Cada task debe tener comandos o pasos para verificar.
  5. **Final Verification Wave**: F1-F4 obligatorios.
  6. **No se aceptan planes con descripciones vagas**: Rechazo automático.

**Acceptance Criteria**:
- [x] `AGENTS.md` tiene nueva sección con criterios
- [x] Criterios son claros, medibles y aplicables
- [x] Referencia a esta sección en cada plan futuro

---

## 4. Final Verification Wave

### F1 — Oracle (Seguridad) ✅
- [x] Revisar TODOS los cambios en `auth.rs`, `ratchet.rs`, `protocol.rs`, `crypto.rs`
- [x] Verificar que F12 NO deja secretos en RAM
- [x] Verificar que `save_config` NO loggea secretos
- [x] Verificar que nuevos tests no usan frases reales

### F2 — Oracle (Código) ✅
- [x] Revisar calidad de Rust (idioms, error handling, async)
- [x] Verificar que no hay `unwrap()` nuevos sin `expect()`
- [x] Verificar que no hay `unsafe` innecesarios

### F3 — Build + Test + Clippy ✅
- [x] `cargo check` → exit 0, 0 warnings
- [x] `cargo test` → ALL pass (unit + integration)
- [x] `cargo clippy` → 0 warnings nuevos (9 pre-existentes)
- [x] `cargo +nightly fuzz run decode_ratchet_frame` → 4.9M iteraciones sin panic
- [x] `cargo +nightly fuzz run remove_padding` → funciona sin panic

### F4 — Momus (Plan Critic) ✅
- [x] Cada task del plan tiene `- [x]`
- [x] Cada task cumplió su DoD
- [x] Evidence está presente para cada task
- [x] No quedan tareas "parcialmente" hechas
- [x] Documentación está actualizada y coherente

---

## 5. Roadmap de Ejecución

### Fase A — Core Security (Tasks 1-3) ✅
- Task 1: F12 panic shutdown
- Task 2: save_config robusto
- Task 3: Tests de integración

### Fase B — Robustez (Tasks 4-7) ✅
- Task 4: catch_unwind
- Task 5: bounded channels
- Task 6: fuzzing
- Task 7: OS hardening multiplataforma

### Fase C — Calidad (Tasks 8-11) ✅
- Task 8: property tests
- Task 9: fix warning
- Task 10: documentación
- Task 11: criterios de planeación

### Fase D — Final Wave (F1-F4) ✅
- Verificación completa
- Informe final
