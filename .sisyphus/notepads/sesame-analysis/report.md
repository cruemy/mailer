# Informe técnico: Evangelium vs Turris contra Sesame Genesis v0.2.1

## Alcance y fuentes verificadas

Este informe compara los planes `plans/Evangelium.md` y `plans/Turris.md` contra el codebase actual de Sesame.

Fuentes leídas completas o por rangos relevantes:

- `plans/Evangelium.md`: 538 líneas, leído desde línea 1 hasta fin.
- `plans/Turris.md`: 755 líneas, leído desde línea 1 hasta fin.
- `src/main.rs`: estructura principal, CLI, listener, reconexión, loop TUI.
- `src/session.rs`: `SessionManager`, `SessionHandle`, broadcast, known peers, frase global.
- `src/tui.rs`: `TuiState`, layout, input, peer list, envío por broadcast.
- `src/peer.rs`: `connect_peer`, `handle_incoming`, `run_peer_session`, mesh peer-list.
- `src/types.rs`: flags actuales, `PeerId`, `PeerAddr`.
- `src/protocol.rs`: framing/padding reutilizable.
- `src/auth.rs`: `perform_handshake(stream, phrase, role, ...)`.
- `src/crypto.rs`, `src/ratchet.rs`, `src/tls.rs`: evidencia para reutilización sin colisiones estructurales.

Convención de referencias:

- Las líneas son las observadas durante la lectura en esta sesión.
- Cuando se cita un rango, se cita archivo + líneas aproximadas y símbolo afectado.
- No se modifica ningún plan; este archivo es un análisis en notepad.

---

# Sección 1: Resumen Ejecutivo

## 1.1 Qué propone Evangelium en 3 líneas

1. `Evangelium.md` propone convertir Sesame de mesh grupal con `--phrase` global a descubrimiento LAN por UDP multicast, chats 1:1 independientes y frase ingresada al conectar (`plans/Evangelium.md:3-5`, `21-30`).
2. Añade `DiscoveryService` sobre `239.255.0.42:42069`, heartbeat cada 10 segundos, timeout de peer a los 30 segundos y flags `FLAG_CONN_REQUEST/ACCEPT/REJECT` (`Evangelium:34-68`, `127-134`, `219-244`, `246-262`).
3. Replantea la TUI como sidebar izquierda + chat activo, reemplaza broadcast por `send_to(peer_id, data)` y mueve la frase desde `SessionManager` a un `ChatState` por peer (`Evangelium:137-176`, `180-205`, `264-323`).

## 1.2 Qué propone Turris en 3 líneas

1. `Turris.md` propone el mismo salto conceptual: discovery/sniffing LAN por UDP multicast, múltiples chats 1:1 y frase secreta por conexión (`plans/Turris.md:1-3`, `22-70`).
2. Define `SniffService`, `SniffedPeerInfo`, `ConnectionState`, flujo `FLAG_CONN_REQUEST/ACCEPT/REJECT`, timeout de frase entrante de 60 segundos y eliminación del broadcast grupal (`Turris:75-179`, `183-267`, `501-528`, `606-634`).
3. Detalla con más precisión el refactor de `SessionManager`, `peer.rs`, `main.rs`, `tui.rs`, docs, tests, tradeoffs y definición de terminado (`Turris:351-473`, `477-558`, `638-755`).

## 1.3 Diferencias clave entre ambos

| Eje | Evangelium | Turris | Impacto técnico |
|---|---|---|---|
| Nombre del servicio LAN | `DiscoveryService` en `src/discovery.rs` (`Evangelium:219-244`) | `SniffService` en `src/sniff.rs` (`Turris:161-179`, `642-644`) | Duplican propósito; debe quedar un solo módulo. |
| Magic heartbeat | `"sesame-v1"` (`Evangelium:49-55`) | `"sesame-sniff-v1"` (`Turris:99-105`) | Incompatibles si se implementan literal. |
| CLI discovery | Explicita `--discovery-port` y `--no-discovery` (`Evangelium:80-85`) | No lista esos flags en cambios por archivo; sí dice que `--phrase`/`--peer` ya no son obligatorios (`Turris:68-69`, `548-557`) | Evangelium cubre mejor operabilidad CLI. |
| Seguridad de discovery/sniff | Amenaza de suplantación mitigada por SPAKE2 (`Evangelium:399-415`) | Amenazas más específicas: heartbeat falso, DoS, escucha pasiva, límite interno 50 (`Turris:143-159`) | Turris cubre mejor threat model. |
| Modelo de chat interno | `ChatState` reemplaza `SessionHandle`, pero el struct de ejemplo no incluye `sender`/`cancel_notify` (`Evangelium:186-196`) | `Chat` contiene `handle: SessionHandle`, `messages`, `state`, `phrase` (`Turris:410-416`) | Turris es más implementable con el código actual. |
| Handshake entrante | Receptor pausa handshake, TUI pide frase (`Evangelium:281-292`) | `handle_incoming` deja de ser fire-and-forget, notifica TUI, espera respuesta o timeout 60s (`Turris:501-528`) | Turris especifica el problema async con más detalle. |
| UI | Más pantallas mockup completas (`Evangelium:327-395`) | Más tabla de navegación e input modes internos (`Turris:288-383`) | Complementarios. |
| Roadmap | Fases con horas por tarea (`Evangelium:425-471`) | Fases, tests y Definition of Done más estrictos (`Turris:655-755`) | Turris tiene mejor cierre verificable. |

## 1.4 Veredicto ejecutivo

**Veredicto:** los planes son **duplicados competitivos con contenido complementario**, no dos features independientes.

- Son duplicados porque ambos cambian las mismas piezas: UDP multicast LAN, frase por conexión, sidebar izquierda, multi-chat 1:1, `ConnectionState`, flags `FLAG_CONN_*`, eliminación de broadcast y refactor de `SessionManager`.
- Son competitivos porque proponen nombres incompatibles para el mismo servicio (`DiscoveryService` vs `SniffService`) y archivos nuevos alternativos (`src/discovery.rs` vs `src/sniff.rs`).
- Son complementarios en detalle: **Evangelium** aporta mejor CLI y mockups; **Turris** aporta mejor seguridad, timeout, DoD y refactor interno.

**Recomendación:** fusionarlos en un único plan canónico. Mantener el nombre técnico `DiscoveryService`/`src/discovery.rs` por claridad, absorber los detalles de seguridad/timeout/API/DoD de Turris, y no implementar ambos por separado.

---

# Sección 2: Arquitectura Actual (Genesis) vs. Propuesta

## 2.1 Arquitectura actual Genesis v0.2.1

Evidencia primaria:

- `main.rs` parsea `--phrase` y `--phrase-fd` (`src/main.rs:121-132`).
- `main.rs` exige frase no vacía y sale con error si falta (`src/main.rs:183-187`).
- `main.rs` crea `LockedBytes` global (`src/main.rs:195-202`).
- `main.rs` pasa esa frase global a `SessionManager::new(...)` (`src/main.rs:244-251`).
- `SessionManager` guarda `phrase: LockedBytes` y `sessions: Mutex<HashMap<PeerId, SessionHandle>>` (`src/session.rs:69-82`).
- `TuiState::handle_event` envía cada mensaje con `session_mgr.broadcast(&data)` (`src/tui.rs:123-139`).
- `peer.rs::run_peer_session` llama a `perform_handshake(..., session_mgr.phrase(), ...)` (`src/peer.rs:445-460`).
- El mesh discovery actual usa `FLAG_PEER_LIST_REQ` y `FLAG_PEER_LIST_RES` (`src/types.rs:61-63`, `src/peer.rs:601-615`, `695-727`).

Diagrama actual:

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│                              Genesis actual                                 │
├─────────────────────────────────────────────────────────────────────────────┤
│ CLI                                                                         │
│   sesame --peer IP:PORT --phrase "secreto"                                  │
│   main.rs exige phrase: src/main.rs:183-187                                  │
│                                                                             │
│ TLS identidad efímera                                                        │
│   tls::generate_cert() -> PeerId                                             │
│                                                                             │
│ SessionManager                                                              │
│   sessions: HashMap<PeerId, SessionHandle>                                   │
│   phrase: LockedBytes  ──────────────────────┐                              │
│   known_peers: HashMap<PeerId, PeerAddr>      │                              │
│   discovery_tx: mpsc::Sender<PeerAddr>        │                              │
│   broadcast(data) -> todos                    │                              │
│                                                │                              │
│ peer.rs                                        ▼                              │
│   connect_peer(addr, session_mgr, connector)                                  │
│   handle_incoming(tls_stream, addr, session_mgr)                              │
│   run_peer_session(...): perform_handshake(session_mgr.phrase())              │
│   FLAG_PEER_LIST_REQ/RES propaga peers conectados por el mesh                 │
│                                                                             │
│ TUI                                                                         │
│   Un solo Vec<(PeerId, String, u8)>                                           │
│   Chat 75% izquierda + Mode/Peers 25% derecha                                 │
│   Enter => broadcast al grupo                                                 │
└─────────────────────────────────────────────────────────────────────────────┘
```

## 2.2 Arquitectura propuesta por Evangelium

Evidencia primaria:

- Discovery UDP multicast en `239.255.0.42:42069`, heartbeat 10s, timeout 30s (`Evangelium:34-68`).
- Nuevos flags `FLAG_CONN_REQUEST = 8`, `FLAG_CONN_ACCEPT = 9`, `FLAG_CONN_REJECT = 10` (`Evangelium:127-134`, `246-251`).
- `ConnectionState` con `Discovered`, `Connecting`, `AwaitingPhrase`, `Handshaking`, `Connected`, `Disconnected` (`Evangelium:253-261`).
- `ChatState` por `PeerId`, mensajes propios, estado y frase temporal (`Evangelium:184-196`).
- Eliminación de broadcast global: `send_to(peer_id, data)` (`Evangelium:198-205`, `268-279`).
- Nuevo `src/discovery.rs` con `DiscoveryService`, `DiscoveredPeer`, `DiscoveredPeerState` (`Evangelium:219-244`).
- TUI sidebar izquierda 30% y chat 70%, input dinámico de frase (`Evangelium:137-176`, `298-313`, `327-395`).

Diagrama Evangelium:

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│                         Evangelium propuesto                                │
├─────────────────────────────────────────────────────────────────────────────┤
│ CLI                                                                         │
│   sesame                                                                    │
│   --phrase opcional                                                         │
│   --discovery-port N                                                        │
│   --no-discovery                                                            │
│                                                                             │
│ src/discovery.rs                                                            │
│   DiscoveryService                                                          │
│   UDP multicast 239.255.0.42:42069                                          │
│   heartbeat JSON { magic: "sesame-v1", port, peer_id, ip }                  │
│   peers: HashMap<PeerId, DiscoveredPeer>                                     │
│                                                                             │
│ TUI                                                                         │
│   Sidebar izquierda: ● ○ ◇ → !                                               │
│   Usuario selecciona peer -> input "Secret phrase"                           │
│                                                                             │
│ SessionManager                                                              │
│   chats: HashMap<PeerId, ChatState>                                          │
│   NO phrase global                                                           │
│   send_to(peer_id, data)                                                     │
│   set_chat_phrase(peer_id, phrase)                                           │
│                                                                             │
│ peer.rs                                                                      │
│   connect_peer(..., phrase)                                                  │
│   FLAG_CONN_REQUEST / ACCEPT / REJECT                                        │
│   perform_handshake(phrase_del_chat)                                         │
└─────────────────────────────────────────────────────────────────────────────┘
```

## 2.3 Arquitectura propuesta por Turris

Evidencia primaria:

- `SniffService` con `peers: Arc<Mutex<HashMap<PeerId, SniffedPeer>>>` y API `start`, `get_peers`, `stop` (`Turris:161-179`).
- Misma dirección/puerto/intervalo/timeout: `239.255.0.42`, `42069`, 10s, 30s (`Turris:88-95`).
- Heartbeat JSON con `magic: "sesame-sniff-v1"` (`Turris:97-105`).
- Seguridad de sniffing: spoofing mitigado por SPAKE2, DoS mitigado por socket no bloqueante y mapa límite 50, exposición solo IP/puerto/peer_id temporal (`Turris:135-159`).
- `handle_incoming` debe notificar TUI, esperar frase/rechazo o timeout 60s (`Turris:501-528`).
- `SessionManager` después: `chats: HashMap<PeerId, Chat>`, `Chat { handle, messages, state, phrase }` (`Turris:387-423`).
- Nuevo event loop con teclado, mensajes, conn_req y conn_response (`Turris:560-602`).

Diagrama Turris:

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│                         Turris / Sniff propuesto                            │
├─────────────────────────────────────────────────────────────────────────────┤
│ CLI                                                                         │
│   sesame                                                                    │
│   --phrase ya NO obligatorio                                                │
│   --peer ya NO obligatorio                                                  │
│                                                                             │
│ src/sniff.rs                                                                │
│   SniffService                                                              │
│   UDP multicast 239.255.0.42:42069                                          │
│   heartbeat JSON { magic: "sesame-sniff-v1", peer_id, ip, port }            │
│   get_peers() -> Vec<SniffedPeerInfo>                                        │
│                                                                             │
│ TUI                                                                         │
│   active_chat: Option<PeerId>                                                │
│   chats: HashMap<PeerId, Vec<...>>                                           │
│   sniffed_peers: Vec<SniffedPeerInfo>                                        │
│   focus: SniffBar | Chat | Input                                             │
│   input_mode: Message | Phrase(PeerId) | ConnRequest(PeerId)                 │
│                                                                             │
│ SessionManager                                                              │
│   chats: HashMap<PeerId, Chat>                                               │
│   Chat contiene SessionHandle + messages + state + phrase                    │
│   send_to(), set_phrase(), take_phrase(), close_chat()                       │
│                                                                             │
│ peer.rs                                                                      │
│   handle_incoming: no fire-and-forget; espera respuesta del usuario          │
│   timeout frase entrante: 60s                                                │
│   sin FLAG_PEER_LIST_REQ automático                                          │
└─────────────────────────────────────────────────────────────────────────────┘
```

## 2.4 Comparativa lado a lado

| Componente | Genesis actual | Evangelium | Turris | Decisión recomendada |
|---|---|---|---|---|
| Descubrimiento inicial | Manual `--peer`; propagación mesh con `FLAG_PEER_LIST_REQ/RES` (`main.rs:352-356`, `peer.rs:601-615`, `695-727`) | `DiscoveryService` UDP multicast | `SniffService` UDP multicast | Unificar como `DiscoveryService` con detalles de Turris. |
| Frase | Global en CLI y `SessionManager.phrase` (`main.rs:183-202`, `session.rs:69-82`) | Por conexión en `ChatState` | Por conexión en `Chat.phrase` | Eliminar global; guardar `Option<LockedBytes>` por chat solo hasta handshake. |
| Topología | Mesh grupal; join/leave; broadcast | 1:1 multi-chat | 1:1 multi-chat | 1:1; no grupos en esta fase. |
| Envío de mensajes | `broadcast()` / `broadcast_except()` (`session.rs:295-319`) | `send_to(peer_id, data)` | `send_to(peer_id, data)` | Implementar `send_to` y limitar broadcast a apagado/pánico si aún aplica. |
| TUI | Un `messages: Vec`; chat único; peers a la derecha (`tui.rs:49-58`, `171-203`, `298-325`) | Sidebar izquierda, input dinámico, mockups | Sidebar izquierda, focus/input modes | Fusionar: estados internos de Turris + mockups de Evangelium. |
| Handshake | `perform_handshake(session_mgr.phrase())` (`peer.rs:445-460`) | `connect_peer` recibe frase | `take_phrase(peer_id)` o parámetro | Mejor: `take_phrase(peer_id)` y pre-auth control frame explícito. |
| Control de conexión | No existe `FLAG_CONN_*`; flags 8/9 ocupados (`types.rs:72-75`) | Define 8/9/10 | Define 8/9/10 | No usar 8/9; crear valores no usados o enum separado pre-auth. |
| Docs | `USAGE.md`, `SECURITY.md` actuales no leídos en detalle | Actualizar `USAGE.md` | Actualizar `USAGE.md` + `SECURITY.md` | Actualizar ambos por cambio de UX y threat model. |

---

# Sección 3: Análisis de Colisiones con Código Actual

## 3.0 Mapa del código actual relevante

| Archivo | Símbolos actuales | Evidencia | Rol actual |
|---|---|---|---|
| `src/main.rs` | `main`, `spawn_supervised`, `apply_keepalive`, `read_phrase_fd` | LSP: `main` línea 72; `apply_keepalive` línea 497; `read_phrase_fd` línea 520 | Orquesta CLI, TLS, listener, reconexión, discovery mesh, TUI. |
| `src/session.rs` | `SessionHandle`, `SessionManager` | LSP: struct `SessionHandle` línea 24; `SessionManager` línea 49 | Estado central de sesiones, frase global, broadcast y peers conocidos. |
| `src/tui.rs` | `TuiState`, `render`, `handle_event` | LSP: `TuiState` línea 37; `handle_event` línea 110; `render` línea 171 | UI de chat único + lista derecha de peers conectados. |
| `src/peer.rs` | `connect_peer`, `connect_peers`, `handle_incoming`, `run_peer_session` | LSP: `connect_peer` línea 243; `handle_incoming` línea 329; `run_peer_session` línea 394 | Conexiones TCP/TLS, PAKE, ratchet, mesh peer-list, dummy traffic. |
| `src/types.rs` | `ChatMessage`, `PeerId`, `PeerAddr`, flags | `types.rs:30-75`, `90-163` | Modelo común serializable y flags wire actuales. |
| `src/auth.rs` | `perform_handshake` | `auth.rs:91-98` | Ya acepta `phrase: &[u8]`, por eso no requiere refactor criptográfico. |
| `src/protocol.rs` | `read_frame`, `write_frame`, padding | `protocol.rs:28-87` | Reutilizable para control frames sobre TLS pre-ratchet si se diseña explícito. |

## 3.1 Colisiones de Evangelium con código actual

### 3.1.1 Colisiones MAYORES — Evangelium

| Área | Código actual | Propuesta Evangelium | Colisión concreta | Gravedad |
|---|---|---|---|---|
| `SessionManager` frase global | `phrase: LockedBytes` en `src/session.rs:69-82`; constructor recibe `phrase` en `97-104`; getter `phrase()` en `371-374` | Eliminar `phrase`, mover a `ChatState` (`Evangelium:268-279`) | Rompe constructor usado en `main.rs:244-251`, tests en `session.rs`, y `peer.rs:451-454` | Mayor |
| Unidad de sesión | `sessions: HashMap<PeerId, SessionHandle>` con sender/cancel/last_message (`session.rs:69-82`, `SessionHandle` en `40-47`) | `HashMap<PeerId, ChatState>` (`Evangelium:186-196`) | El ejemplo de `ChatState` no incluye `sender`, `cancel_notify`, `connected_since`, `last_message`; si reemplaza literalmente, se pierde capacidad de enviar/cancelar/timeout | Mayor |
| Broadcast | `TuiState::handle_event` llama `session_mgr.broadcast(&data)` (`tui.rs:123-139`); `panic_shutdown` también (`session.rs:256-267`) | Eliminar `broadcast()` / `broadcast_except()` (`Evangelium:276-278`) | Debe reescribirse envío desde TUI, GOODBYE, JOIN/LEAVE, panic y cierre de sesión | Mayor |
| TUI estado único | `TuiState` tiene `messages: Vec`, `input`, `my_id`, `session_mgr`, flags quit/panic, scroll (`tui.rs:49-58`) | `MultiChatState`, `active_chat`, sidebar, input dinámico (`Evangelium:298-313`) | Requiere rediseño integral de estado, render y eventos | Mayor |
| Layout TUI | Layout horizontal 75/25 con mode + peers a la derecha (`tui.rs:171-203`) | Sidebar izquierda 30% + chat 70% (`Evangelium:137-154`, `302`) | Cambia todos los `Rect` y renderizadores | Mayor |
| Handshake entrante | `main.rs` acepta TLS y lanza `tokio::spawn(peer::handle_incoming(...))` (`main.rs:268-296`); `handle_incoming` delega directo a `run_peer_session` (`peer.rs:340-356`) | Receptor pausa handshake, notifica TUI, pide frase (`Evangelium:287-291`) | El handler entrante actual no tiene canal para bloquear hasta input TUI ni timeout de respuesta | Mayor |
| Pre-auth request | `ChatMessage` se procesa después de ratchet en `peer.rs:678-742` | `FLAG_CONN_REQUEST` antes de handshake (`Evangelium:103-120`, `287-291`) | Circularidad: no se puede enviar `ChatMessage` cifrado con ratchet antes de `perform_handshake` y ratchet | Mayor |
| `main.rs` CLI | `--phrase` obligatorio (`main.rs:183-187`) | `--phrase` opcional; discovery sin args (`Evangelium:317-320`) | Cambia flujo de arranque, decoy phrase default, `LockedBytes` global y help | Mayor |
| Mesh discovery | Reconnection loop y `discovery_tx` actuales (`main.rs:307-346`) | `DiscoveryService` externo (`Evangelium:319-323`) | Hay que eliminar o aislar loop de reconexión basado en `known_peers` | Mayor |
| Peer list propagation | `FLAG_PEER_LIST_REQ/RES` en `peer.rs:601-615`, `695-727` | Eliminar flujo automático (`Evangelium:292`) | Retira descubrimiento mesh actual y su canal `send_discovered` | Mayor |

### 3.1.2 Colisiones MENORES — Evangelium

| Archivo | Colisión | Evidencia actual | Requisito Evangelium | Acción precisa |
|---|---|---|---|---|
| `src/types.rs` | Valores de flag conflictivos | `FLAG_SYSTEM_GOODBYE = 8`, `FLAG_SYSTEM_DISPLAY_NAME = 9` (`types.rs:72-75`) | `FLAG_CONN_REQUEST = 8`, `FLAG_CONN_ACCEPT = 9`, `FLAG_CONN_REJECT = 10` (`Evangelium:249-251`) | Reasignar nuevos flags o usar control enum pre-auth; no pisar 8/9. |
| `src/types.rs` | `ConnectionState` no existe | Solo flags/PeerId/PeerAddr actuales (`types.rs:38-163`) | Agregar enum (`Evangelium:253-261`) | Adición aislada, pero impacta TUI/session. |
| `src/protocol.rs` | Control pre-auth no existe | `read_frame/write_frame` trabajan bytes (`protocol.rs:50-87`) | `CONNECTION_REQUEST` antes de PAKE | Reutilizar framing TLS para nuevo `PreAuthControl`; no mezclar con ratchet `ChatMessage`. |
| `src/main.rs` | Help CLI desactualizado | Usage actual incluye frase obligatoria (`main.rs:161-173`, `183-187`) | `--discovery-port`, `--no-discovery` (`Evangelium:80-85`) | Cambiar texto y parser. |
| `docs/USAGE.md` | Debe reflejar nuevo flujo | Evangelium roadmap exige docs (`Evangelium:468-471`) | Documentar sin args, discovery, manual peer | Cambio documental. |

### 3.1.3 Sin colisiones estructurales — Evangelium

| Archivo | Por qué se reutiliza | Evidencia |
|---|---|---|
| `src/auth.rs` | `perform_handshake` ya recibe `phrase: &[u8]`; solo cambia el origen de esa frase | `auth.rs:91-98`; Evangelium reconoce esto en `294-296`. |
| `src/crypto.rs` | `LockedBytes` ya mlock/zeroize; sirve para frase temporal por chat | `crypto.rs:20-67`; Evangelium exige `LockedBytes` temporal en `192`, `403-406`. |
| `src/ratchet.rs` | Double Ratchet sigue siendo por sesión; no requiere rediseño para 1:1 | `ratchet.rs:12-34`; Turris/Evangelium dicen E2EE sin cambios conceptuales. |
| `src/tls.rs` | TLS efímero/mTLS se mantiene; PeerId de cert efímero sigue útil para discovery | `tls.rs:15-25`, `149-173`. |
| `src/protocol.rs` | Framing/padding puede reutilizarse para frames de chat; con cuidado también para control TLS pre-auth | `protocol.rs:28-87`. |
| `Cargo.toml` | Evangelium declara que no requiere dependencias nuevas (`Evangelium:215-217`, `475-477`) | `tokio::net::UdpSocket` ya disponible por Tokio full según plan. |

### 3.1.4 Código que Evangelium elimina o transforma

| Código actual | Archivo/líneas | Destino recomendado |
|---|---|---|
| `SessionManager.phrase: LockedBytes` | `src/session.rs:71` | Eliminar; frase vive en `ChatState.phrase: Option<LockedBytes>`. |
| Parámetro `phrase` de `SessionManager::new` | `src/session.rs:97-104`, llamada en `main.rs:244-251` | Eliminar del constructor. |
| `SessionManager::phrase()` | `src/session.rs:371-374` | Eliminar; reemplazar con `take_phrase(peer_id)`. |
| `SessionManager::broadcast()` | `src/session.rs:295-305` | Eliminar para mensajes normales; si se conserva para panic debe renombrarse a control explícito. |
| `SessionManager::broadcast_except()` | `src/session.rs:307-319` | Eliminar JOIN/LEAVE grupal o transformar a notificación local por chat. |
| `known_peers` | `src/session.rs:76`; usado en `remove_session`, `known_peers_list` | Mover responsabilidad a `DiscoveryService`. |
| `discovery_tx`, `set_discovery_tx`, `send_discovered` | `src/session.rs:79`, `386-400` | Eliminar; discovery LAN no sale de sesiones cifradas. |
| Reconnection loop de `main.rs` | `src/main.rs:307-339` | Eliminar o reemplazar por estado `Offline/Discovered`; reconexión manual desde sidebar. |
| Discovery channel de `main.rs` | `src/main.rs:342-346`, `429-438` | Eliminar para mesh peer-list; reemplazar por snapshots/eventos de `DiscoveryService`. |
| `FLAG_PEER_LIST_REQ/RES` automático | `src/types.rs:61-63`, `peer.rs:601-615`, `695-727` | No usar en flujo automático; se podrían reservar legacy pero no enviar. |
| TUI chat único `messages: Vec` | `src/tui.rs:50`, `96-108` | Reemplazar por historiales por chat. |
| Sidebar derecha `render_peer_list` | `src/tui.rs:298-325` | Rehacer como sidebar izquierda con peers descubiertos/conectados/offline. |
| CLI `--phrase` obligatorio | `src/main.rs:183-187` | Hacer opcional; pedir en input de conexión. |

### 3.1.5 Código que Evangelium agrega

| Archivo nuevo/modificado | Elementos nuevos | Evidencia del plan |
|---|---|---|
| `src/discovery.rs` | `DiscoveryService`, `DiscoveredPeer`, `DiscoveredPeerState`, heartbeat sender/listener, `get_discovered_peers` | `Evangelium:219-244`, roadmap `431-433`. |
| `src/types.rs` | `ConnectionState`, flags de conexión con valores corregidos, posiblemente `DiscoveredPeerInfo` | `Evangelium:246-262`. |
| `src/session.rs` | `ChatState`, `send_to`, `set_chat_phrase`, `initiate_connection`, `handle_connection_request` | `Evangelium:264-279`. |
| `src/tui.rs` | `MultiChatState`, `active_chat`, focus, input modes, incoming notification, Ctrl+W | `Evangelium:298-313`, `327-395`. |
| `src/peer.rs` | Pre-auth control flow, phrase-specific handshake, no mesh peer list | `Evangelium:281-292`, `448-451`. |
| `docs/USAGE.md` | Discovery usage, no-args startup, manual fallback | `Evangelium:468-471`, `494-525`. |

## 3.2 Colisiones de Turris con código actual

### 3.2.1 Colisiones MAYORES — Turris

| Área | Código actual | Propuesta Turris | Colisión concreta | Gravedad |
|---|---|---|---|---|
| `SessionManager` | `phrase`, `sessions`, `known_peers`, `discovery_tx`, `broadcast` (`session.rs:69-82`) | Quitar `phrase`, `known_peers`, `broadcast`; agregar `chats: HashMap<PeerId, Chat>` (`Turris:387-423`) | Reestructura el struct central y todos sus consumidores | Mayor |
| `SessionHandle` | Unidad actual de sesión con `sender`, `connected_since`, `last_message`, `cancel_notify` (`session.rs:40-47`) | `Chat` contiene `handle: SessionHandle` (`Turris:410-416`) | Menos destructivo que Evangelium, pero requiere mover/encapsular todos los accesos | Mayor |
| `peer.rs` handshake | `run_peer_session` toma frase desde `session_mgr.phrase()` (`peer.rs:445-460`) | `take_phrase(&peer_id)` o frase por parámetro (`Turris:489-499`) | Cambia firma/contrato de `run_peer_session`, `handle_incoming`, `handle_outgoing`, `connect_peer` | Mayor |
| `handle_incoming` | Fire-and-forget desde `main.rs:294-296`; delega inmediato (`peer.rs:340-356`) | Debe notificar TUI, esperar frase, rechazar/timeout (`Turris:501-528`) | Requiere canales nuevos `conn_req_rx/conn_resp_rx` y control de vida de stream TLS | Mayor |
| `main.rs` event loop | Tres ramas: teclado, `discovery_rx`, `msg_rx` (`main.rs:393-482`) | Más ramas: keyboard, msg, conn_req, conn_response; sniff shared state (`Turris:560-602`) | Cambia loop principal y ownership de conectores/TLS streams | Mayor |
| Reconnection/discovery actual | `known_peers_list()` cada 5s y mesh `discovery_tx` (`main.rs:307-346`) | Sniff maneja peers; no reconnection loop ni discovery channel (`Turris:548-557`) | Hay que retirar lógica funcional existente, no solo agregar sniff | Mayor |
| Flags | 8/9 ya ocupados por goodbye/display name (`types.rs:72-75`) | `FLAG_CONN_REQUEST=8`, `ACCEPT=9`, `REJECT=10` (`Turris:610-612`) | Conflicto wire directo y regresión de display name/GOODBYE | Mayor si se implementa literal |
| TUI | `TuiState` no tiene `active_chat`, `chats`, `sniffed_peers`, `focus`, `input_mode`, `pending_requests` (`tui.rs:49-58`) | Turris requiere todos esos campos (`Turris:358-383`) | Rediseño total del estado UI | Mayor |
| Semántica de chat | Actual un chat mezclado; `add_message(peer_id, text, flags)` global (`tui.rs:96-108`) | `add_message_to_chat(peer_id, msg)` (`Turris:577-580`) | Cambia todas las rutas de mensaje desde `main.rs` y `peer.rs` | Mayor |

### 3.2.2 Colisiones MENORES — Turris

| Archivo | Colisión | Evidencia actual | Requisito Turris | Acción precisa |
|---|---|---|---|---|
| `src/types.rs` | `SniffedPeerInfo` no existe | `types.rs:90-163` cubre `PeerId`, `PeerAddr`; no info de discovery | Agregar `SniffedPeerInfo` (`Turris:625-633`) | Adición aislada. |
| `src/types.rs` | `ConnectionState` no existe | No hay enum actual | Agregar enum (`Turris:615-623`) | Adición con consumidores nuevos. |
| `src/main.rs` | No parser de `--sniff-port`/`--discovery-port` | CLI actual `--port`, `--peer`, `--phrase`, etc. (`main.rs:113-180`) | Turris no especifica flag, pero requiere sniff port 42069 | Resolver desde Evangelium: `--discovery-port`. |
| `src/protocol.rs` | No frame de control pre-auth | Solo byte framing genérico (`protocol.rs:50-87`) | `CONN_REQUEST` antes de PAKE (`Turris:210-224`, `501-513`) | Crear `PreAuthControlFrame`, usar `read_frame/write_frame` sobre TLS antes de ratchet. |
| `docs/SECURITY.md` | Nuevo threat model no documentado | Turris exige doc de sniffing (`Turris:650-651`, `693`) | Agregar sección con exposición heartbeat y spoof/DoS. |

### 3.2.3 Sin colisiones estructurales — Turris

| Archivo | Por qué se reutiliza | Evidencia |
|---|---|---|
| `src/auth.rs` | Turris explícitamente dice SPAKE2 + Argon2 sin cambios y `perform_handshake` ya acepta frase | `Turris:11-14`, `649`; `auth.rs:91-98`. |
| `src/crypto.rs` | `LockedBytes` sirve para frase temporal y zeroize | `crypto.rs:20-67`; `Turris:15-18`, `415`. |
| `src/ratchet.rs` | Double Ratchet se mantiene 1:1 | `ratchet.rs:12-34`; `Turris:14`, `237-259`. |
| `src/tls.rs` | TLS 1.3/mTLS y certs efímeros se mantienen | `tls.rs:15-25`, `149-173`; `Turris:11-14`, `536-557`. |
| `Cargo.toml` | Turris declara dependencias nuevas: ninguna | `Turris:18`, `642`. |

### 3.2.4 Código que Turris elimina o transforma

| Código actual | Archivo/líneas | Destino recomendado |
|---|---|---|
| `SessionManager.phrase` | `src/session.rs:71` | Eliminar; `Chat.phrase: Option<LockedBytes>`. |
| `SessionManager::phrase()` | `src/session.rs:371-374` | Eliminar; usar `take_phrase(peer_id)`. |
| `broadcast()` | `src/session.rs:295-305` | Eliminar para chat normal; `send_to` por peer. |
| `broadcast_except()` | `src/session.rs:307-319` | Eliminar notificaciones grupales JOIN/LEAVE. |
| `known_peers_list()` | `src/session.rs:376-384` | Eliminar; `DiscoveryService/SniffService` mantiene peers. |
| `list_peer_addresses()` | `src/session.rs:351-358` | Eliminar del flujo automático. |
| `send_discovered()` | `src/session.rs:395-400` | Eliminar; discovery no depende de mensajes cifrados. |
| `discovery_tx` | `src/session.rs:79`, `main.rs:342-346` | Eliminar. |
| Reconnection loop | `src/main.rs:307-339` | Eliminar o convertir a estado UI manual. |
| `FLAG_PEER_LIST_REQ/RES` automático | `src/peer.rs:601-615`, `695-727` | Eliminar del flujo normal. |
| Single global `TuiState.messages` | `src/tui.rs:50` | Reemplazar por `HashMap<PeerId, Vec<...>>`. |
| Right-side peer list | `src/tui.rs:191-203`, `298-325` | Rehacer como left sidebar. |

### 3.2.5 Código que Turris agrega

| Archivo nuevo/modificado | Elementos nuevos | Evidencia del plan |
|---|---|---|
| `src/sniff.rs` | `SniffService`, `SniffedPeer`, `start`, `get_peers`, `stop`, heartbeat | `Turris:161-179`, `642-644`. |
| `src/types.rs` | `ConnectionState`, `SniffedPeerInfo`, `FLAG_CONN_*` corregidos | `Turris:606-634`, `644`. |
| `src/session.rs` | `Chat`, `send_to`, `set_phrase`, `take_phrase`, `close_chat`, connection state methods | `Turris:426-448`, `645`. |
| `src/peer.rs` | Incoming connection request wait, phrase timeout 60s, no peer-list request | `Turris:477-528`, `646`. |
| `src/main.rs` | Sniff init, no phrase requirement, conn request/response channels | `Turris:532-602`, `647`. |
| `src/tui.rs` | Sidebar, multi-chat HashMap, dynamic input, accept/reject incoming | `Turris:288-383`, `648`. |
| `docs/USAGE.md` | New CLI and keyboard flow | `Turris:650`, `693`, `755`. |
| `docs/SECURITY.md` | Sniffing threat model | `Turris:651`, `693`. |

---

# Sección 4: Colisiones Entre Ambos Planes

## 4.1 Features compartidas

| Feature | Evangelium | Turris | Conclusión |
|---|---|---|---|
| UDP multicast LAN | `239.255.0.42:42069`, heartbeat 10s, timeout 30s (`Evangelium:40-45`) | Mismo addr/puerto/intervalo/timeout (`Turris:88-95`) | Duplicado exacto. |
| No dependencias nuevas | `tokio::net::UdpSocket`, std (`Evangelium:215-217`, `475-477`) | `tokio` + std (`Turris:18`, `642`) | Duplicado exacto. |
| Frase por conexión | Frase al conectar, no al arrancar (`Evangelium:21-30`, `89-126`) | Frase por conexión (`Turris:48-70`, `183-248`) | Duplicado exacto. |
| Multi-chat 1:1 | `ChatState` por `PeerId` (`Evangelium:180-196`) | `chats: HashMap<PeerId, Chat>` (`Turris:410-416`) | Misma arquitectura; Turris añade `handle`. |
| Sidebar izquierda | Layout peers izquierda/chat derecha (`Evangelium:137-154`) | Layout `SNIFF (30%)` izquierda (`Turris:288-306`) | Duplicado exacto con diferente etiqueta. |
| Iconografía | `● ○ ◇ → !` (`Evangelium:156-164`) | `● ○ ◇ → !` con acción posible (`Turris:309-318`) | Duplicado; Turris tabla más completa. |
| Flags `FLAG_CONN_*` | Request/Accept/Reject con valores 8/9/10 (`Evangelium:127-134`) | Valores 8/9/10 (`Turris:261-267`, `610-612`) | Duplicado y ambos chocan con código actual. |
| `ConnectionState` | Enum (`Evangelium:253-261`) | Enum (`Turris:615-623`) | Duplicado exacto. |
| `send_to()` | Reemplaza broadcast (`Evangelium:198-205`, `272`) | Reemplaza broadcast (`Turris:430-432`) | Duplicado exacto. |
| Eliminar peer-list mesh | Eliminar `FLAG_PEER_LIST_REQ/RES` automático (`Evangelium:292`) | No hay `FLAG_PEER_LIST_REQ` automático (`Turris:493`) | Duplicado exacto. |
| Docs/tests | Actualizar docs y tests (`Evangelium:464-471`) | Actualizar docs y tests (`Turris:686-693`, `747-755`) | Duplicado, Turris más exhaustivo. |

## 4.2 Features que difieren

| Diferencia | Evangelium | Turris | Veredicto |
|---|---|---|---|
| Nombre | `DiscoveryService` | `SniffService` | Elegir `DiscoveryService`: más descriptivo y menos coloquial. |
| Archivo | `src/discovery.rs` | `src/sniff.rs` | Elegir `src/discovery.rs`; no crear ambos. |
| Heartbeat magic | `sesame-v1` | `sesame-sniff-v1` | Elegir uno nuevo explícito: `sesame-discovery-v1`. No usar ambos. |
| Peer info | `DiscoveredPeer` con `state: DiscoveredPeerState` | `SniffedPeerInfo` con `ConnectionState` | Consolidar en `DiscoveredPeerInfo` usando `ConnectionState`. |
| CLI | `--discovery-port`, `--no-discovery` | No define esos flags | Absorber flags de Evangelium. |
| Seguridad DoS | General | Menciona mapa límite 50 y socket no bloqueante | Absorber de Turris, pero documentar límite exacto en código. |
| Timeout frase | No da número salvo handshake actual y fallos | 60 segundos (`Turris:522-528`) | Absorber 60s de Turris. |
| Conexión simultánea | Primera gana, segunda falla duplicada (`Evangelium:490`) | Primera request gana, segunda rechaza con mensaje explícito (`Turris:269-284`, `724`) | Absorber detalle Turris. |
| Estado `ChatState` | No incluye `SessionHandle` | Incluye `handle: SessionHandle` | Absorber Turris; sin handle se rompe `send_to`/cancel. |
| Mockups UI | Más pantallas completas | Mejor tabla de teclas/input modes | Fusionar ambos. |

## 4.3 ¿Son el mismo plan con distinto nombre?

Sí. Técnicamente son el mismo plan porque comparten las mismas decisiones arquitectónicas irreversibles:

1. Abandonan frase global.
2. Abandonan mesh grupal como UX principal.
3. Abandonan broadcast de mensajes normales.
4. Introducen UDP multicast LAN.
5. Introducen multi-chat 1:1.
6. Introducen estados de conexión por peer.
7. Introducen input de frase por peer.
8. Rediseñan `SessionManager` y `TuiState`.
9. Mantienen SPAKE2, TLS y Double Ratchet.
10. Eliminan el flujo automático `FLAG_PEER_LIST_REQ/RES`.

No hay una partición razonable donde Evangelium sea “LAN discovery” y Turris sea “multi-chat”: ambos hacen ambas cosas.

## 4.4 ¿Cuál plan es más completo/detallado?

| Criterio | Ganador | Evidencia |
|---|---|---|
| Precisión de UI visual | Evangelium | Pantallas inicial, conectando, chat activo, conexión entrante (`Evangelium:327-395`). |
| Precisión del modelo interno TUI | Turris | `active_chat`, `chats`, `sniffed_peers`, `focus`, `input_mode`, `pending_requests` (`Turris:358-383`). |
| Seguridad discovery | Turris | Amenazas y mitigaciones explícitas (`Turris:143-159`, `251-259`). |
| CLI operable | Evangelium | `--discovery-port`, `--no-discovery` (`Evangelium:80-85`). |
| Refactor `SessionManager` | Turris | API completa (`Turris:426-448`) y transición (`451-473`). |
| Refactor `peer.rs` | Turris | `handle_incoming` no fire-and-forget, timeout 60s (`Turris:501-528`). |
| Roadmap verificable | Turris | Tests y DoD (`Turris:686-693`, `743-755`). |

**Resultado:** Turris es más completo técnicamente; Evangelium tiene mejor nombre/CLI/mockups.

## 4.5 Veredicto: implementar ambos, fusionarlos o elegir uno

**No implementar ambos.** Implementar ambos produciría:

- Dos servicios UDP para el mismo multicast.
- Dos structs de peer descubierto.
- Dos nombres para el mismo estado.
- Dos flujos de conexión por frase.
- Dos cambios incompatibles sobre `SessionManager`.
- Dos modificaciones paralelas a `TuiState`.

**Fusionar.** Crear un único plan canónico:

- Nombre recomendado: `Evangelium` como plan visible si se quiere conservar el nombre ya asociado a “Discovery LAN + chats múltiples”.
- Servicio recomendado: `DiscoveryService` en `src/discovery.rs`.
- Contenido absorbido desde Turris: seguridad del sniffing, timeout 60s, API de `SessionManager`, `Chat` con `SessionHandle`, event loop con conn request/response, tests y DoD.

---

# Sección 5: Duplicidad de Código y Features

## 5.1 Features duplicadas consolidables

| Feature duplicada | Consolidación recomendada |
|---|---|
| UDP multicast heartbeat | Un único `DiscoveryService` con addr `239.255.0.42`, puerto default `42069`, heartbeat `10s`, timeout `30s`. |
| Peer info LAN | Un único `DiscoveredPeerInfo { peer_id, addr, is_online, last_seen, state }`. |
| `ConnectionState` | Definir una sola vez en `src/types.rs`. |
| Frase por conexión | Una sola API `set_phrase/take_phrase` por `PeerId`; no frase en `main.rs` global. |
| Input dinámico | Un solo `InputMode`: `Message`, `Phrase(PeerId)`, `ConnRequest(PeerId)`. |
| Sidebar izquierda | Una sola implementación en `tui.rs`, no `SniffBar` y `Peers` separados. |
| `FLAG_CONN_*` | No duplicar ni usar valores 8/9; definir control frames o flags no conflictivos. |
| Eliminación broadcast | Un solo refactor: `send_to` y cierre de chat. |
| Discovery fallback manual | `--peer` manual + pedir frase al conectar, con `--no-discovery` opcional. |
| Docs | Un solo update a `docs/USAGE.md` y `docs/SECURITY.md`. |

## 5.2 Código que se escribiría dos veces si se implementan por separado

| Código duplicado potencial | Dónde aparecería | Consecuencia |
|---|---|---|
| Socket UDP multicast | `src/discovery.rs` y `src/sniff.rs` | Doble bind al puerto 42069 o dos tareas leyendo el mismo canal. |
| Heartbeat serializer/deserializer | Ambos servicios | Magic incompatible: `sesame-v1` vs `sesame-sniff-v1`. |
| Peer timeout loop | Ambos servicios | Estados offline divergentes. |
| `ConnectionState` enum | Dos nombres/módulos o una re-declaración | Imports confusos y match incompletos. |
| Peer info struct | `DiscoveredPeer` vs `SniffedPeerInfo` | TUI tendría que mapear tipos equivalentes. |
| Session chat map | `ChatState` vs `Chat` | Dos modelos para el mismo lock/state. |
| `send_to` | Misma función añadida por ambos | Riesgo de dos variantes con errores distintos. |
| Input phrase flow | Dos branches en TUI | UX inconsistente, bugs de foco. |
| Conn request channels | Main/TUI/peer dobles | Deadlocks o respuestas entregadas al flujo equivocado. |
| Tests | Discovery loopback y handshake por frase repetidos | Más mantenimiento sin cobertura adicional. |

## 5.3 Recomendación: qué plan absorbe a qué

Recomendación explícita:

- **Evangelium absorbe Turris** como documento canónico de feature.
- Se conserva de Evangelium:
  - Nombre de feature: discovery LAN + chats múltiples.
  - `DiscoveryService` y `src/discovery.rs`.
  - Flags CLI `--discovery-port` y `--no-discovery`.
  - Mockups de pantallas.
- Se absorbe de Turris:
  - Seguridad de sniffing.
  - Timeout de frase entrante de 60s.
  - API detallada de `SessionManager`.
  - `Chat` que conserva `SessionHandle`.
  - Event loop con `conn_req_rx` / `conn_resp_rx`.
  - Tests/DoD.

Si se debe elegir un plan sin editarlo, elegir **Turris** por completitud técnica. Pero el resultado óptimo no es Turris puro: es Evangelium + detalles de Turris.

---

# Sección 6: Mejoras Sugeridas

## 6.1 Mejoras al diseño propuesto basadas en el MVP

### 6.1.1 No implementar `FLAG_CONN_REQUEST` como `ChatMessage` normal

Problema:

- En el código actual, `ChatMessage` se descifra y procesa solo después de `perform_handshake` y después de inicializar Double Ratchet (`peer.rs:445-460`, `628-742`).
- Ambos planes quieren enviar `CONN_REQUEST` antes de `perform_handshake` (`Evangelium:103-120`; `Turris:210-224`, `501-513`).
- Por lo tanto, `FLAG_CONN_REQUEST` como `ChatMessage` cifrado es circular: necesita ratchet, pero el ratchet necesita handshake, y el handshake necesita frase aceptada.

Mejora concreta:

```rust
#[derive(Serialize, Deserialize, Debug)]
pub enum PreAuthControlFrame {
    ConnRequest { peer_id: PeerId },
    ConnAccept,
    ConnReject { reason: ConnRejectReason },
}
```

- Transportar `PreAuthControlFrame` sobre TLS usando `protocol::write_frame/read_frame` antes de `perform_handshake`.
- No pasarlo por Double Ratchet.
- No mezclarlo con `ChatMessage.flags`.
- Mantener `ChatMessage` para tráfico post-auth.

### 6.1.2 Resolver el conflicto de flags 8/9

Problema concreto:

- Actual: `FLAG_SYSTEM_GOODBYE = 8` y `FLAG_SYSTEM_DISPLAY_NAME = 9` (`src/types.rs:72-75`).
- Evangelium/Turris: `FLAG_CONN_REQUEST = 8`, `FLAG_CONN_ACCEPT = 9`, `FLAG_CONN_REJECT = 10` (`Evangelium:249-251`, `Turris:610-612`).

Mejora concreta:

- Opción A preferida: no usar flags para pre-auth; usar `PreAuthControlFrame`.
- Opción B si se insiste en flags post-auth: asignar valores libres, por ejemplo `10`, `11`, `12`, dejando 8/9 intactos.
- Añadir test que garantice unicidad de flags.

### 6.1.3 Mantener `SessionHandle` dentro de `ChatState`

Problema:

- Evangelium muestra `ChatState` sin `sender` ni `cancel_notify` (`Evangelium:186-193`).
- El código actual necesita `sender` para enviar a un peer (`SessionHandle.sender`, `session.rs:40-47`) y `cancel_notify` para desconectar (`session.rs:237-254`, `peer.rs:781-804`).

Mejora concreta:

```rust
pub struct ChatState {
    pub peer_id: PeerId,
    pub peer_addr: PeerAddr,
    pub handle: Option<SessionHandle>,
    pub messages: Vec<ChatMessage>,
    pub state: ConnectionState,
    pub phrase: Option<LockedBytes>,
    pub last_error: Option<String>,
}
```

- `handle: None` para descubierto/offline/pending.
- `handle: Some(...)` solo cuando conectado.
- Esto combina la claridad de Evangelium con la viabilidad de Turris.

### 6.1.4 No devolver `&mut Chat` desde `SessionManager` con `Mutex`

Turris propone `get_or_create_chat(&self, peer_id) -> &mut Chat` (`Turris:441-443`). En Rust, con estado dentro de `Mutex<HashMap<...>>`, no se puede devolver un `&mut Chat` con vida válida después de soltar el lock.

Mejora concreta:

- Usar métodos de operación:
  - `ensure_chat(peer_id, addr)`
  - `with_chat_mut(peer_id, |chat| { ... })`
  - `chat_snapshot(peer_id) -> Option<ChatSnapshot>`
- O devolver snapshots clonados para TUI.

### 6.1.5 Separar estado de discovery de estado de sesión

Ambos planes dicen que discovery/sniff maneja peers conocidos. Correcto. Pero `ConnectionState` mezcla dos dominios:

- Presencia LAN: online/offline por heartbeat.
- Estado de sesión: connecting/awaiting phrase/handshaking/connected/error.

Mejora concreta:

```rust
pub enum PresenceState {
    Online,
    Offline,
}

pub enum ConnectionState {
    Discovered,
    Connecting,
    AwaitingPhrase,
    Handshaking,
    Connected,
    Disconnected,
    Error,
}
```

Si se mantiene un solo enum, documentar que `Disconnected`/`Discovered` dependen de discovery y sesión.

## 6.2 Mejoras de seguridad

| Mejora | Archivo/área | Justificación exacta |
|---|---|---|
| Cap de peers descubiertos | `src/discovery.rs` | Turris menciona límite interno 50 (`Turris:153-156`), pero debe codificarse como `MAX_DISCOVERED_PEERS`. |
| Validar magic/version | `src/discovery.rs` | Evangelium y Turris tienen magic distinto; usar uno y rechazar lo demás. |
| Ignorar self heartbeat | `src/discovery.rs` | `PeerId` propio se conoce desde `main.rs:228`; no debe aparecer en sidebar. |
| No exponer display name en heartbeat | `src/discovery.rs` | Los planes solo exponen peer_id/ip/port (`Evangelium:47-55`, `Turris:135-141`); mantener mínimo. |
| TTL multicast local | `src/discovery.rs` | Alcance esperado es LAN; evitar fuga accidental más allá de subnet si OS lo permite. |
| Rate limit por IP | `src/discovery.rs` | Mitiga flood UDP de un host; complemento al límite de mapa. |
| Zeroize frase al cancelar | `src/tui.rs`, `src/session.rs` | F12 durante handshake debe zeroizar temporal (`Evangelium:489`, `Turris:726`). |
| Timeout entrada frase 60s | `src/peer.rs`/`src/main.rs` | Turris lo define (`Turris:522-528`, `721`). Evita streams colgados. |
| No logs de frase | `src/tui.rs`, `src/main.rs` | Actual código loguea display name pero no frase; mantener prohibición. |
| Test de flag uniqueness | `src/types.rs` tests | Evita repetir el bug 8/9 descubierto. |

## 6.3 Mejoras de UX

| Mejora | Área | Detalle concreto |
|---|---|---|
| Estado inicial sin chat activo | `tui.rs` | Si `active_chat = None`, Enter en input no debe enviar; mostrar ayuda como Evangelium (`Evangelium:329-346`). |
| Input de frase enmascarado | `tui.rs` | Mostrar `*`, guardar bytes en `LockedBytes`, no en `String` más tiempo del necesario. |
| Mensaje de error por frase incorrecta | `tui.rs` | Mostrar peer y volver a `Discovered`/`○`, como planes (`Evangelium:486`, `Turris:720`). |
| Foco visible | `tui.rs` | Turris requiere `FocusArea`; resaltar sidebar/input activo (`Turris:371-375`). |
| Teclas consistentes | `tui.rs` | Usar tabla Turris: Tab, ↑↓, Enter, Esc, Ctrl+W, A/R, F12 (`Turris:319-335`). |
| No auto-conectar | `discovery.rs` + `tui.rs` | Ambos planes dicen selección manual (`Evangelium:67`, `538`; `Turris:711`). |
| Manual fallback claro | `main.rs` + docs | `--peer` manual debe pedir frase al conectar (`Evangelium:517-525`). |

## 6.4 Mejoras de rendimiento

| Mejora | Archivo | Razón |
|---|---|---|
| Snapshot de peers para TUI | `src/discovery.rs`, `src/tui.rs` | Evita mantener locks durante render. |
| Watch channel para cambios discovery | `src/discovery.rs` | Evita polling agresivo; TUI puede renderizar cuando cambia estado. |
| Un solo heartbeat task | `src/discovery.rs` | Evita doble servicio si se fusionan planes. |
| `try_send` con backpressure visible | `src/session.rs` | Actual `broadcast` ignora errores (`session.rs:300-304`); `send_to` debería devolver `Result`. |
| No clonar todo historial cada frame | `src/tui.rs` | Actual render crea `Vec<ListItem>` cada frame (`tui.rs:224-262`); con multi-chat limitar al chat activo. |
| Mantener max de mensajes por chat | `src/tui.rs`/`session.rs` | Actual `MAX_MESSAGES = 500` global (`tui.rs:33-35`); aplicar por chat. |

---

# Sección 7: Arquitectura Requerida

## 7.1 Arquitectura final recomendada fusionada

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│                         Sesame Discovery Multi-Chat                         │
├─────────────────────────────────────────────────────────────────────────────┤
│ CLI / main.rs                                                               │
│   --port N                                                                  │
│   --peer IP:PORT                 manual fallback                            │
│   --discovery-port N             default 42069                              │
│   --no-discovery                 disable UDP multicast                      │
│   --phrase / --phrase-fd          optional only for manual/preconfigured use │
│   --decoy / --decoy-phrase        must be re-evaluated without global phrase │
│                                                                             │
│ TLS identity                                                                │
│   tls::generate_cert() -> PeerId                                            │
│                                                                             │
│ DiscoveryService (src/discovery.rs)                                         │
│   UDP multicast 239.255.0.42:42069                                          │
│   heartbeat JSON { magic: "sesame-discovery-v1", peer_id, ip, port }        │
│   peers: HashMap<PeerId, DiscoveredPeer>                                    │
│   emits snapshots/updates to TUI                                            │
│                                                                             │
│ TUI (src/tui.rs)                                                            │
│   sidebar left: discovered/offline/connecting/connected/error               │
│   active_chat: Option<PeerId>                                               │
│   input_mode: Message | Phrase(peer) | ConnRequest(peer)                    │
│   pending_requests                                                          │
│                                                                             │
│ SessionManager (src/session.rs)                                             │
│   chats: HashMap<PeerId, ChatState>                                         │
│   no global phrase                                                          │
│   ChatState.handle: Option<SessionHandle>                                   │
│   ChatState.phrase: Option<LockedBytes> only before/till handshake          │
│   send_to(peer_id, data) -> Result                                          │
│                                                                             │
│ peer.rs                                                                     │
│   Outgoing: user selected peer + phrase                                     │
│      TCP -> TLS -> PreAuthControl::ConnRequest -> wait accept -> SPAKE2     │
│   Incoming: TCP -> TLS -> emit conn_req -> wait TUI response -> accept/rej  │
│      if accept: perform_handshake(take_phrase(peer_id))                    │
│   Post-auth: Double Ratchet ChatMessage only                               │
│                                                                             │
│ Crypto/Auth/TLS/Ratchet                                                     │
│   Reused: auth.rs, crypto.rs, tls.rs, ratchet.rs                            │
└─────────────────────────────────────────────────────────────────────────────┘
```

## 7.2 Lista de archivos nuevos

| Archivo | Propósito | Fuente absorbida |
|---|---|---|
| `src/discovery.rs` | Servicio UDP multicast, heartbeat, listener, timeout offline, snapshots | Nombre de Evangelium; seguridad de Turris. |
| `tests/discovery_loopback.rs` o tests unitarios en `src/discovery.rs` | Validar parse heartbeat, self-ignore, timeout, cap | Roadmaps de ambos; DoD Turris. |
| `tests/multichat_handshake.rs` o integración equivalente | Validar frase correcta/incorrecta y 3 chats | Turris `686-692`, Evangelium `468-470`. |

Nota: no crear `src/sniff.rs` si existe `src/discovery.rs`. `Sniff` puede quedar como nombre visible en UI solo si el producto lo requiere, pero no como módulo técnico duplicado.

## 7.3 Lista de archivos a modificar

| Archivo | Modificación requerida |
|---|---|
| `src/main.rs` | Parser de `--discovery-port`/`--no-discovery`; `--phrase` no obligatorio; inicializar `DiscoveryService`; eliminar reconnection loop mesh; eliminar `discovery_tx`; agregar canales conn request/response; ajustar event loop. |
| `src/session.rs` | Quitar frase global; introducir `ChatState`; reemplazar `sessions` por `chats` o encapsular sesiones dentro de chats; agregar `send_to`, phrase/state/message APIs; eliminar known peers/discovery tx. |
| `src/tui.rs` | Rediseñar estado multi-chat; sidebar izquierda; input modes; notificación entrante; teclas nuevas; enviar por `send_to` al chat activo. |
| `src/peer.rs` | Cambiar handshake para usar frase por peer; introducir pre-auth control frames; incoming wait + timeout; remover peer-list mesh automático; ajustar cleanup para no broadcast grupal. |
| `src/types.rs` | Agregar `ConnectionState`, `DiscoveredPeerInfo`, `PreAuthControlFrame` o flags no conflictivos; test de unicidad. |
| `src/protocol.rs` | Reutilizable; opcionalmente agregar helpers typed `read_json_frame/write_json_frame` con límite pequeño para pre-auth. |
| `docs/USAGE.md` | Documentar no-args, discovery, manual peer, teclas, frase por conexión. |
| `docs/SECURITY.md` | Documentar exposición UDP, spoofing, DoS, frase temporal, no persistencia de historial. |
| `Cargo.toml` | Sin cambios previstos si Tokio ya está con `full`. |

## 7.4 Lista de archivos a eliminar

No se recomienda eliminar archivos completos existentes.

Sí se elimina código interno:

| Código interno | Archivo |
|---|---|
| Frase global en `SessionManager` | `src/session.rs` |
| `SessionManager::phrase()` | `src/session.rs` |
| `known_peers`, `known_peers_list`, `list_peer_addresses`, `send_discovered`, `set_discovery_tx` | `src/session.rs` |
| Reconnection loop cada 5s | `src/main.rs` |
| Discovery channel mesh | `src/main.rs` |
| Auto `FLAG_PEER_LIST_REQ` al conectar | `src/peer.rs` |
| Handlers `FLAG_PEER_LIST_REQ/RES` en flujo normal | `src/peer.rs` |
| Broadcast normal para mensajes de usuario | `src/tui.rs`, `src/session.rs` |
| Layout peers derecha como única lista | `src/tui.rs` |

## 7.5 API propuesta

### 7.5.1 `src/discovery.rs`

```rust
pub const DEFAULT_DISCOVERY_ADDR: Ipv4Addr = Ipv4Addr::new(239, 255, 0, 42);
pub const DEFAULT_DISCOVERY_PORT: u16 = 42069;
pub const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(10);
pub const PEER_TIMEOUT: Duration = Duration::from_secs(30);
pub const MAX_DISCOVERED_PEERS: usize = 50;

pub struct DiscoveryService { /* socket/tasks/state */ }

impl DiscoveryService {
    pub async fn start(
        my_id: PeerId,
        listen_port: u16,
        discovery_port: u16,
    ) -> std::io::Result<Arc<Self>>;

    pub fn peers_snapshot(&self) -> Vec<DiscoveredPeerInfo>;
    pub fn subscribe(&self) -> watch::Receiver<Vec<DiscoveredPeerInfo>>;
    pub async fn stop(&self);
}
```

### 7.5.2 `src/types.rs`

```rust
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum ConnectionState {
    Discovered,
    Connecting,
    AwaitingPhrase,
    Handshaking,
    Connected,
    Disconnected,
    Error,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DiscoveredPeerInfo {
    pub peer_id: PeerId,
    pub addr: PeerAddr,
    pub is_online: bool,
    pub last_seen_ms: u64,
    pub state: ConnectionState,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum PreAuthControlFrame {
    ConnRequest { peer_id: PeerId },
    ConnAccept,
    ConnReject { reason: String },
}
```

Si se mantienen flags post-auth:

```rust
pub const FLAG_CONN_REQUEST: u8 = 10;
pub const FLAG_CONN_ACCEPT: u8 = 11;
pub const FLAG_CONN_REJECT: u8 = 12;
```

pero la recomendación fuerte es no usarlos para pre-auth.

### 7.5.3 `src/session.rs`

```rust
pub struct ChatState {
    pub peer_id: PeerId,
    pub peer_addr: PeerAddr,
    pub handle: Option<SessionHandle>,
    pub messages: Vec<ChatMessage>,
    pub state: ConnectionState,
    pub phrase: Option<LockedBytes>,
    pub last_error: Option<String>,
}

impl SessionManager {
    pub fn new(
        message_tx: mpsc::Sender<(PeerId, ChatMessage)>,
        inactivity_timeout: Duration,
        my_listen_addr: PeerAddr,
        my_peer_id: PeerId,
        my_display_name: Option<String>,
    ) -> Self;

    pub fn ensure_chat(&self, peer_id: PeerId, addr: PeerAddr);
    pub fn close_chat(&self, peer_id: &PeerId);

    pub fn register_session(&self, peer_id: PeerId, handle: SessionHandle) -> Result<(), &'static str>;
    pub fn remove_session(&self, peer_id: &PeerId);
    pub fn disconnect_peer(&self, peer_id: &PeerId);

    pub fn send_to(&self, peer_id: &PeerId, data: &[u8]) -> Result<(), &'static str>;
    pub fn get_sender(&self, peer_id: &PeerId) -> Option<mpsc::Sender<Vec<u8>>>;

    pub fn set_phrase(&self, peer_id: &PeerId, phrase: LockedBytes);
    pub fn take_phrase(&self, peer_id: &PeerId) -> Option<LockedBytes>;

    pub fn set_connection_state(&self, peer_id: &PeerId, state: ConnectionState);
    pub fn get_connection_state(&self, peer_id: &PeerId) -> Option<ConnectionState>;

    pub fn add_message(&self, peer_id: &PeerId, msg: ChatMessage);
    pub fn messages_snapshot(&self, peer_id: &PeerId) -> Vec<ChatMessage>;
    pub fn chats_snapshot(&self) -> Vec<ChatSnapshot>;

    pub fn panic_shutdown(&self);
    pub fn cancel_rx(&self) -> watch::Receiver<bool>;
    pub fn system_msg(&self, text: &str);
}
```

### 7.5.4 `src/peer.rs`

```rust
pub async fn connect_peer(
    addr: PeerAddr,
    peer_id: PeerId,
    session_mgr: Arc<SessionManager>,
    connector: TlsConnector,
) -> Result<(), PeerConnectError>;

pub async fn handle_incoming(
    tls_stream: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    peer_addr: PeerAddr,
    session_mgr: Arc<SessionManager>,
    conn_req_tx: mpsc::Sender<IncomingConnRequest>,
    conn_resp_rx: ConnResponseRouter,
) -> Result<(), PeerConnectError>;

async fn run_peer_session(
    tls_stream: tokio_rustls::TlsStream<tokio::net::TcpStream>,
    peer_id: PeerId,
    peer_addr: PeerAddr,
    session_mgr: Arc<SessionManager>,
    is_initiator: bool,
    phrase: LockedBytes,
) -> Result<(), Box<dyn std::error::Error>>;
```

Notas:

- `connect_peer` debe poder mapear `PeerId -> PeerAddr` desde discovery.
- `handle_incoming` no debe quedarse con un receiver global compartido sin routing por peer; necesita correlación request/response.
- `run_peer_session` recibe `phrase` ya extraída para que se zeroize al salir.

### 7.5.5 `src/tui.rs`

```rust
pub enum FocusArea {
    Sidebar,
    Chat,
    Input,
}

pub enum InputMode {
    Message,
    Phrase(PeerId),
    ConnRequest(PeerId),
}

pub struct TuiState {
    pub active_chat: Option<PeerId>,
    pub chats: HashMap<PeerId, Vec<(PeerId, String, u8)>>,
    pub discovered_peers: Vec<DiscoveredPeerInfo>,
    pub focus: FocusArea,
    pub input_mode: InputMode,
    pub pending_requests: Vec<PeerId>,
    pub input: String,
    pub my_id: PeerId,
    pub session_mgr: Arc<SessionManager>,
    pub quit: bool,
    pub panic_requested: bool,
}

impl TuiState {
    pub fn handle_event(&mut self, event: Event) -> Vec<TuiAction>;
    pub fn add_message_to_chat(&mut self, peer_id: PeerId, msg: ChatMessage);
    pub fn set_discovered_peers(&mut self, peers: Vec<DiscoveredPeerInfo>);
    pub fn show_conn_request(&mut self, peer_id: PeerId);
    pub fn render(&mut self, frame: &mut Frame);
}
```

`handle_event` debería devolver acciones (`StartConnection`, `SendMessage`, `AcceptConnection`, `RejectConnection`, `CloseChat`) en vez de llamar directamente a red en todas las ramas. Esto reduce acoplamiento y evita que la TUI bloquee.

---

# Sección 8: Roadmap de Implementación Recomendado

## 8.1 Fases con dependencias

| Fase | Nombre | Depende de | Archivos | Esfuerzo | Entregable verificable |
|---|---|---|---|---|---|
| 0 | Corrección de diseño protocolar | Ninguna | `src/types.rs`, `src/protocol.rs` | Quick/Short: 0.5 día | `PreAuthControlFrame` o flags corregidos; test de unicidad; ningún choque 8/9. |
| 1 | DiscoveryService LAN | Fase 0 | `src/discovery.rs`, `src/types.rs`, `src/main.rs` mínimo | Short: 1 día | Dos instancias se ven por UDP; self heartbeat ignorado; timeout offline. |
| 2 | SessionManager multi-chat | Fase 0 | `src/session.rs`, tests | Medium: 1-1.5 días | No frase global; `send_to`; `ChatState`; tests de estado/phrase take. |
| 3 | Peer handshake por conexión | Fases 0 y 2 | `src/peer.rs`, `src/main.rs`, `src/auth.rs` sin cambios estructurales | Medium/Large: 1.5-2 días | Frase correcta conecta; frase incorrecta falla; timeout 60s; no peer-list mesh automático. |
| 4 | TUI multi-chat/sidebar | Fases 1-3 | `src/tui.rs`, `src/main.rs` | Large: 2 días | Sidebar ●○◇→!, active chat, input phrase/message, accept/reject, Ctrl+W. |
| 5 | Limpieza legacy mesh | Fases 1-4 | `src/main.rs`, `src/session.rs`, `src/peer.rs`, `src/types.rs` | Short: 0.5-1 día | Sin reconnection loop mesh; sin `FLAG_PEER_LIST_REQ/RES` automático; docs actualizados. |
| 6 | Tests/docs/security | Todas | `tests/`, `docs/USAGE.md`, `docs/SECURITY.md` | Medium: 1 día | `cargo check`, `cargo test`, `cargo clippy`; manual 2-3 instancias; docs completas. |

## 8.2 Orden recomendado de commits/unidades atómicas

1. Agregar `ConnectionState`, `PreAuthControlFrame` y corregir conflicto de flags en `src/types.rs`.
2. Agregar `src/discovery.rs` sin conectarlo todavía al TUI; testear heartbeat parse/timeout.
3. Integrar `DiscoveryService` en `main.rs` con `--discovery-port`/`--no-discovery`, solo log/snapshot inicial.
4. Refactor `SessionManager` para eliminar frase global y añadir `ChatState` + `send_to` manteniendo compat temporal si hace falta.
5. Cambiar `peer.rs` para recibir/tomar frase por peer en outgoing sin tocar aún incoming UX.
6. Implementar incoming `ConnRequest` con canales y timeout 60s.
7. Rehacer `TuiState` multi-chat y sidebar.
8. Eliminar mesh peer-list automático y reconnection loop.
9. Actualizar docs.
10. Ejecutar verification wave: check, test, clippy, manual multi-instance.

## 8.3 Riesgos y mitigaciones

| Riesgo | Causa | Mitigación |
|---|---|---|
| Deadlock entre `handle_incoming` y TUI | Stream TLS espera frase mientras TUI espera evento mal routeado | Usar request ID/PeerId y `oneshot` por solicitud; timeout 60s. |
| Conflicto de flags rompe GOODBYE/display name | Ambos planes usan 8/9 | No usar 8/9; test de unicidad; preferir control enum pre-auth. |
| Pérdida de `SessionHandle` al adoptar `ChatState` | Evangelium no incluye handle en ejemplo | Usar `handle: Option<SessionHandle>` como Turris. |
| UI envía mensaje sin active chat | Antes existía chat global | `InputMode::Message` requiere `active_chat: Some(peer_id)`; si no, mostrar ayuda. |
| Discovery falso llena sidebar | UDP spoof/flood | `MAX_DISCOVERED_PEERS`, rate limit por IP, magic/version, TTL local. |
| Frase queda en `String` del input | TUI input actual es `String` (`tui.rs:51`) | Al confirmar, mover a `LockedBytes`, limpiar `input`, zeroize buffer temporal si se introduce wrapper. |
| Reconexión automática contradice frase por conexión | Loop actual reconecta cada 5s usando frase global (`main.rs:307-339`) | Eliminar loop; reconexión manual desde sidebar. |
| Incompatibilidad con manual `--peer` | Discovery nuevo asume PeerId previo | Manual peer debe crear chat por addr con PeerId desconocido hasta TLS; UI muestra addr temporal. |
| Múltiples conexiones simultáneas | Ambos peers inician a la vez | Regla determinista: menor PeerId gana o primera request aceptada gana; documentar y testear. |
| Tests flakey con multicast | CI/local puede bloquear multicast | Separar tests unitarios de heartbeat parse/timeout y manual/integration gated para multicast real. |

## 8.4 Criterios de aceptación mínimos de la arquitectura fusionada

- [ ] `src/types.rs` no reutiliza valores de flags existentes; `FLAG_SYSTEM_GOODBYE` y `FLAG_SYSTEM_DISPLAY_NAME` siguen funcionando.
- [ ] `SessionManager` ya no tiene `phrase: LockedBytes` ni `phrase()`.
- [ ] `main.rs` arranca sin `--phrase` cuando discovery está habilitado.
- [ ] `main.rs` permite `--no-discovery --peer IP:PORT` y pide frase al conectar.
- [ ] Discovery UDP publica heartbeat cada 10s y marca offline a los 30s.
- [ ] TUI muestra peers descubiertos en sidebar izquierda con `● ○ ◇ → !`.
- [ ] Enter sobre peer descubierto pide frase y conecta solo a ese peer.
- [ ] Mensaje de usuario usa `send_to(active_chat)` y no broadcast.
- [ ] Frase incorrecta falla sin revelar frase y vuelve a estado descubierto/error reintentable.
- [ ] Incoming connection muestra notificación y acepta/rechaza con frase o timeout.
- [ ] `auth.rs`, `crypto.rs`, `ratchet.rs`, `tls.rs` no sufren refactors criptográficos innecesarios.
- [ ] `cargo check`, `cargo test`, `cargo clippy` pasan.
- [ ] Docs explican discovery, frase por conexión, controles y límites de seguridad.

## 8.5 Veredicto final

Los planes Evangelium y Turris deben tratarse como una única migración arquitectónica de tamaño **Large**: Sesame pasa de mesh grupal con frase global a discovery LAN + multi-chat 1:1 con frase por conexión.

La implementación debe partir de una fusión explícita, no de dos ramas paralelas. El mayor ajuste no documentado por los planes es protocolar: `CONN_REQUEST/ACCEPT/REJECT` no puede ser un `ChatMessage` normal antes del handshake porque el `ChatMessage` actual solo existe después del Double Ratchet. Resolver ese punto antes de tocar TUI o `SessionManager` evita rehacer trabajo.
