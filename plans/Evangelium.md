# Discovery LAN + Chats Multiples con Frase por Conexión

## Resumen

Convertir Sesame de un chat grupal con frase global a un cliente con descubrimiento automático de peers en LAN + múltiples chats 1:1 independientes, cada uno con su propia frase secreta ingresada al momento de conectar.

---

## 1. Arquitectura Actual vs. Propuesta

### Hoy (mesh grupal con frase global)

```
sesame --peer 192.168.1.5:9000 --phrase "secreto"

Frase global → todos usan la misma → grupo mesh
Un solo panel de chat mezclado (todos los mensajes juntos)
Peer list en columna derecha
```

### Mañana (chats 1:1 con descubrimiento)

```
sesame  (sin args — o con --port opcional)

Discovery UDP multicast → detecta peers en LAN
Cada peer es un chat independiente
Frase se ingresa AL CONECTAR, no al arrancar
Múltiples chats abiertos simultáneamente
```

---

## 2. Discovery LAN — Multicast UDP

### Cómo funciona

Cada instancia de Sesame envía un heartbeat periódico por UDP multicast. Escucha heartbeats de otras instancias. Así se descubren sin configurar IPs manualmente.

```
Puerto multicast UDP: 42069
Dirección multicast:  239.255.0.42
Intervalo heartbeat:  10 segundos
Timeout de peer:      30 segundos sin heartbeat → se marca como offline
```

### Formato del heartbeat (JSON, < 256 bytes)

```json
{
  "magic": "sesame-v1",
  "port": 9000,
  "peer_id": "a1b2c3d4...",
  "ip": "192.168.1.5"
}
```

### Flujo

```
1. Instancia inicia → crea socket UDP multicast
2. Se une al grupo multicast 239.255.0.42:42069
3. Envía heartbeat inmediato (presencia inicial)
4. Escucha heartbeats de otros peers en el mismo grupo
5. Cada 10s reenvía heartbeat
6. Si no recibe heartbeat de un peer por 30s → lo muestra como desconectado
7. Al seleccionar un peer detectado → inicia conexión TCP/TLS
```

### ¿Por qué multicast UDP y no mDNS?

| Opción | Ventaja | Desventaja |
|--------|---------|------------|
| **Multicast UDP** | Simple, sin dependencias extra | No atraviesa routers |
| **mDNS** | Estándar, usado por avahi/bonjour | Dependencia `libmdns`, más complejo |
| **Broadcast UDP** | Funciona en toda subnet | No funciona en VLANs modernas |

Elegimos **multicast UDP** por simplicidad y porque es la red local el alcance esperado.

### Nuevo flag CLI

```
--discovery-port  N    Puerto multicast UDP (default: 42069)
--no-discovery         Deshabilitar discovery (útil si solo se quiere --peer manual)
```

---

## 3. Frase por Conexión — Flujo Completo

### Estados de una conexión

```
DESCUBIERTO → CONECTANDO → ESPERANDO_FRASE → HANDSHAKE → CHATEANDO
```

### Paso a paso

```
USUARIO A                          USUARIO B
─────────                          ─────────

1. A ve a B en la sidebar
2. A selecciona a B → "Iniciar conexión..."
3. A ingresa frase: "mi-secreto"
   ──────────────────────────────────────►
4. A conecta TCP → TLS → envía
   CONNECTION_REQUEST (con PeerId de A)
   ──────────────────────────────────────►
5.                                    B recibe NOTIFICACIÓN:
                                      "A quiere conectarse"
                                      "Ingresá la frase secreta:"
6.                                    B ingresa frase: "mi-secreto"
   ◄──────────────────────────────────
7. AMBOS ejecutan perform_handshake()
   con la frase que cada uno ingresó
   ├─ SPAKE2 + Argon2id + challenge-response
   ├─ Si OK → Double Ratchet + sesión establecida
   └─ Si FAIL → "Frase incorrecta" + cierre
8.           ◄─── CHAT ABIERTO ───►
```

### ¿Qué pasa si las frases no coinciden?

SPAKE2 garantiza que si ambas partes usan distinta frase, el handshake falla. Ningún lado revela su frase — solo saben "no coincide". Se muestra un mensaje de error y se cierra la conexión. El peer vuelve a estado DESCUBIERTO.

### Tipos de mensajes nuevos (flags)

| Flag | Nombre | Propósito |
|------|--------|-----------|
| `FLAG_CONN_REQUEST` | 8 | Solicitud de conexión entrante |
| `FLAG_CONN_ACCEPT` | 9 | Aceptación (procede al handshake) |
| `FLAG_CONN_REJECT` | 10 | Rechazo explícito |

---

## 4. Sidebar Izquierda — Nuevo Layout TUI

### Layout

```
┌──────────────┬─────────────────────────────┐
│  PEERS (30%) │     CHAT: a1b2c3d4...       │
│              │                             │
│  ● a1b2c3d4  │  [you] hola                 │
│  ○ f6e7d8c9  │  [a1b2...] qué tal          │
│  ◇ 9a0b1c2d  │                             │
│  ○ 3e4f5a6b  │                             │
│              │                             │
│              │                             │
├──────────────┴─────────────────────────────┤
│  Message: [_____________________________]  │
└────────────────────────────────────────────┘
```

### Iconografía de la sidebar

| Símbolo | Significado |
|---------|-------------|
| `●` | Conectado y chateando |
| `○` | Descubierto en LAN, no conectado |
| `◇` | Desconectado (se fue de la LAN) |
| `→` | Conectándose / handshake en progreso |
| `!` | Error al conectar |

### Navegación

- `Tab` / `Shift+Tab` — cambiar entre sidebar y panel de chat
- `↑` / `↓` — navegar lista de peers en la sidebar
- `Enter` en un peer desconectado → inicia conexión
- `Esc` en la sidebar → vuelve al panel de chat activo
- `Ctrl+W` — cerrar chat activo

### Input de frase

Cuando se inicia una conexión, el input cambia temporalmente de "Message" a "Secret phrase for <peer>:". Al presionar Enter, la frase se envía y comienza el handshake. El input vuelve a "Message".

---

## 5. Múltiples Chats Simultáneos

### Estado interno

Cada chat se identifica por `PeerId` y mantiene:

```rust
struct ChatState {
    peer_id: PeerId,
    peer_addr: PeerAddr,
    messages: Vec<(PeerId, String, u8)>,  // historial propio
    state: ConnectionState,
    phrase: Option<LockedBytes>,  // frase solo en RAM durante handshake
}
```

`SessionManager` pasa a manejar `HashMap<PeerId, ChatState>` en lugar de `sessions: HashMap<PeerId, SessionHandle>`.

### Broadcast

Se elimina el concepto de broadcast global. Cada mensaje se envía solo al chat activo.

```rust
// Antes: session_mgr.broadcast(&data)  → a todos
// Ahora: session_mgr.send_to(&peer_id, &data) → solo a ese peer
```

### Persistencia de historial

Los mensajes viven en RAM mientras el chat está abierto. Si se cierra el chat (Ctrl+W), se descartan. Si el peer se reconecta, se empieza de cero (identidad efímera).

---

## 6. Cambios por Archivo

### `Cargo.toml` — Dependencias nuevas

No se requieren dependencias nuevas. `tokio` ya tiene `UdpSocket`. El manejo de multicast es parte de la std de Rust + tokio.

### `src/discovery.rs` — **NUEVO ARCHIVO** (~120 líneas)

```rust
pub struct DiscoveryService {
    socket: tokio::net::UdpSocket,
    peers: Arc<Mutex<HashMap<PeerId, DiscoveredPeer>>>,
    peer_timeout: Duration,
}

struct DiscoveredPeer {
    addr: PeerAddr,
    last_seen: Instant,
    state: DiscoveredPeerState,
}

enum DiscoveredPeerState {
    Online,
    Offline,
}
```

Funciones:
- `start_discovery(my_addr, my_id, discovery_port)` → spawn tareas heartbeat + listener
- `handle_heartbeat(msg, sender_addr)` → actualiza mapa de peers descubiertos
- `get_discovered_peers()` → lista de peers vistos recientemente
- `mark_offline(peer_id)` → marca como offline

### `src/types.rs` — Nuevas flags + estados

```rust
pub const FLAG_CONN_REQUEST: u8 = 8;
pub const FLAG_CONN_ACCEPT: u8 = 9;
pub const FLAG_CONN_REJECT: u8 = 10;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    Discovered,
    Connecting,
    AwaitingPhrase,
    Handshaking,
    Connected,
    Disconnected,
}
```

### `src/session.rs` — Refactor mayor

**Cambios clave:**

1. **Eliminar `phrase: LockedBytes` del SessionManager** — ya no es global
2. **`ChatState` reemplaza a `SessionHandle` como unidad de estado** — agrupa sesión + mensajes + estado de conexión
3. **Nuevos métodos:**
   - `get_or_create_chat(peer_id) -> &mut ChatState`
   - `send_to(peer_id, data)` — envía solo a ese peer
   - `set_chat_phrase(peer_id, phrase)` — asigna frase para handshake
   - `initiate_connection(peer_id)` — inicia flujo de conexión
   - `handle_connection_request(from_peer)` — recibe solicitud
4. **Eliminar:**
   - `broadcast()` / `broadcast_except()` — ya no aplica
   - `phrase()` — ya no es global
   - `known_peers` — ahora lo maneja discovery

### `src/peer.rs` — Refactor medio

**Cambios clave:**

1. `connect_peer()` recibe `phrase: LockedBytes` como parámetro (no de SessionManager)
2. `run_peer_session()` recibe la frase para ese peer específico
3. Nuevo flujo de `FLAG_CONN_REQUEST`:
   - Receptor pausa handshake, notifica TUI
   - TUI pide frase al usuario
   - Receptor responde con frase ingresada
   - Handshake procede
4. Eliminar `FLAG_PEER_LIST_REQ` / `FLAG_PEER_LIST_RES` del flujo automático

### `src/auth.rs` — Sin cambios estructurales

La función `perform_handshake()` ya acepta `phrase: &[u8]` como parámetro. El cambio es de dónde viene esa frase (antes de SessionManager, ahora del ChatState).

### `src/tui.rs` — Refactor mayor (~400 líneas nuevas)

**Cambios clave:**

1. **Layout nuevo:** sidebar izquierda (30%) + chat (70%)
2. **`MultiChatState`:** en lugar de un solo `messages: Vec`, tener `HashMap<PeerId, Vec<(PeerId, String, u8)>>`
3. **`active_chat: Option<PeerId>`:** cuál chat se está viendo
4. **Sidebar interactiva:** navegación con ↑↓, selección con Enter
5. **Flujo de input dinámico:**
   - Modo normal: input de mensaje para el chat activo
   - Modo conexión: input de frase secreta para conectar
6. **Notificaciones:** mostrar toast/barra de conexión entrante
7. **Teclas nuevas:**
   - `Tab` / `Shift+Tab`: cambiar foco sidebar ↔ chat
   - `Ctrl+W`: cerrar chat activo
   - `R`: rechazar conexión entrante

### `src/main.rs` — Cambios moderados

1. **CLI:** `--phrase` pasa a ser opcional (solo si se quiere frase preconfigurada para --peer)
2. **Al arrancar sin `--phrase`:** no se requiere, solo se inicia discovery
3. **Inicializar `DiscoveryService`** y pasar su `discovered_peers` al TUI
4. **Manejar eventos de discovery** junto con eventos de TUI y mensajes
5. **Conexiones desde discovery:** cuando el usuario selecciona un peer descubierto
6. **Manejar `FLAG_CONN_REQUEST`** en el message loop
7. **Integrar múltiples chats** en el event loop principal

---

## 7. Flujo de UI — Estados de Pantalla

### Pantalla inicial (sin peers)

```
┌──────────────┬──────────────────────────────┐
│  PEERS       │   SESAME v0.1                │
│              │                              │
│  (buscando   │   Escuchando en :9000        │
│   peers...)  │   Discovery en 239.255.0.42  │
│              │                              │
│              │   No hay peers detectados     │
│              │   en la red local             │
│              │                              │
│              │   ↑↓ navegar · Enter conectar │
│              │   Tab cambiar foco            │
├──────────────┴──────────────────────────────┤
│  Message: [                            ]    │
└─────────────────────────────────────────────┘
```

### Conectando (input de frase)

```
┌──────────────┬──────────────────────────────┐
│  PEERS       │   Conectando a: a1b2c3d4     │
│              │                              │
│  → a1b2c3d4  │   Ingresá la frase secreta   │
│  ○ f6e7d8c9  │   para esta conexión:        │
│              │                              │
│              │                              │
│              │                              │
├──────────────┴──────────────────────────────┤
│  Phrase: [***************************]      │
└─────────────────────────────────────────────┘
```

### Chat activo

```
┌──────────────┬──────────────────────────────┐
│  PEERS       │   Chat con: a1b2c3d4         │
│              │                              │
│  ● a1b2c3d4  │  [you] hola                  │
│  ○ f6e7d8c9  │  [a1b2c3d4] qué tal          │
│  ◇ 9a0b1c2d  │                              │
│              │                              │
│              │                              │
├──────────────┴──────────────────────────────┤
│  Message: [___________________________]     │
└─────────────────────────────────────────────┘
```

### Notificación de conexión entrante

```
┌──────────────┬──────────────────────────────┐
│  PEERS       │                              │
│              │  ╔═══════════════════════╗    │
│  ○ a1b2c3d4  │  ║ CONEXIÓN ENTRANTE     ║    │
│  ○ f6e7d8c9  │  ║ f6e7d8c9 quiere       ║    │
│              │  ║ conectarse            ║    │
│              │  ║ Ingresá la frase: __  ║    │
│              │  ║ [Aceptar] [Rechazar]  ║    │
│              │  ╚═══════════════════════╝    │
├──────────────┴──────────────────────────────┤
│  Phrase: [                             ]    │
└─────────────────────────────────────────────┘
```

---

## 8. Consideraciones de Seguridad

### La frase secreta

- Nunca viaja en texto plano sobre la red (SPAKE2 es zero-knowledge)
- Vive en `LockedBytes` solo durante el handshake
- Se zeroiza inmediatamente después de derivar `session_key`
- No se persiste en disco
- Cada conexión tiene su propia frase independiente

### Discovery UDP

- El heartbeat solo expone: PeerId, IP, puerto
- No revela frases ni claves
- Posible suplantación: un atacante en la LAN puede enviar heartbeats falsos
- Mitigación: al conectar, el handshake SPAKE2 falla si no saben la frase
- El atacante solo logra que aparezca un peer falso en la sidebar — nunca conecta sin la frase

### Eliminación de broadcast

- Ya no hay broadcast de mensajes a todos los peers
- Cada mensaje viaja solo al destinatario
- Mitigación de fuga de información: un peer no sabe a quién más le estás escribiendo

---

## 9. Roadmap de Implementación

### Fase 1 — Discovery UDP

| # | Tarea | Archivo | Estimado |
|---|-------|---------|----------|
| 1.1 | Crear `DiscoveryService` con socket multicast | `src/discovery.rs` (nuevo) | 2h |
| 1.2 | Integrar discovery en `main.rs` | `src/main.rs` | 30min |
| 1.3 | Mostrar peers descubiertos en el TUI | `src/tui.rs` | 1h |

### Fase 2 — Refactor de SessionManager

| # | Tarea | Archivo | Estimado |
|---|-------|---------|----------|
| 2.1 | Eliminar frase global de `SessionManager` | `src/session.rs` | 30min |
| 2.2 | Agregar `ChatState` con frase por conexión | `src/session.rs` | 1h |
| 2.3 | Cambiar broadcast → `send_to()` | `src/session.rs` + `src/tui.rs` | 30min |
| 2.4 | Agregar `ConnectionState` enum | `src/types.rs` | 15min |

### Fase 3 — Frase por conexión

| # | Tarea | Archivo | Estimado |
|---|-------|---------|----------|
| 3.1 | Modificar `connect_peer()` para recibir frase | `src/peer.rs` | 30min |
| 3.2 | Agregar `FLAG_CONN_REQUEST/ACCEPT/REJECT` | `src/peer.rs` + `src/types.rs` | 1h |
| 3.3 | Flujo de conexión entrante con prompt de frase | `src/peer.rs` + `src/tui.rs` | 2h |
| 3.4 | Manejar timeout de handshake por frase incorrecta | `src/peer.rs` | 30min |

### Fase 4 — Multi-chat TUI

| # | Tarea | Archivo | Estimado |
|---|-------|---------|----------|
| 4.1 | Sidebar izquierda con lista de peers | `src/tui.rs` | 1h |
| 4.2 | Múltiples paneles de chat (`HashMap<PeerId, Vec<...>>`) | `src/tui.rs` | 1h |
| 4.3 | Navegación con ↑↓ + Tab + Enter | `src/tui.rs` | 1h |
| 4.4 | Input dinámico (message ↔ phrase) | `src/tui.rs` | 1h |
| 4.5 | Notificación de conexión entrante | `src/tui.rs` | 1h |
| 4.6 | Cerrar chat con `Ctrl+W` | `src/tui.rs` | 30min |

### Fase 5 — Limpieza y tests

| # | Tarea | Archivo | Estimado |
|---|-------|---------|----------|
| 5.1 | Test de discovery (loopback multicast) | `tests/` | 1h |
| 5.2 | Test de frase incorrecta → handshake falla | `tests/` | 30min |
| 5.3 | Test de múltiples chats simultáneos | `tests/` | 1h |
| 5.4 | Actualizar docs y CLI help | `docs/USAGE.md` + `src/main.rs` | 30min |

---

## 10. Dependencias Nuevas

Ninguna. `tokio::net::UdpSocket` ya está incluido con `tokio = { version = "1", features = ["full"] }`.

---

## 11. Comportamiento ante Fallos

| Escenario | Comportamiento |
|-----------|---------------|
| Discovery no disponible (puerto ocupado) | Warning en TUI, el app sigue funcionando con `--peer` manual |
| Frase incorrecta al conectar | "Frase incorrecta" + peer vuelve a `Discovered` |
| Peer se desconecta de la red | Se marca `◇ Offline` en sidebar después de 30s |
| Reconexión: peer vuelve a aparecer | Vuelve a `○ Online`, usuario puede reconectar |
| F12 durante handshake | Zeroize de frase temporal + cierre seguro |
| Dos peers conectan simultáneamente | Primera conexión gana, segunda falla con "sesión duplicada" |

---

## 12. Uso Final

### Descubrimiento automático + chat manual

```bash
# Solo funciona si están en la misma LAN
# ---
# Terminal 1 (Peer A):
sesame

# Terminal 2 (Peer B):
sesame

# Ambos ven al otro en la sidebar
# A selecciona a B → ingresa frase "foo"
# B recibe notificación → ingresa frase "foo"
# ✅ Conexión establecida, pueden chatear

# A selecciona a C → ingresa frase "bar"
# C recibe notificación → ingresa frase "bar"
# ✅ Segunda conexión independiente
```

### Sin discovery (modo legacy)

```bash
sesame --peer 192.168.1.5:9000  # se le pedirá frase al conectar
```

### Red local sin multicast

Si multicast no está disponible (ej: algunas VLANs configuradas), se puede especificar un peer manualmente. El discovery es la puerta de entrada, pero no el único camino.

---

## 13. Tradeoffs y Decisiones

| Decisión | Alternativa | Por qué |
|----------|-------------|---------|
| **Multicast UDP** vs mDNS | mDNS requiere libmdns | Simple, sin dependencias, 0 config |
| **Phrase por conexión** vs frase global | Modelo grupal actual | Privacidad entre chats, cada conexión es independiente |
| **Historial en RAM** vs persistencia en disco | Disco permite reanudar | Identidad efímera: al cerrar app, no queda rastro |
| **Sidebar izquierda** vs derecha | Layout actual (derecha) | Consistente con Telegram/WhatsApp (izquierda) |
| **SPAKE2 sin cambios** vs nuevo protocolo | Otro PAKE | SPAKE2 ya funciona, solo cambia de dónde viene la frase |
| **Conexión manual desde sidebar** vs auto-conectar a todos descubiertos | Auto-conectar simplificaría | El usuario debe elegir con quién compartir frase |
