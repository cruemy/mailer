# Sniff — Plan Técnico Completo

Descubrimiento automático de pares en LAN + múltiples chats 1:1 con frase secreta por conexión.

---

## 1. Stack y Dependencias

| Capa | Librería | Propósito |
|------|----------|-----------|
| Discovery | `tokio::net::UdpSocket` | Multicast UDP para heartbeat entre pares |
| Conexión | `rustls` + `tokio-rustls` | TLS 1.3 igual que el core actual |
| Handshake | `spake2` + `argon2` | PAKE + KDF por conexión (sin cambios) |
| E2EE | `x25519-dalek` + `chacha20poly1305` + `hkdf` | Double Ratchet (sin cambios) |
| TUI | `ratatui` + `crossterm` | Sidebar + multi-chat + input dinámico |
| Memoria | `os-memlock` + `zeroize` | Frase temporal bloqueada en RAM |

**Dependencias nuevas:** ninguna. Todo se resuelve con `tokio` (ya incluido) y la std de Rust.

---

## 2. ¿Qué cambia conceptualmente?

### Hoy (modelo mesh con frase global)

```
┌─────────────────────────────────────────────┐
│  TODOS CON UNA SOLA FRASE                   │
│                                             │
│  sesame --phrase "mariposa" --peer IP:PORT  │
│                                             │
│  ┌──────────┐                               │
│  │  Peer A  │── frase: "mariposa"           │
│  └──┬───┬───┘                               │
│     │   │                                   │
│  ┌──┘   └──┐                                │
│  ▼         ▼                                │
│ ┌────┐  ┌────┐                              │
│ │ B  │  │ C  │  ← todos usan "mariposa"    │
│ └────┘  └────┘                              │
│                                             │
│  UN solo chat: todo se mezcla en un panel   │
│  --phrase es OBLIGATORIO al arrancar        │
│  --peer es OBLIGATORIO (o te quedas solo)   │
└─────────────────────────────────────────────┘
```

### Mañana (chats 1:1 con frase por conexión)

```
┌─────────────────────────────────────────────┐
│  CADA CHAT CON SU PROPIA FRASE              │
│                                             │
│  sesame   ← sin args, solo arranca          │
│                                             │
│  ┌────────────────────────────────┐         │
│  │ SIDEBAR         │ CHAT ACTIVO  │         │
│  │                 │              │         │
│  │ ● a1b2  ◄───────┤ [you] hola  │         │
│  │ ○ f6e7           │ [a1b2] qué  │         │
│  │ ◇ 9a0b           │             │         │
│  │                 │ frase: **** │         │
│  └────────────────────────────────┘         │
│                                             │
│  a1b2 conectó con frase "perro"             │
│  f6e7 conectó con frase "gato"              │
│  Son INDEPENDIENTES — un chat por peer      │
│  --phrase ya NO es obligatorio              │
│  --peer ya NO es obligatorio (discovery)    │
└─────────────────────────────────────────────┘
```

---

## 3. Sniffing LAN — Multicast UDP

### ¿Por qué multicast y no otra cosa?

| Opción | Ventaja | Desventaja |
|--------|---------|------------|
| **Multicast UDP** | Simple, sin dependencias | No cruza routers |
| **mDNS (libmdns)** | Estándar (Bonjour/Avahi) | Dependencia externa, complejidad |
| **Broadcast UDP** | Funciona en toda subnet | Filtrado en VLANs modernas |
| **TCP port scan** | No requiere multicast | Lento, intrusivo, falsos positivos |

**Decisión:** multicast UDP. Es simple, no requiere dependencias nuevas, y el alcance es la red local exactamente como se necesita.

### Puerto y dirección

```
Dirección multicast: 239.255.0.42
Puerto UDP:          42069
Intervalo heartbeat: 10 segundos
Timeout offline:     30 segundos sin heartbeat
```

### Formato del heartbeat (JSON, < 256 bytes)

```json
{
  "magic": "sesame-sniff-v1",
  "peer_id": "a1b2c3d4e5f6...",
  "ip": "192.168.1.42",
  "port": 9000
}
```

### Diagrama de flujo

```
INSTANCIA A                           INSTANCIA B
────╂────                              ────╂────
   │                                      │
   ├── Crea UdpSocket ──────────────────  │
   ├── join_multicast(239.255.0.42:42069) │
   │                                      │
   ├── Envía heartbeat ── UDP ──────────► │
   │   { magic, peer_id, ip, port }       │
   │                                      ├── Recibe heartbeat
   │                                      ├── Añade A a sniffed_peers
   │                                      ├── Envía heartbeat ── UDP ──►
   │  ◄── UDP ──── Recibe heartbeat       │
   │  ├── Añade B a sniffed_peers        │
   │                                      │
   │  ─── cada 10s ─── heartbeat ──────►  │
   │  ◄── heartbeat ─── cada 10s ───      │
   │                                      │
   │  ─── si pasan 30s sin heartbeat ──   │
   │  ├── Marca B como offline            │
   │                                      │
   │  ─── B vuelve a aparecer ──          │
   │  ├── Marca B como online             │
```

### ¿Qué expone el heartbeat?

- `peer_id`: hash del cert efímero (cambia cada ejecución)
- `ip`: IP de interfaz de red
- `port`: puerto TCP donde escucha Sesame

No expone: frase, claves, contenido de chat, historial.

### Seguridad del sniffing

```
AMENAZA:                            MITIGACIÓN:
───────                             ──────────
Atacante envía heartbeat falso      Al conectar, SPAKE2 requiere la frase.
                                    Sin frase, el handshake FALLA.
                                    El peer falso solo aparece en la sidebar
                                    como "○ descubierto" — nunca conecta.

Atacante hace DoS al discovery      Rate limit natural: UDP no tiene conexión.
(envía miles de heartbeats)         Socket es NO BLOQUEANTE.
                                    Mapa de peers tiene límite interno (50).

Atacante escucha heartbeats         Solo expone IP + puerto + peer_id temporal.
(para saber quién usa Sesame)       peer_id cambia cada ejecución.
```

### API pública del SniffService

```rust
pub struct SniffService {
    peers: Arc<Mutex<HashMap<PeerId, SniffedPeer>>>,
}

struct SniffedPeer {
    addr: PeerAddr,
    last_seen: Instant,
    is_online: bool,
}

impl SniffService {
    pub fn start(my_id: PeerId, my_listen_port: u16, sniff_port: u16) -> Arc<Self>;
    pub fn get_peers(&self) -> Vec<SniffedPeerInfo>;
    pub fn stop(&self);
}
```

---

## 4. Frase por Conexión — Flujo Completo

### Estados de una conexión

```
DESCUBIERTO ──→ CONECTANDO ──→ ESPERANDO_FRASE ──→ HANDSHAKE ──→ CHATEANDO
     ↑                │               │                │              │
     └────────────────┴───────────────┴────────────────┘              │
     Error / rechazo / timeout                                       │
                                                                      │
     ◇ OFFLINE ──→ (vuelve a aparecer) ──→ DESCUBIERTO               │
                                                                      │
     CHATEANDO ──→ DESCONECTADO ──→ (sniff detecta) ──→ OFFLINE
```

### Diagrama del handshake por conexión

```
USUARIO A                          USUARIO B
(sesión con frase "secreto")       (sesión con frase "secreto")
────────────────────               ────────────────────

1. A selecciona a B en la sidebar
2. A ingresa frase en el prompt: "secreto" [Enter]
   │
3. ┌── FLUJO DE CONEXIÓN ───────────────────────────┐
   │                                                 │
   │  A → B: TCP connect + TLS handshake            │
   │  A → B: FLAG_CONN_REQUEST { peer_id: A }       │
   │                                                 │
   │  ── B recibe CONN_REQUEST ──                     │
   │  B muestra en TUI:                              │
   │  ╔═══════════════════════════╗                   │
   │  ║ a1b2c3d4 quiere           ║                   │
   │  ║ conectarse               ║                   │
   │  ║ Frase: [____________]    ║                   │
   │  ║ [Aceptar] [Rechazar]     ║                   │
   │  ╚═══════════════════════════╝                   │
   │                                                 │
   │  B ingresa frase: "secreto" [Enter]             │
   │  B → A: FLAG_CONN_ACCEPT                        │
   │                                                 │
   └─────────────────────────────────────────────────┘
   │
4. ┌── AUTH HANDSHAKE (SPAKE2 + Argon2id) ──────────┐
   │  Ambos ejecutan perform_handshake()              │
   │  cada uno con su frase ingresada                 │
   │                                                 │
   │  ├─ Salt exchange (32B c/u)                     │
   │  ├─ derive_key(frase, salts) → password_key     │
   │  ├─ SPAKE2 PAKE exchange                        │
   │  ├─ session_key = SHA256(pake || exporter ...)  │
   │  └─ Challenge-response (prueba mutua)           │
   │                                                 │
   │  SI frases coinciden:                           │
   │  ├─ X25519 DH → shared_secret                  │
   │  ├─ HKDF → root_chain → Double Ratchet          │
   │  ├─ Sesión registrada en SessionManager         │
   │  └─ CHAT ACTIVO                                 │
   │                                                 │
   │  SI frases NO coinciden:                        │
   │  ├─ SPAKE2 falla silenciosamente               │
   │  ├─ "Frase incorrecta" en TUI                    │
   │  ├─ Conexión TCP/TLS cerrada                    │
   │  └─ Peer vuelve a DESCUBIERTO                   │
   └─────────────────────────────────────────────────┘
```

### Propiedades de seguridad del handshake

| Propiedad | Cómo se garantiza |
|-----------|-------------------|
| **Zero-knowledge:** nadie revela su frase | SPAKE2: ambas partes obtienen el mismo secreto solo si usaron la misma frase. No hay intercambio de la frase en sí. |
| **Anti-offline:** no se puede brute-force offline | Sin interacción con un peer legítimo, no se puede verificar si una frase es correcta. |
| **Binding a la sesión:** no aplica a otra sesión | session_key incluye salts + TLS exporter + peer IDs + transcript. |
| **Forward secrecy:** si roban frase hoy, mensajes de ayer están seguros | Double Ratchet con DH ratchet cada 3 mensajes. |
| **Plausible deniability:** no hay prueba de origen | Sin firmas. Ambos peers tienen las mismas claves. |

### Tipos de mensaje nuevos (flags)

| Flag | Valor | Propósito |
|------|-------|-----------|
| `FLAG_CONN_REQUEST` | 8 | Solicitud de conexión entrante (body: PeerId del que solicita) |
| `FLAG_CONN_ACCEPT` | 9 | Aceptación de conexión (procede al handshake) |
| `FLAG_CONN_REJECT` | 10 | Rechazo explícito de conexión |

### ¿Qué pasa si dos personas intentan conectarse simultáneamente?

```
A intenta conectar a B  ──→  CONN_REQUEST
B intenta conectar a A  ──→  CONN_REQUEST

AMBOS reciben CONN_REQUEST al mismo tiempo.

RESULTADO:
  La primera CONN_REQUEST que llega gana.
  La segunda detecta que ya hay un handshake en curso para ese peer.
  → Se rechaza con "conexión simultánea, reintentá"

Esto es consistente con cómo funciona Signal/WhatsApp — 
primero uno inicia, el otro acepta.
```

---

## 5. Sidebar + Multi-Chat — Layout del TUI

### Layout completo

```
┌────────────────────────────────────────────────────┐
│  SESAME v0.1    ● 2 conectados   ○ 1 disponible   │
├──────────────┬─────────────────────────────────────┤
│  SNIFF (30%) │  CHAT CON: a1b2c3d4e5f6           │
│              │                                     │
│  ● a1b2c3d4  │  [you] hola, cómo andas            │
│  ● f6e7d8c9  │  [a1b2c3d4] todo bien! vos?       │
│  ○ 9a0b1c2d  │  [you] acá probando sesame         │
│  ◇ 3e4f5a6b  │                                     │
│  → deadbeef  │                                     │
│              │                                     │
├──────────────┴─────────────────────────────────────┤
│  Message: [__________________________________]    │
└────────────────────────────────────────────────────┘
```

### Iconografía de la sidebar

| Símbolo | Significado | Acción posible |
|---------|-------------|----------------|
| `●` | Conectado — chateando activamente | Enter para enfocar su chat |
| `○` | Descubierto en LAN, no conectado | Enter para iniciar conexión |
| `◇` | Offline — desapareció de la LAN | Esperar a que vuelva |
| `→` | Conectándose / handshake en progreso | Esperar... |
| `!` | Error al conectar (frase incorrecta) | Enter para reintentar |

### Navegación por teclado

| Tecla | Contexto | Acción |
|-------|----------|--------|
| `Tab` | Global | Alternar foco: sidebar ↔ chat |
| `↑` / `↓` | Sniff bar | Navegar lista de peers |
| `Enter` | Sniff bar (peer ○) | Iniciar conexión → modo frase |
| `Enter` | Sniff bar (peer ●) | Abrir/enfocar ese chat |
| `Enter` | Input frase | Enviar frase, iniciar handshake |
| `Enter` | Input mensaje | Enviar mensaje al chat activo |
| `Esc` | Input frase | Cancelar conexión, volver a sniff bar |
| `Esc` | Input mensaje | Salir del chat activo, volver a sniff bar |
| `Ctrl+W` | Chat activo | Cerrar chat (desconectar) |
| `R` | Notificación entrante | Rechazar conexión entrante |
| `A` | Notificación entrante | Aceptar conexión entrante |
| `F12` | Global | Pánico: zeroize + cerrar todo |

### Input dinámico

El input en la parte inferior cambia según el estado:

```
MODO NORMAL (chat activo):
┌────────────────────────────────────────────────────┐
│  Message: [_______________________________]       │
└────────────────────────────────────────────────────┘

MODO CONEXIÓN (iniciando):
┌────────────────────────────────────────────────────┐
│  Secret phrase for a1b2c3d4: [***************]     │
└────────────────────────────────────────────────────┘

MODO NOTIFICACIÓN ENTRANTE:
┌────────────────────────────────────────────────────┐
│  f6e7d8c9 wants to connect — Phrase: [________]  │
│  [Enter=accept  R=reject]                          │
└────────────────────────────────────────────────────┘
```

### Estado interno del TUI

```rust
struct TuiState {
    // Chat activo: qué peer estamos viendo
    active_chat: Option<PeerId>,

    // Múltiples historiales de chat
    chats: HashMap<PeerId, Vec<(PeerId, String, u8)>>,

    // Peers sniffeado (vía discovery + conectados)
    sniffed_peers: Vec<SniffedPeerInfo>,

    // Foco actual
    focus: FocusArea,  // SniffBar | Chat | Input

    // Modo del input
    input_mode: InputMode,  // Message | Phrase(PeerId) | ConnRequest(PeerId)

    // Para conexiones entrantes que esperan frase
    pending_requests: Vec<PeerId>,

    // ID local
    my_id: PeerId,
}
```

---

## 6. SessionManager — Refactor

### Antes vs. Después

```
ANTES (sesame-mvp-plan):
┌──────────────────────────────┐
│         SessionManager       │
│                              │
│  phrase: LockedBytes  ← global  │
│  sessions: HashMap<PeerId,  │
│    SessionHandle>            │
│  known_peers: HashMap<...>   │
│  discovery_tx: channel       │
│  broadcast() → a todos       │
└──────────────────────────────┘

DESPUÉS (sniff):
┌──────────────────────────────────┐
│         SessionManager            │
│                                  │
│  ❌ phrase eliminada (ya no hay) │
│                                  │
│  chats: HashMap<PeerId, Chat>    │
│  Chat {                          │
│    handle: SessionHandle,        │
│    messages: Vec<...>,           │
│    state: ConnectionState,       │
│    phrase: Option<LockedBytes>,  │
│  }                               │
│                                  │
│  ❌ known_peers (lo maneja sniff)│
│  ❌ broadcast() eliminado        │
│  ✅ send_to(peer_id, data)       │
│  ✅ get_chat(peer_id) -> &Chat   │
│  ✅ set_phrase(peer_id, phrase)  │
└──────────────────────────────────┘
```

### API nueva

```rust
impl SessionManager {
    // Reemplaza a broadcast()
    pub fn send_to(&self, peer_id: &PeerId, data: &[u8]) -> Result<(), &'static str>;

    // Gestión de frases por conexión
    pub fn set_phrase(&self, peer_id: &PeerId, phrase: LockedBytes);
    pub fn take_phrase(&self, peer_id: &PeerId) -> Option<LockedBytes>;

    // Estado de conexión
    pub fn set_connection_state(&self, peer_id: &PeerId, state: ConnectionState);
    pub fn get_connection_state(&self, peer_id: &PeerId) -> Option<ConnectionState>;

    // Chats
    pub fn get_or_create_chat(&self, peer_id: &PeerId) -> &mut Chat;
    pub fn close_chat(&self, peer_id: &PeerId);

    // Mensajes del chat (ahora por peer, no global)
    pub fn add_message(&self, peer_id: &PeerId, msg: ChatMessage);
    pub fn get_messages(&self, peer_id: &PeerId) -> Vec<ChatMessage>;
}
```

### Transición: lo que se elimina

| Método antiguo | Motivo |
|----------------|--------|
| `broadcast()` | Ya no hay "grupo". Cada mensaje va a un solo peer. |
| `broadcast_except()` | Idem. |
| `phrase()` | Ya no hay frase global. Cada peer tiene la suya. |
| `known_peers_list()` | Sniff maneja los peers conocidos. |
| `clear_known_peers()` | Sniff lo maneja. |
| `list_peer_addresses()` | Sniff tiene la lista de direcciones. |
| `send_discovered()` | Sniff expone peers vía `get_peers()`. |

### Lo que se mantiene

| Método | Cambio |
|--------|--------|
| `register_session()` | Se mantiene, pero ahora recibe `phrase` como parámetro en lugar de leer de `self.phrase`. |
| `remove_session()` | Se mantiene, pero sin broadcast de SYSTEM_ALONE (no aplica al nuevo modelo). |
| `panic_shutdown()` | Se mantiene. |
| `cancel_rx()` | Se mantiene. |
| `update_last_message()` | Se mantiene. |
| `spawn_timeout_checker()` | Se mantiene. |
| `system_msg()` | Se mantiene (para mensajes del sistema en el chat activo o notificaciones). |

---

## 7. peer.rs — Refactor

### Antes vs. Después

```
ANTES:
run_peer_session(stream, peer_id, addr, session_mgr, is_initiator)
  ├── phrase = session_mgr.phrase()   ← frase global
  ├── perform_handshake(phrase, ...)
  ├── FLAG_PEER_LIST_REQ automático
  └── loop: recibe mensajes, broadcast

DESPUÉS:
run_peer_session(stream, peer_id, addr, session_mgr, is_initiator)
  ├── phrase = session_mgr.take_phrase(&peer_id)   ← frase de este peer
  ├── perform_handshake(phrase, ...)
  ├── ❌ NO hay FLAG_PEER_LIST_REQ automático
  └── loop: recibe mensajes, send_to() al peer específico

connect_peer(addr, session_mgr, connector)
  ├── Antes: lee frase de session_mgr.phrase()
  └── Ahora: la frase ya fue asignada vía session_mgr.set_phrase()
```

### Flujo nuevo de conexión entrante

```rust
// En handle_incoming() — cuando alguien hace TCP connect
async fn handle_incoming(tls_stream, peer_addr, session_mgr) {
    // 1. Hacer TLS handshake (mTLS, certs efímeros)
    // 2. Extraer peer_id del cert
    // 3. Enviar FLAG_CONN_REQUEST al TUI
    // 4. ESPERAR a que el usuario ingrese una frase
    //    (o rechace la conexión)
    // 5. Si acepta → set_phrase() + comenzar handshake
    // 6. Si rechaza → FLAG_CONN_REJECT + cerrar
}
```

Esto implica que `handle_incoming` ya no puede ser fire-and-forget. Necesita:
1. Extraer peer_id inmediatamente (TLS ya lo da)
2. Enviar notificación al TUI
3. Esperar respuesta del usuario (o timeout)
4. Proceder con handshake o rechazar

### Timeout de espera de frase

Si el usuario no responde en 60 segundos a una `CONN_REQUEST`, se rechaza automáticamente:

```rust
const PHRASE_TIMEOUT: Duration = Duration::from_secs(60);
```

---

## 8. main.rs — Refactor

### Antes vs. Después

```
ANTES:
main()
  ├── Parse --phrase (OBLIGATORIO)
  ├── Parse --peer (opcional, pero si no hay te quedas solo)
  ├── Crear SessionManager con frase global
  ├── TLS listener + connector
  ├── Conectar a --peers conocidos
  ├── Reconnection loop cada 30s
  ├── Discovery channel (solo para peer_list_res)
  └── TUI event loop

DESPUÉS:
main()
  ├── Parse args (--phrase ya NO es obligatorio)
  ├── ❌ No se crea SessionManager con frase
  ├── TLS listener + connector
  ├── ✅ Iniciar SniffService (multicast UDP)
  ├── ❌ NO hay reconnection loop (lo maneja sniff)
  ├── ❌ NO hay discovery channel (lo maneja sniff)
  ├── ✅ Conectar a --peers conocidos (pide frase al conectar)
  └── TUI event loop (integrado con sniff + multi-chat)
```

### Nuevo event loop

```
loop {
    tokio::select! {
        // Eventos de teclado del TUI
        event = event_rx.recv() => {
            tui_state.handle_event(event);
            // Si el usuario inició conexión:
            //   → session_mgr.set_phrase(peer_id, phrase)
            //   → peer::connect_peer(addr, session_mgr, connector)
        }

        // Peers sniffeado via UDP multicast
        // (SniffService actualiza un Arc<Mutex<HashMap>>)
        // El TUI simplemente lee ese mapa en cada render

        // Mensajes entrantes (de peers conectados)
        msg = msg_rx.recv() => {
            tui_state.add_message_to_chat(peer_id, msg);
        }

        // Conexiones entrantes (CONN_REQUEST)
        conn_req = conn_req_rx.recv() => {
            tui_state.show_conn_request(peer_id);
        }

        // Aceptación/rechazo de conexión entrante
        conn_response = conn_resp_rx.recv() => {
            // El usuario respondió: tiene frase o rechazó
            match response {
                Accept(phrase) => {
                    session_mgr.set_phrase(peer_id, phrase);
                    // continuar handshake
                }
                Reject => {
                    enviar FLAG_CONN_REJECT
                }
            }
        }
    }
}
```

---

## 9. types.rs — Nuevos tipos y flags

```rust
// ── Nuevas flags ──
pub const FLAG_CONN_REQUEST: u8 = 8;
pub const FLAG_CONN_ACCEPT: u8 = 9;
pub const FLAG_CONN_REJECT: u8 = 10;

// ── Nuevo enum ──
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ConnectionState {
    Discovered,
    Connecting,
    AwaitingPhrase,
    Handshaking,
    Connected,
    Disconnected,
}

// ── Nueva struct ──
#[derive(Clone, Debug)]
pub struct SniffedPeerInfo {
    pub peer_id: PeerId,
    pub addr: PeerAddr,
    pub is_online: bool,
    pub last_seen: Instant,
    pub state: ConnectionState,
}
```

---

## 10. Cambios por archivo

| Archivo | Cambios |
|---------|---------|
| `Cargo.toml` | Sin cambios (tokio ya incluye UdpSocket) |
| `src/sniff.rs` | **Nuevo archivo.** `SniffService` con socket multicast UDP, heartbeat cada 10s, timeout 30s, `start()`, `stop()`, `get_peers()` |
| `src/types.rs` | `FLAG_CONN_REQUEST` (8), `FLAG_CONN_ACCEPT` (9), `FLAG_CONN_REJECT` (10). `ConnectionState` enum. `SniffedPeerInfo` struct. |
| `src/session.rs` | Eliminar `phrase: LockedBytes`. Reemplazar `sessions: HashMap<PeerId, SessionHandle>` por `chats: HashMap<PeerId, Chat>` donde `Chat` agrupa `SessionHandle` + mensajes + estado + frase. Eliminar `broadcast()` / `broadcast_except()`. Agregar `send_to()`, `get_or_create_chat()`, `set_phrase()`, `take_phrase()`, `close_chat()`, `set_connection_state()`. Eliminar `known_peers`, `discovery_tx`, `list_peer_addresses()`, `send_discovered()`. |
| `src/peer.rs` | `connect_peer()` recibe frase como parámetro (o la lee de `session_mgr.take_phrase()`). `run_peer_session()` recibe frase específica. Nuevo manejo de `FLAG_CONN_REQUEST` / `FLAG_CONN_ACCEPT` / `FLAG_CONN_REJECT`. Eliminar `FLAG_PEER_LIST_REQ` / `FLAG_PEER_LIST_RES` automático. `handle_incoming()` no es más fire-and-forget: notifica TUI y espera frase. Timeout de 60s para frase entrante. |
| `src/main.rs` | `--phrase` ya NO es obligatorio. Inicializar `SniffService`. Reemplazar reconnection loop por sniff. Integrar eventos de sniff + conexiones entrantes + multi-chat en el event loop. |
| `src/tui.rs` | Layout sidebar izquierda (30%) + chat (70%). `HashMap<PeerId, Vec<(PeerId, String, u8)>>` para múltiples chats. Input dinámico (Message ↔ Phrase). Navegación con Tab, ↑↓, Enter. Notificación de conexión entrante con prompt de frase + Aceptar/Rechazar. Iconografía de sidebar (● ○ ◇ → !). Cerrar chat con Ctrl+W. |
| `src/auth.rs` | Sin cambios estructurales. `perform_handshake()` ya acepta `phrase: &[u8]`. Solo cambia de dónde viene la frase. |
| `docs/USAGE.md` | Actualizar: `--phrase` ya no es obligatorio. Agregar sección de sniffing automático. Agregar controles de teclado nuevos. |
| `docs/SECURITY.md` | Agregar sección sobre seguridad de sniffing UDP. Agregar threat model del nuevo flujo. |

---

## 11. Roadmap de implementación

```
FASE 1 — SNIFFING LAN
  [ ] src/sniff.rs: SniffService con multicast UDP
  [ ] src/main.rs: integración básica (iniciar sniff al arrancar)
  [ ] src/types.rs: SniffedPeerInfo
  [ ] src/tui.rs: mostrar peers sniffeado en sidebar (solo lectura inicial)

FASE 2 — SESSIONMANAGER REFACTOR
  [ ] src/session.rs: eliminar frase global, agregar Chat struct
  [ ] src/session.rs: send_to() reemplaza a broadcast()
  [ ] src/session.rs: set_phrase() / take_phrase() por peer
  [ ] src/session.rs: ConnectionState tracking
  [ ] src/types.rs: ConnectionState enum + nuevas flags

FASE 3 — FRASE POR CONEXIÓN
  [ ] src/peer.rs: connect_peer() recibe frase por parámetro
  [ ] src/peer.rs: run_peer_session() usa frase específica
  [ ] src/peer.rs: FLAG_CONN_REQUEST + FLAG_CONN_ACCEPT + FLAG_CONN_REJECT
  [ ] src/peer.rs: handle_incoming() con espera de frase + timeout 60s
  [ ] src/main.rs: canal conn_req_rx / conn_resp_rx

FASE 4 — MULTI-CHAT TUI
  [ ] src/tui.rs: sidebar izquierda con lista de peers
  [ ] src/tui.rs: HashMap<PeerId, Vec<...>> para múltiples chats
  [ ] src/tui.rs: input dinámico (Message ↔ Phrase ↔ ConnRequest)
  [ ] src/tui.rs: navegación Tab, ↑↓, Enter, Esc, Ctrl+W
  [ ] src/tui.rs: notificación de conexión entrante
  [ ] src/tui.rs: render condicional según ConnectionState

FASE 5 — LIMPIEZA Y TESTS
  [ ] tests: sniff loopback multicast (2 instancias en localhost)
  [ ] tests: handshake con frase correcta → conexión exitosa
  [ ] tests: handshake con frase incorrecta → falla silenciosa
  [ ] tests: 3 peers simultáneos cada uno con su frase
  [ ] tests: timeout de frase entrante (60s)
  [ ] tests: conexión simultánea (race condition)
  [ ] docs: actualizar USAGE.md y SECURITY.md
```

---

## 12. Tradeoffs y Decisiones

| Decisión | Alternativa | Por qué |
|----------|-------------|---------|
| **Multicast UDP** para sniffing | mDNS (libmdns) | 0 dependencias externas, simple, suficiente para LAN |
| **Frase por conexión** | Frase global (modelo actual) | Privacidad: cada chat es independiente. No comparten clave |
| **Handshake síncrono con espera de frase** | Handshake sin frase primero, luego preguntar | Más seguro: no se revela peer_id sin frase aceptada |
| **Timeout 60s para frase entrante** | Sin timeout | Evita conexiones colgadas si el usuario no responde |
| **Sidebar izquierda** | Sidebar derecha (layout actual) | Consistente con Telegram/WhatsApp/Signal |
| **Historial en RAM** | Persistencia en disco | Principio efímero: al cerrar, no queda rastro |
| **Eliminar broadcast grupal** | Mantener broadcast + multi-chat | Inconsistente: si cada chat tiene su frase, no hay "grupo" |
| **Sniff como servicio separado** | Sniff integrado en SessionManager | Separación de concerns: sniff es red, sesión es estado |
| **Solo 1:1, sin grupos** | Mesh grupal con sender keys | El usuario pidió múltiples chats con frases distintas |
| **Conexión manual desde sidebar** | Auto-conectar a todos los sniffeado | Usuario controla con quién comparte frase |

---

## 13. Comportamiento ante Fallos

| Escenario | Comportamiento |
|-----------|----------------|
| **Sniff no disponible** (puerto 42069 ocupado) | Warning en TUI. App funciona igual con `--peer` manual. |
| **Frase incorrecta** al conectar | SPAKE2 falla. TUI muestra: "Frase incorrecta para a1b2c3d4". Peer vuelve a ○. |
| **Timeout de frase entrante** (usuario no responde en 60s) | Se rechaza automáticamente. Peer que intentó conectar ve: "Conexión rechazada — timeout". |
| **Peer se desconecta de la LAN** | Sniff deja de recibir heartbeats → 30s después → `◇ offline` en sidebar. Chat activo muestra "a1b2c3d4 se desconectó". |
| **Peer vuelve a la LAN** | Sniff recibe heartbeat → `○ online` en sidebar. Chat anterior ya no existe (nuevo cert = nuevo PeerId). |
| **Dos conexiones simultáneas** | Primera gana. Segunda recibe "conexión simultánea — reintentá". |
| **El mismo peer conecta dos veces** | `register_session()` detecta duplicado y rechaza. |
| **F12 durante handshake con frase en RAM** | `panic_shutdown()` zeroiza frase temporal + cierra todo. |
| **Se cierra el chat activo (Ctrl+W)** | `close_chat()` → `remove_session()` → peer vuelve a `○` descubierto sin conexión. |
| **Reboot de red (router, switch)** | Todas las conexiones TCP caen. Sniff reinicia heartbeats. Peers reaparecen gradualmente. |

---

## 14. Contra qué NO vamos

- No vamos a implementar un PAKE propio — SPAKE2 ya está.
- No vamos a persistir historial en disco — la app es efímera.
- No vamos a auto-conectar a todos los peers sniffeado — el usuario elige.
- No vamos a mantener broadcast grupal — no tiene sentido con frases distintas.
- No vamos a cruzar NAT/routers — sniff es solo LAN.
- No vamos a agregar "grupos" — el modelo es 1:1.

---

## 15. Definición de terminado

El plan `sniff` se considera completo solo si:

- `cargo check` y `cargo test` pasan sin errores.
- Dos instancias en la misma LAN se descubren mutuamente en ≤ 15 segundos.
- Una conexión con frase correcta establece chat en ≤ 5 segundos (post-TLS).
- Una conexión con frase incorrecta falla sin revelar qué frase se usó.
- El TUI muestra sidebar con iconografía correcta para cada estado.
- Se pueden tener 3+ chats simultáneos, cada uno con su frase.
- Al cerrar con Ctrl+W, el peer vuelve a estado descubierto.
- F12 zeroiza frases temporales y cierra todo el proceso.
- `docs/USAGE.md` documenta el nuevo flujo de sniffing + frase por conexión.
