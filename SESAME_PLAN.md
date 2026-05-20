# Sesame — Plan Técnico Completo v2

Chat P2P efímero con doble cifrado, ofuscación de metadatos, anti-coerción y doble ratchet.

---

## 1. Stack Completo

| Capa | Librería | Propósito |
|---|---|---|
| Async runtime | `tokio` (full) | I/O + eventos |
| TLS 1.3 | `rustls` + `tokio-rustls` | Cifrado capa externa, forward secrecy, anti-MITM |
| Certs efímeros | `rcgen` + `rustls-pemfile` | Ed25519 keypair nuevo cada ejecución, en RAM |
| E2EE (Double Ratchet) | `double-ratchet` + `x25519-dalek` + `hkdf` | Cifrado capa interna, self-healing, forward secrecy |
| Cifrado simétrico | `chacha20poly1305` | ChaCha20 + Poly1305 para mensajes |
| Key derivation | `argon2` | Frase + salt → session key (resistente a GPU/ASIC) |
| CSPRNG | `rand` (kernel `getrandom`) | Salts, nonces, DH keypairs |
| Serialización | `serde` + `serde_json` | Mensajes |
| TUI | `ratatui` + `crossterm` | Interfaz tipo Telegram |
| **mlock** | `mlock` | Bloquear claves en RAM, evitar que vayan a swap/disco |
| **zeroize** | `zeroize` | Borrado seguro de claves en RAM (memset_s) |

---

## 2. ¿Qué gano con `mlock()`?

```
SIN mlock():                              CON mlock():
┌────────────────────┐                    ┌────────────────────┐
│  RAM del proceso   │                    │  RAM del proceso   │
│  ┌──────────────┐  │                    │  ┌──────────────┐  │
│  │ session_key  │  │                    │  │ session_key  │◄─│─ LOCKED
│  │ root_chain   │  │                    │  │ root_chain   │◄─│─ LOCKED
│  │ private_keys │  │                    │  │ private_keys │◄─│─ LOCKED
│  └──────┬───────┘  │                    │  └──────────────┘  │
│         │          │                    └────────────────────┘
│         ▼          │                           │
│    SWAP A DISCO    │                    ╔══════╧══════════════╗
│  ┌──────────────┐  │                    ║  NUNCA VAN A DISCO  ║
│  │ session_key  │  │                    ║  Solo existen en RAM║
│  │ root_chain   │  │                    ║  zeroize()+exit=0   ║
│  │ ...          │  │                    ╚═════════════════════╝
│  └──────────────┘  │
│  (sobrevive al     │
│   cierre del app)  │
└────────────────────┘

mlock() llama a VirtualLock() en Windows, mlock() en POSIX.
```

**Escenario real:** el kernel necesita memoria → swappea páginas de tu proceso al disco. Esas páginas contienen `session_key`, las cadenas del ratchet, DH private keys, etc. El usuario cierra la app. Horas después, alguien con acceso al disco hace `strings /swapfile | grep` y encuentra fragmentos de claves.

Con `mlock()`: las páginas marcadas están **ancladas en RAM físicas**. No se swappean jamás. El OS prefiere matar procesos antes que forzar el desbloqueo.

**En Rust:** crate `mlock` abstrae esto cross-platform. Se usa así:

```rust
use mlock::Mlock;
use zeroize::Zeroize;

let mut secret = [0u8; 32];
let locked = Mlock::new(&mut secret)?; // ← anclado en RAM
// ... usar secret ...
drop(locked); // ← unlock automático
secret.zeroize(); // ← sobrescribe en RAM antes de soltar
```

---

## 3. Arquitectura en Capas (de afuera hacia adentro)

```
┌─────────────────────────────────────────────────────────┐
│                    CAPA DE USUARIO                       │
│  TUI (ratatui): burbujas, input, barra de estado        │
│  Panel de conexiones (ver peers conectados)              │
├─────────────────────────────────────────────────────────┤
│               CAPA DE OFUSCACIÓN (ANTI-METADATOS)        │
│  • Padding a tamaño fijo (1400 bytes)                    │
│  • Tráfico dummy cifrado a intervalos aleatorios         │
│  • Plausible deniability (sin firmas digitales)          │
├─────────────────────────────────────────────────────────┤
│            CAPA E2EE — DOUBLE RATCHET                    │
│  • X25519 DH ratchet (cada 3 mensajes)                   │
│  • Symmetric key ratchet (cada mensaje)                  │
│  • msg_key = HKDF(chain_key) → ChaCha20-Poly1305        │
│  • Self-healing: si roban clave, próximo DH la repara    │
│  • **1 estado de ratchet por peer conectado**            │
├─────────────────────────────────────────────────────────┤
│         CAPA DE AUTENTICACIÓN + DERIVACIÓN               │
│  • Intercambio de salts (32B cada uno)                   │
│  • Argon2id(frase, salt, 64MB, 3 iter) → session_key    │
│  • HKDF(session_key, contextos) → root_key + chains      │
│  • Challenge-response prueba que ambos saben la frase    │
├─────────────────────────────────────────────────────────┤
│              CAPA TLS 1.3 (TRANSPORTE)                   │
│  • mTLS: ambos presentan cert efímero Ed25519            │
│  • X25519 ephemeral → Perfect Forward Secrecy            │
│  • ChaCha20-Poly1305 (negociado por rustls)              │
│  • Anti-replay, anti-MITM a nivel de red                 │
├─────────────────────────────────────────────────────────┤
│          CAPA DE GESTIÓN DE CONEXIONES                   │
│  • SessionManager: mapa de peers conectados              │
│  • 1 listener + N conexiones salientes                   │
│  • Misma frase para todos → mismo pool de salts          │
├─────────────────────────────────────────────────────────┤
│                  CAPA TCP (tokio)                        │
│  • Conexión directa (IP:puerto)                          │
│  • Listener + connector (P2P)                            │
└─────────────────────────────────────────────────────────┘
```

---

## 4. Gestión de Conexiones — Sesiones Simultáneas

### ¿Qué pasa si N personas usan la misma frase?

```
                ┌──────────────┐
                │   Peer A     │
                │ frase: "..." │
                └──┬───┬───┬──┘
                   │   │   │
       ┌───────────┘   │   └───────────┐
       ▼               ▼               ▼
 ┌──────────┐   ┌──────────┐   ┌──────────┐
 │  Peer B  │   │  Peer C  │   │  Peer D  │
 │ frase:"  │   │ frase:"  │   │  frase:  │
 └──────────┘   └──────────┘   └──────────┘

Cada par (A-B, A-C, A-D, B-C, B-D, C-D):
├─ TLS unique (certs únicos, X25519 ephemeral distinto)
├─ Salt exchange único (salt_A_B ≠ salt_A_C)
├─ session_key ÚNICA (misma frase + salt distinto)
├─ Double Ratchet independiente (root_chain distinta)
└─ Canal indistinguible para un observador externo
```

### SessionManager

```rust
struct SessionManager {
    sessions: HashMap<PeerId, Session>,
    listener: TcpListener,
    phrase: String,           // compartida
    max_sessions: usize,      // límite configurable
}

struct Session {
    peer_id: PeerId,          // hash del cert público (identidad única)
    tls_stream: TlsStream<TcpStream>,
    ratchet: DoubleRatchet,   // estado independiente
    connected_since: Instant,
    last_message: Instant,
}

struct PeerId([u8; 32]);  // SHA256(cert_public_key_der)
```

**Cada peer se identifica por el hash de su cert efímero** — dos instancias del mismo usuario en distinta máquina son dos `PeerId` distintos. La frase no identifica, solo autentica.

### Límites configurables

```
sesame --peer 192.168.1.10:9000 --phrase "mariposa-azul-42"
       --max-peers 5          # máximo conexiones simultáneas
       --same-ip-limit 1      # 1 conexión por IP

Comportamiento cuando se excede:
• --max-peers: rechazar nuevas conexiones (mostrar en TUI "grupo lleno")
• --same-ip-limit: rechazar segunda conexión desde misma IP
• Timeout de inactividad: drop automático si > X min sin mensajes
```

### Malla de conexiones por peer (topología)

```
CADA PEER MANTIENE:
┌─ Peer ─────────────────────────────────┐
│                                         │
│  LISTENER (entrantes):                  │
│  ├─ Session B (Peer B, IP:port)        │
│  ├─ Session C (Peer C, IP:port)        │
│  └─ Session D (Peer D, IP:port)        │
│                                         │
│  CONNECTOR (salientes):                  │
│  ├─ -> Peer B (si B no conectó primero) │
│  ├─ -> Peer C                           │
│  └─ -> Peer D                           │
│                                         │
│  DOUBLE RATCHET STATES:                 │
│  ├─ ratchet_A↔B (msg_key distinta)      │
│  ├─ ratchet_A↔C                        │
│  └─ ratchet_A↔D                        │
└─────────────────────────────────────────┘

TOTAL: N peers = N-1 ratchets por peer
       5 peers = 4 ratchets c/u = 10 ratchets totales
```

### Flujo de conexión para N peers

```
1. Peer A inicia, escucha en :9000
2. Peer B inicia, escucha en :9000
3. A conecta a B, B acepta → sesión A↔B
   • Handshake TLS → salt exchange → Argon2 → Double Ratchet
4. Peer C inicia, escucha en :9000
5. C conecta a A y B
   • A acepta a C → sesión A↔C (nuevo ratchet independiente)
   • B acepta a C → sesión B↔C (nuevo ratchet independiente)
   • C tiene 2 ratchets (C↔A, C↔B)
   • A tiene 2 ratchets (A↔B, A↔C)
   • B tiene 2 ratchets (B↔A, B↔C)
6. Así sucesivamente...

Siempre se puede unir quien tenga la frase y la IP:puerto de al menos un peer activo.
```

---

## 5. Chats Grupales — Arquitectura

### Modelo: "Malla completa con E2EE pairwise"

```
NO existe un concepto de "grupo" como entidad.
Un grupo = TODOS los peers conectados con la misma frase.

PARA ENVIAR UN MENSAJE AL GRUPO:
  Peer A quiere decir "hola a todos"
  
  Por cada peer conectado en SessionManager:
    1. Serializar mensaje
    2. Cifrar con ratchet_A↔PeerX
    3. Enviar por TLS canal específico
  
  Peer A envía 3 copias cifradas (una para B, una para C, una para D)

  OBSERVADOR DE RED VE:
    • 3 streams TLS distintos
    • Cada uno con payloads cifrados de tamaño similar (padding)
    • NO puede saber que es el mismo mensaje replicado
    • NO puede saber cuántos peers hay en el grupo

PARA RECIBIR:
  Cada peer descifra SOLO lo que le llega por su ratchet con el emisor
  No puede descifrar los mensajes entre otros peers
```

### Overhead

| Peers | Ratchets/peer | Mensaje al grupo = N-1 cifrados |
|---|---|---|
| 2 | 1 | 1 cifrado |
| 3 | 2 | 2 cifrados |
| 5 | 4 | 4 cifrados |
| 10 | 9 | 9 cifrados |

**Límite práctico:** ~10-15 peers con Doble Ratchet completo. Más que eso necesitás Sender Keys (tipo Signal) o un relay.

### Sender Keys (mejora futura, no implementada ahora)

```
En lugar de cifrar N veces, cada peer genera una "sender key" que comparte
con todos los demás UNA VEZ, y luego envía un solo cifrado para todos.

PRO:
  • 1 cifrado por mensaje, no N-1
  • Escala a grupos grandes

CONTRA:
  • Si un peer pierde sincronización, todos se ven afectados
  • Más complejo de implementar (requiere consenso)
  • Necesita un canal de difusión confiable

Para MVP: mesh con pairwise. Para v2: Sender Keys.
```

---

## 6. Ciclo de Vida de una Conexión (por par de peers)

### Fase 0 — Inicialización

```
APP INICIA
│
├─ Argumentos CLI:
│   sesame --peer IP:PORT [--peer IP:PORT ...]
│          --phrase "frase"
│          [--max-peers 10]
│          [--same-ip-limit 1]
│          [--decoy]
│
├─ Registrar F12 handler (crossterm)
├─ Crear SessionManager vacío
├─ Generar Ed25519 keypair + cert autofirmado
├─ Iniciar listener TLS en :9000
└─ Conectar vía TLS a cada --peer listado
```

### Fase 1 — Handshake TLS 1.3

```
PEER A                              PEER B
│                                   │
├── TCP SYN ───────────────────────►│
├◄────────────────────── SYN-ACK ───┤
├── TLS ClientHello ──────────────►│
│   (cipher suites: ChaCha20)      │
├◄── TLS ServerHello + Cert(A) ────┤
│   (X25519 ephemeral +            │
│    sig alg: Ed25519)             │
├── TLS Client Cert(B) + Fin ────►│
├◄── TLS Finished ─────────────────┤
│                                   │
│  ← TLS 1.3 listo →               │
│  ← Forward secrecy garantizada → │
│  ← A y B se autentican con cert→ │
```

### Fase 2 — Intercambio de Salts + Derivación

```
CANAL TLS (externo, cifrado)

├── A: salt_A = getrandom(32)
├── B: salt_B = getrandom(32)
├── A ──── salt_A ────────────────► B
├── B ──── salt_B ────────────────► A
│
├── AMBOS:
│   session_key = mlock(Argon2id(
│       password: frase_compartida,
│       salt: salt_A || salt_B,
│       mem_cost: 65536 (64MB),
│       time_cost: 3,
│       parallelism: 4,
│       output: 32 bytes
│   ))
│   ← session_key está en mlock() →
│   ← Nunca va a swap ni a disco   │
```

### Fase 3 — Autenticación Mutua

```
├── A → B: SHA256(session_key || "initiator" || salt_A)
├── B verifica → B → A: SHA256(session_key || "responder" || salt_B)
├── A verifica
│
├── Si no coincide → DROP conexión (mostrar "frase incorrecta" en TUI)
├── Si coincide → continuar
│
│  ← Ambos probaron que saben la frase sin revelarla →
│  ← TLS protegió todo el intercambio →
```

### Fase 4 — Inicialización del Double Ratchet

```
├── A: keypair_A = x25519_dalek::EphemeralSecret::random()
├── B: keypair_B = x25519_dalek::EphemeralSecret::random()
│
├── A ──── pub_A ──────────────────► B
├── B ──── pub_B ──────────────────► A
│
├── AMBOS (con mlock):
│   shared_secret = DH(priv, pub_other)
│   root_chain = HKDF(session_key, shared_secret, "sesame-root")
│   send_chain = HKDF(root_chain, "sesame-send", 32)
│   recv_chain = HKDF(root_chain, "sesame-recv", 32)
│
│   A: send = send_chain, recv = recv_chain
│   B: send = recv_chain, recv = send_chain
│
│  ← Double Ratchet listo →          │
│  ← Estado en mlock() →             │
│  ← session_key ya no se necesita → │
│  ← zeroize(session_key) →          │
```

### Fase 5 — Envío de Mensaje

```
USUARIO ESCRIBE: "hola"

1. SERIALIZAR
   message = ChatMessage {
       peer_id: hash(cert_A),     // quién lo envía
       text: "hola",
       timestamp: 0,              // no exponemos tiempo
       flags: 0,                  // real(0) | dummy(1)
   }
   plaintext = serde_json::to_vec(&message)

2. DOUBLE RATCHET
   msg_key = HKDF(send_chain, "sesame-msg")
   send_chain = SHA256(send_chain)      // ← forward secrecy
   nonce = getrandom(12)
   ciphertext = ChaCha20Poly1305.encrypt(msg_key, nonce, plaintext)

   SI DH_RATCHET_COUNTER % 3 == 0:
       new_eph = X25519::random()
       shared = DH(new_eph.priv, their_pub)
       root_chain = HKDF(root_chain, shared, "sesame-dh-ratchet")
       send_chain = HKDF(root_chain, "sesame-send", 32)
       recv_chain = HKDF(root_chain, "sesame-recv", 32)
       incluir new_eph.pub en el frame

3. OFUSCACIÓN
   frame = [nonce(12) || ciphertext(N) || tag(16)]
   padded = pad_to_1400(frame)          // tamaño fijo
   
4. ENVÍO POR TLS (al peer específico)
   tls_stream.write(length_prefix(4) || padded)
   // TLS lo cifra nuevamente como capa externa

LO QUE VE UN OBSERVADOR:
  • Segmentos TCP con TLS cifrado
  • Tamaño constante (~1400 bytes + overhead)
  • Flujo continuo (dummy traffic tapa silencios)
  • No distingue entre mensajes para distintos peers
  • No distingue mensaje real de dummy
```

### Fase 6 — Recepción de Mensaje

```
TLS recibe frame → descifra capa externa

1. Despadding: extraer frame real
2. Descartar dummy si flag == 1
3. Double Ratchet decrypt:
   a) Si incluye new_pub:
      DH(our_priv, new_pub) → root_chain = HKDF(root, shared)
      recv_chain = HKDF(root, "sesame-recv")
   b) msg_key = HKDF(recv_chain, "sesame-msg")
      recv_chain = SHA256(recv_chain)   // forward secrecy
      plaintext = ChaCha20Poly1305.decrypt(msg_key, nonce, ciphertext)

4. Deserializar → ChatMessage
5. Mostrar en TUI con identificación del peer_id

6. Si es para grupo (futuro): mostrar en burbuja grupal
   con identificador del remitente
```

---

## 7. Ciclo de Vida de Grupo (N peers)

### Unirse a un grupo existente

```
PEER D (nuevo)                     PEER A (ya conectado)
  │                                    │
  ├── Conoce IP:port de A             │
  ├── TCP → TLS handshake             │
  ├── Salt exchange + derivación      │
  ├── Auth mutua (misma frase)        │
  ├── Ratchet init (D↔A)              │
  │                                    │
  │  ← Sesión D↔A lista →             │
  │                                    │
  ├── Ahora D necesita conectarse     │
  │   también a B y C.                │
  │   ¿Cómo consigue IPs de B y C?    │
  │                                    │
  ├── OPCIÓN A: A le pasa la lista     │
  │   D → A: "dame peers"            │
  │   A → D: [B:9001, C:9002]        │
  │   (cifrado, por el ratchet D↔A)   │
  │                                    │
  ├── OPCIÓN B: broadcast             │
  │   D envía broadcast por A:         │
  │   "soy D, IP:puerto de D,          │
  │    conectense si tienen la frase"  │
  │   Otros peers ven el broadcast     │
  │   y conectan a D directamente      │
  │                                    │
  ├── OPCIÓN C: lista fija en args     │
  │   sesame --peer A --peer B --peer C│
  │   D ya tiene todas las IPs desde   │
  │   el arranque                      │
```

**Para MVP:** Opción C (lista fija). Para v2: Opción A (propagación peer-to-peer).

### Salida de un peer

```
PEER C se desconecta

1. Drop de conexión TCP
2. SessionManager detecta timeout
3. Notifica a otros peers:
   "C se fue" (se muestra en TUI)
4. Libera estado del ratchet C
5. zeroize() de todas las claves de C
6. Si C vuelve a conectar:
   - Nuevo cert (efímero, distinto cada ejecución)
   - Nueva sesión completamente independiente
   - No hay "reanudación" — todo es fresco

SI SE VA EL ÚLTIMO PEER:
  • Si no queda nadie con la frase activa,
    la frase deja de tener utilidad
  • No hay persistencia, no hay "sesión guardada"
  • El grupo deja de existir hasta que alguien
    vuelva a iniciar con la frase
```

---

## 8. Anti-Coerción

### Frase Señuelo

```
DOS FRASES:
  SESAME_REAL = "mariposa-azul-42"     // verdadera
  SESAME_DECOY = "esto-no-es-nada-99"  // señuelo

  El binario es UNO SOLO.
  El modo se elige por flag:
    sesame --phrase "mariposa-azul-42"  → modo real
    sesame --phrase "esto-no-es-nada-99" --decoy → modo señuelo

ESCENARIO DE COERCIÓN:
  1. Atacante te fuerza a revelar la frase
  2. Entregás "esto-no-es-nada-99"
  3. Atacante corre el app con --decoy
  4. Si los demás peers están en modo señuelo:
     - Conexión establecida
     - Grupo falso: conversación vacía o con mensajes falsos
     - No se puede detectar que es señuelo
  5. Si los demás están en modo real:
     - Handshake falla (frases distintas)
     - App muestra: "frase incorrecta, no se pudo conectar"
     - No revela que existe una frase real ni quién la tiene

HANDOFF (cambio de modo con F12):
  • Presiona F12 → modo pánico:
    1. zeroize() de TODAS las claves
    2. Cerrar conexiones TCP sin enviar "bye"
    3. Limpiar pantalla TUI
    4. Cambiar al otro modo (real ↔ señuelo)
    5. Reconectar automáticamente
  • Si el atacante vuelve y ve el app funcionando:
    Presiona F12 otra vez → vuelve a modo señuelo
```

### Tecla de Pánico (F12) — Detalle

```
FLUJO COMPLETO DE F12:

Phase 1 — ZEROIZE (< 1ms)
  ──────────────────────
  • zeroize(session_key)
  • zeroize(root_chain)
  • zeroize(send_chain)
  • zeroize(recv_chain)
  • zeroize(msg_key temporal)
  • zeroize(DH_private_keys)
  • drop(ratchet_states)
  • drop(mlock_locks)     // ← libera las páginas
  // El compilador NO puede optimizar estas escrituras

Phase 2 — NETWORK
  ────────────────
  • Abortar todas las conexiones TCP
  • Cancelar dummy traffic tasks
  • No enviar "disconnect" — solo DROP silencioso
  // Así un observador de red no ve un "mensaje de despedida"

Phase 3 — TUI
  ────────────
  • ratatui::clear() + render pantalla de "desconectado"
  • Mostrar barra de estado: "▼ MODO SEÑUELO" o "▼ CONECTANDO..."

Phase 4 — RECONEXIÓN
  ────────────────────
  • Cambiar modo interno (real ↔ decoy)
  • Tomar la frase correspondiente al nuevo modo
  • Reconectar a los peers conocidos
  • Nueva identidad (nuevo cert efímero)
  • Todo nuevo: salts, session_key, ratchets
```

---

## 9. Ofuscación de Metadatos

### Padding

```
CONFIG: PADDING_BLOCK = 1400 bytes

AL ENVIAR:
  payload = [nonce(12) || ciphertext(N) || tag(16)]
  total_padded = ceil(payload_len / PADDING_BLOCK) * PADDING_BLOCK
  padded_len = max(PADDING_BLOCK, total_padded)
  frame = [payload_len(2B BE) || payload || zeros(padded_len - 2 - payload_len)]

AL RECIBIR:
  payload_len = read_u16(frame)
  payload = frame[2..2+payload_len]
  // descartar ceros
```

### Tráfico Dummy

```
CONFIG:
  INTERVALO: random(3s, 7s)
  PAYLOAD: 64 bytes aleatorios

Tarea en background:
  loop:
    sleep(random(3s, 7s))
    if last_real_msg > DUMMY_INTERVAL_MIN:
      nonce = random(12)
      ciphertext = ChaCha20.encrypt(msg_key, nonce, random_bytes(64))
      flags = 1  // dummy
      frame = Frame { nonce, ciphertext, flags }
      stream.send(frame)

Receptor:
  if frame.flags == 1: descartar sin mostrar
```

### Plausible Deniability

```
REGLAS ESTRICTAS:
  1. NO hay firmas digitales en ningún mensaje
     - Ni Ed25519, ni RSA, ni HMAC con clave estática
     - Todo el cifrado es SIMÉTRICO
  
  2. Ambos peers tienen las MISMAS claves:
     - Ambos tienen send_chain y recv_chain
     - Cualquier mensaje pudo ser creado por cualquiera de los dos
     - No hay prueba de origen

  3. Al cerrar: zeroize() de todo. No existe transcript verificable.
     - Lo único que existe es tráfico TLS capturado
     - Pero descifrar un mensaje no prueba quién lo originó
     - Ambos pudieron haber creado cualquier mensaje

  IMPLICACIÓN LEGAL:
  Si alguien presenta un transcript de la conversación como "prueba",
  no puede demostrar que NO fue fabricado por él mismo
  (o por cualquiera que supiera la frase).
```

---

## 10. `mlock()` — Detalle de implementación

### Qué páginas se bloquean

```
ESTRUCTURAS BLOQUEADAS CON mlock():

  1. session_key (32B) — resultado de Argon2
  2. root_chain (32B) — semilla del Double Ratchet
  3. send_chain (32B) — cadena de envío
  4. recv_chain (32B) — cadena de recepción
  5. all_msg_keys (32B * max_skip) — claves saltadas para reordenamiento
  6. DH_private_keys (32B * N.peers) — claves privadas efímeras
  7. phrase_input (variable) — la frase en memoria durante la derivación

  Total estimado: ~512 bytes por sesión + ~32B por sesión extra
  (mlock trabaja a nivel de páginas de 4KB, así que el overhead
   real es ~4KB por sesión)

FLUJO DE PROTECCIÓN:

  let mut session_key = [0u8; 32];
  let locked = Mlock::new(&mut session_key)?;
  // ↑ session_key está en página bloqueada en RAM
  
  // ... derivación y uso ...
  
  drop(locked);
  // ↑ se desbloquea automáticamente cuando el Mlock se dropea
  
  session_key.zeroize();
  // ↑ sobrescribe con ceros antes de que se libere la página
```

### Manejo de errores

```
Si mlock() falla (ej: límite de páginas bloqueadas por proceso):
  • Mostrar warning en TUI: "⚠️ mlock falló — claves podrían ir a swap"
  • El programa CONTINÚA funcionando (no es fatal)
  • Registrar en logs de debug si existen

Para producción:
  • Verificar capacidad con getrlimit(RLIMIT_MEMLOCK) en POSIX
  • En Windows: verificar privilegios SeLockMemoryPrivilege
  • Si no hay suficientes páginas: bloquear solo lo más crítico
    (session_key + root_chain) y dejar el resto sin mlock
```

---

## 11. Propiedades de Seguridad — Tabla

| Amenaza | Mitigación |
|---|---|
| **Eavesdropper de red** | TLS 1.3 ChaCha20-Poly1305 + E2EE Double Ratchet |
| **MITM activo** | Necesita saber frase + romper TLS o certs |
| **Metadatos (quién, cuándo, cuánto)** | Padding fijo 1400B + tráfico dummy aleatorio |
| **Inferir que es chat** | Tráfico cifrado indistinguible de ruido |
| **Robo de claves (hoy)** | Forward secrecy: symmetric ratchet avanzó |
| **Robo de claves (ayer)** | Self-healing: DH ratchet renovó claves |
| **Frase comprometida (después)** | Salt rotativo cada sesión → claves distintas |
| **Frase en swap/disco** | `mlock()` → no va a disco |
| **Claves en swap/disco** | `mlock()` + `zeroize()` |
| **Coerción: revelar frase** | Frase señuelo + modo decoy |
| **Coerción: vigilancia en vivo** | F12 → zeroize + cambio de modo instantáneo |
| **Transcript como prueba legal** | Plausible deniability: simétrico, sin firmas |
| **Brute-force de frase offline** | Argon2id 64MB + 3 iter |
| **Nonce reuse** | Nonce random 12B → P(colisión) ~2⁻⁹⁶ |
| **Replay attack** | TLS anti-replay + sesión efímera sin estado |
| **Side-channel timing** | Tráfico dummy constante elimina correlación |
| **Quantum computer futuro** | X25519 vulnerable. Mitigación futura: agregar ML-KEM |

---

## 12. Estructura del Código

```
src/
├── main.rs              # CLI, init SessionManager, TUI, panic handler
│
├── tls.rs               # generar_certs(), config_server(), config_client()
│                        # Ed25519 via rcgen, autofirmado en RAM
│
├── crypto.rs            # derive_key(phrase, salt) → session_key (mlock)
│                        # helpers: HKDF, SHA256, ChaCha20, getrandom
│                        # zeroize_key_material()
│
├── ratchet.rs           # DoubleRatchet struct
│                        # init(session_key, their_pub) → (send_chain, recv_chain)
│                        # encrypt(plaintext) → Frame
│                        # decrypt(Frame) → plaintext
│                        # DH ratchet + symmetric ratchet automático
│                        # skipped_keys para reordenamiento
│
├── auth.rs              # handshake(session_key, stream)
│                        # salt exchange + challenge-response
│
├── session.rs           # SessionManager
│                        # HashMap<PeerId, Session>
│                        # add_peer(), remove_peer(), broadcast()
│                        # max_peers, same_ip_limit
│                        # group_peer_list() → lista de IPs activas
│
├── peer.rs              # P2P loop
│                        # run_listener() + connect_peer()
│                        # spawn receive + send + dummy tasks
│
├── protocol.rs          # Frame struct, length-prefixed I/O
│                        # padding/depadding, dummy detection
│
├── obfuscate.rs         # ObfuscationConfig
│                        # apply_padding(), remove_padding()
│                        # should_send_dummy(), random_interval()
│
├── panic.rs             # PanicMode enum (Real | Decoy)
│                        # zeroize_and_panic() — F12 handler
│                        # switch_mode() + reconnect()
│
├── tui.rs               # Ratatui interface
│                        # AppState, render(), handle_input()
│                        # chat bubbles, peer list panel
│                        # panic mode indicator
│
└── types.rs             # ChatMessage, PeerId, PeerAddr, SessionState
```

---

## 13. Dependencias (Cargo.toml)

```toml
[package]
name = "sesame"
version = "0.1.0"
edition = "2024"

[dependencies]
# Async
tokio = { version = "1", features = ["full"] }

# TLS
rustls = { version = "0.23", features = ["ring"] }
tokio-rustls = "0.26"
rustls-pemfile = "2"
rcgen = "0.13"

# E2EE + Double Ratchet
x25519-dalek = { version = "2", features = ["static_secrets"] }
chacha20poly1305 = "0.10"
sha2 = "0.10"
hkdf = "0.12"

# Key derivation
argon2 = "0.5"

# CSPRNG
rand = "0.8"

# RAM pinning
mlock = "0.3"

# Secure zeroize
zeroize = { version = "1", features = ["zeroize_derive"] }

# Serialization
serde = { version = "1", features = ["derive"] }
serde_json = "1"

# TUI
ratatui = "0.28"
crossterm = "0.28"
```

---

## 14. Tradeoffs y Decisiones

| Decisión | Alternativa | Por qué |
|---|---|---|
| **Mesh P2P** (cada par su ratchet) | Signal con relay | Sin server central, privacidad total |
| **Lista fija de peers en CLI** | DHT / propagación | Simple, sin infraestructura extra |
| **Misma frase para todo el grupo** | Claves por par | Simple, el salt garantiza unicidad |
| **DH ratchet cada 3 msgs** | Cada mensaje | Balance seguridad/CPU para chat |
| **Padding 1400B** | MTU 1500 | Deja espacio para overhead TLS+TCP |
| **Dummy cada 3-7s aleatorio** | Intervalo fijo | Evita patrones detectables |
| **Frase señuelo en mismo binario** | Binarios separados | No levanta sospechas |
| **F12 como tecla de pánico** | Señal especial | No compite con input de chat |
| **ChaCha20-Poly1305 (E2EE)** | AES-256-GCM | Rápido sin AES-NI |
| **mlock() no fatal si falla** | Obligatorio | App funciona igual, solo pierde protección |
| **JSON para mensajes** | Bincode | Debuggeable, overhead despreciable |
| **max_peers configurable** | Sin límite | Evita DoS por conexiones múltiples |
| **sin relay** | Relay server | Lo dejamos para futura iteración |

---

## 15. Roadmap de implementación

```
FASE 1 — NÚCLEO
  [ ] project init + Cargo.toml + types
  [ ] tls.rs: certs efímeros + config server/client
  [ ] crypto.rs: derive_key() + helpers
  [ ] ratchet.rs: Double Ratchet encrypt/decrypt
  [ ] protocol.rs: frame I/O + length-prefix
  [ ] auth.rs: handshake (salt exchange + challenge)
  [ ] session.rs: SessionManager (1 sesión)
  [ ] peer.rs: listener + connector (P2P 1:1)

FASE 2 — TUI
  [ ] tui.rs: ratatui con burbujas + input
  [ ] main.rs: integrar TUI + peer loop

FASE 3 — OFUSCACIÓN + ANTI-COERCIÓN
  [ ] obfuscate.rs: padding + dummy traffic
  [ ] panic.rs: F12 handler + zeroise + modo señuelo
  [ ] mlock() integration en crypto.rs

FASE 4 — GRUPO + MULTI-SESIÓN
  [x] session.rs: N sesiones simultáneas
  [x] peer.rs: conectar a múltiples peers
  [x] broadcast de mensaje al grupo
  [x] propagación de IPs entre peers

FASE 5 — ENDURECIMIENTO
  [ ] pruebas de seguridad (escenarios de ataque)
  [ ] manejo de errores + reintentos
  [ ] edge cases: peer duplicado, reconexión, timeout
```

---

## 16. Fase 4 — Especificación de Implementación

### Principios

- **Malla completa:** cada par de peers tiene su propio Double Ratchet independiente
- **Sin relay ni servidor central:** mesh P2P puro
- **Peer discovery dinámico (Opción A):** al conectar a un peer, pedís la lista del grupo
- **Reconexión condicional:** solo si el grupo sigue vivo (≥2 peers restantes al remover)
- **Identidad efímera:** si quedás solo (peer_count == 0), regenerás certs y arrancás de cero
- **Sin rate limits:** todo viaja cifrado por el ratchet, no hay vectores de ataque reales

### Constantes de mensaje (`types.rs`)

```
FLAG_REAL: u8 = 0             — mensaje de chat normal
FLAG_DUMMY: u8 = 1            — tráfico dummy (descartar)
FLAG_PEER_LIST_REQ: u8 = 2    — solicitar lista de peers
FLAG_PEER_LIST_RES: u8 = 3    — respuesta con lista de peers
FLAG_SYSTEM_JOIN: u8 = 4      — broadcast: alguien se unió
FLAG_SYSTEM_LEAVE: u8 = 5     — broadcast: alguien se fue
FLAG_SYSTEM_ALONE: u8 = 6     — el grupo quedó vacío, regenerar identidad
```

### Peer discovery — Flujo

```
NUEVO PEER X conecta a PEER A (primer --peer conocido):
  1. X ↔ A: TLS + auth + ratchet → sesión
  2. session_mgr registra a X, broadcast JOIN a otros (flags=4)
  3. X (initiator) envía PEER_LIST_REQ (flags=2) cifrado por el ratchet
  4. A recibe flags=2:
     - session_mgr.list_peer_addresses(exclude: &peer_id)
     - responde con PEER_LIST_RES (flags=3), body: JSON(Vec<PeerAddr>)
  5. X recibe flags=3:
     - Deserializa Vec<PeerAddr>
     - Para cada addr: si no es self y no está conectada →
       envía a discovery_channel (mpsc::UnboundedSender<PeerAddr>)
  6. Main recibe de discovery_rx → spawn(connect_peer(addr))
  7. X conecta a B, C, D en paralelo con sesiones independientes
```

### Reconexión condicional

```
remove_session(&peer_id) decide:
  peer_count después de remover ≥ 2:
    → guardar addr en known_peers (HashMap<PeerId, PeerAddr>)
    → main reconnection loop (cada 30s) intenta reconectar

  peer_count == 0:
    → clear known_peers
    → mandar FLAG_SYSTEM_ALONE por message_tx
    → main recibe: regenerar certs → nuevo acceptor + connector → clear TUI
```

### Timeout de inactividad

- Default: 300 segundos (5 min), configurable via `--inactivity-timeout`
- `spawn_timeout_checker()`: task background que cada 30s revisa `last_message`
- Si `Instant::now() - last_message > inactivity_timeout` → `remove_session()`
- El peer loop detecta sender cerrado (msg_rx.recv() → None) → break → cleanup

### TUI — Panel de peers

```
Layout horizontal:
  ┌──────────────────────┬──────────────────┐
  │      CHAT (75%)      │  PEERS (25%)     │
  │                      │  a1b2c3d4        │
  │  mensajes...         │  10.0.0.5:9000   │
  │                      │                  │
  │                      │  f6e7d8c9        │
  │                      │  10.0.0.7:9000   │
  │                      │                  │
  │                      │  2/10 peers      │
  ├──────────────────────┴──────────────────┤
  │  Message: [______________________]      │
  └─────────────────────────────────────────┘
```

System messages (JOIN/LEAVE) se muestran en gris itálico con prefijo `◆`.

### Cambios por archivo

| Archivo | Cambios |
|---------|---------|
| `types.rs` | FLAG_* constants, `PartialEq + Serialize + Deserialize` en PeerAddr |
| `session.rs` | `inactivity_timeout`, `known_peers`, `discovery_tx`, `spawn_timeout_checker()`, `list_peer_addresses()`, `is_connected_to_addr()`, `update_last_message()`, `broadcast_except()`, remove_session con lógica de grupo |
| `peer.rs` | `connect_peer()`, `connect_peers()`, manejo de flags 2-5 en loop, broadcast JOIN/LEAVE, discovery channel |
| `main.rs` | `--inactivity-timeout`, discovery channel, reconnection loop, identity regeneration en FLAG_SYSTEM_ALONE |
| `tui.rs` | Layout horizontal, `render_peer_list()`, `render_mode_indicator()`, system messages gris itálico, `Vec<(PeerId, String, u8)>` |

---

## 17. Fase 5 — Endurecimiento: Especificación

### Principios

- Solo hardening real — sin features nuevos
- No se toca criptografía (TLS + E2EE se mantienen intactos)
- No se agrega persistencia ni identidad global
- Prioridad: evitar DoS, pánicos en cascada, tareas fantasma

### Task 1 — Límite de tamaño en `read_frame`

**Archivo:** `src/protocol.rs`

**Problema:** `read_frame` lee `u32` (4GB) y hace `vec![0u8; frame_len]`. Atacante envía `0xFFFFFFFF` → OOM.

**Solución:**
```rust
pub const MAX_FRAME_SIZE: usize = 1024 * 1024 * 10; // 10MB

pub async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R) -> std::io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf).await?;
    let frame_len = u32::from_be_bytes(len_buf) as usize;
    if frame_len > MAX_FRAME_SIZE {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "frame too large"));
    }
    let mut buf = vec![0u8; frame_len];
    reader.read_exact(&mut buf).await?;
    Ok(buf)
}
```

---

### Task 2 — Mutex poisoning: `unwrap()` → `expect()`

**Archivos:** `src/session.rs`, `src/main.rs`, `src/tui.rs`

**Problema:** ~35 `lock().unwrap()` en todo el codebase. Un solo pánico envenena el Mutex y todos los `unwrap()` posteriores paniquean en cascada.

**Solución:** Reemplazar cada `lock().unwrap()` con `lock().expect("contexto descriptivo")` en:
- `session.rs`: ~20 ocurrencias en métodos de SessionManager
- `main.rs`: `shared_acceptor`, `shared_connector` (~5 ocurrencias)
- `tui.rs`: `panic_handler` (2 ocurrencias)

---

### Task 3 — F12: watch channel para matar peer tasks

**Archivo:** `src/session.rs`

**Problema:** F12 llama `clear_sessions()` que limpia el HashMap, pero las spawned tasks de cada conexión **siguen corriendo** procesando datos de red para siempre.

**Solución:**

```rust
pub struct SessionManager {
    // ... campos existentes ...
    cancel_tx: tokio::sync::watch::Sender<bool>,
}
```

- Cada peer task recibe un `cancel_rx: watch::Receiver<bool>` al registrarse
- En el `tokio::select!` del peer loop, se agrega:
  ```rust
  _ = cancel_rx.changed() => {
      if *cancel_rx.borrow() { break; }
  }
  ```
- `clear_sessions()` setea la watch a `true`:
  ```rust
  pub fn clear_sessions(&self) {
      let _ = self.cancel_tx.send(true);
      self.sessions.lock().unwrap().clear();
  }
  ```
- Al registrar un nuevo peer post-F12, la watch está en `true` → la tarea nueva se cancela inmediatamente

---

### Task 4 — Protección contra self-connection

**Archivo:** `src/session.rs`, `src/peer.rs`

**Problema:** `my_listen_addr` es `0.0.0.0:port`. No matchea `127.0.0.1:port` ni la IP pública. Un peer puede conectarse a sí mismo.

**Solución:** `register_session` recibe `my_peer_id: &PeerId` y lo compara con el peer_id que intenta conectarse:

```rust
pub fn register_session(
    &self,
    handle: SessionHandle,
    my_peer_id: &PeerId,
) -> Result<(), &'static str> {
    if handle.peer_id == *my_peer_id {
        return Err("cannot connect to self");
    }
    if sessions.contains_key(&handle.peer_id) {
        return Err("duplicate session");
    }
    // ... límites existentes ...
}
```

---

### Task 5 — Sesión duplicada + TCP simultáneo

**Archivo:** `src/session.rs`

**Problema:** `HashMap::insert` sobrescribe silenciosamente. Si ambos peers conectan simultáneamente, la segunda conexión mata la primera.

**Solución:** Check explícito en `register_session` (junto con self-connection en Task 4):

```rust
if sessions.contains_key(&handle.peer_id) {
    return Err("duplicate session");
}
```

Regla: el que ya está conectado se queda. El que intenta conectar segundo recibe error y su loop se dropea.

---

### Task 6 — Límite en deserialización JSON

**Archivo:** `src/peer.rs`

**Problema:** `serde_json::from_slice(&plaintext)` y `serde_json::from_str(&msg.text)` sin límite de tamaño. Atacante puede enviar JSON gigante.

**Solución:**

```rust
const MAX_JSON_SIZE: usize = 1024 * 64; // 64KB

// Antes de deserializar
if plaintext.len() > MAX_JSON_SIZE {
    eprintln!("[peer] oversized json from {peer_id}, dropping");
    continue;
}
```

Aplica a los dos puntos de deserialización:
1. `serde_json::from_slice(&plaintext)` para ChatMessage (line ~308)
2. `serde_json::from_str(&msg.text)` para Vec<PeerAddr> (line ~342)

---

### Task 7 — Canales bounded con backpressure

**Archivo:** `src/main.rs`, `src/peer.rs`, `src/session.rs`

**Problema:** 4 canales `unbounded_channel` sin backpressure. Si el receptor se atora, la memoria crece sin límite.

**Solución:**

| Canal | Tipo actual | Nuevo tipo | Estrategia |
|-------|------------|------------|------------|
| Mensajes TUI (`msg_tx` → `msg_rx`) | `unbounded` | `channel(1024)` | Sliding window: `try_send()` → si lleno, dropear el más viejo |
| Descubrimiento (`discovery_tx` → `discovery_rx`) | `unbounded` | `channel(256)` | `try_send()` → si lleno, ignorar |
| Escritura por peer (`msg_tx` → `msg_rx` por peer) | `unbounded` | `channel(256)` | Backpressure natural: `send().await` bloquea hasta que la red consuma |
| Eventos TUI (`event_tx` → `event_rx`) | `unbounded` | `unbounded` | Sin cambios (no queremos perder input del usuario) |

Para sliding window en TUI:
```rust
match msg_tx.try_send((peer_id, msg)) {
    Ok(_) => {}
    Err(mpsc::error::TrySendError::Full(_)) => {
        // Canal lleno, el TUI está saturado — dropear mensaje más viejo
        // No hacemos nada, el mensaje se pierde (el nuevo no entra)
    }
    Err(mpsc::error::TrySendError::Closed(_)) => {}
}
```

---

### Task 8 — Task supervisión: JoinHandle + catch_unwind

**Archivo:** `src/main.rs`

**Problema:** Todos los `tokio::spawn` son fire-and-forget. Si una tarea paniquea, la funcionalidad se pierde para siempre.

**Solución:**

```rust
pub struct TaskSupervisor {
    pub listener_handle: Option<JoinHandle<()>>,
    pub reconnection_handle: Option<JoinHandle<()>>,
    pub timeout_handle: Option<JoinHandle<()>>,
}
```

- Almacenar `JoinHandle` para las tareas críticas (listener, reconnection loop, timeout checker)
- Envolver cada una en un helper que loguee el panic:
  ```rust
  fn spawn_supervised<F>(f: F, name: &'static str) -> JoinHandle<()>
  where F: Future<Output = ()> + Send + 'static
  {
      tokio::spawn(async move {
          if let Err(panic) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).await {
              eprintln!("[sesame] task '{name}' panicked: {panic:?}");
          }
      })
  }
  ```

**Qué tareas se supervisan:**
- Listener loop (aceptar conexiones entrantes)
- Reconnection loop (reconexión cada 30s)
- Timeout checker (inactividad)
- Peer connections individuales (se almacenan en SessionManager para cancelación en F12)

---

### Resumen de cambios por archivo

| Archivo | Cambios |
|---------|---------|
| `protocol.rs` | `MAX_FRAME_SIZE`, validación en `read_frame` |
| `session.rs` | `expect()` en locks, `cancel_tx` watch channel, `register_session` con `my_peer_id` + duplicate check, `clear_sessions()` envía cancel |
| `peer.rs` | Watch channel en `select!`, límite JSON en deserialización, pasar `my_peer_id` a `register_session` |
| `main.rs` | `expect()` en locks, canales bounded, `TaskSupervisor`, `catch_unwind` en tareas críticas, pasar `my_peer_id` a `connect_peer` |

### Roadmap actualizado

```
FASE 1 — NÚCLEO                  [x]
FASE 2 — TUI                     [x]
FASE 3 — OFUSCACIÓN + ANTI-COERCIÓN [x]
FASE 4 — GRUPO + MULTI-SESIÓN    [x]
FASE 5 — ENDURECIMIENTO
  [x] Task 1: read_frame max size
  [x] Task 2: Mutex poisoning handler
  [x] Task 3: F12 watch channel
  [x] Task 4: Self-connection
  [x] Task 5: Sesión duplicada
  [x] Task 6: Límite JSON
  [x] Task 7: Canales bounded
  [x] Task 8: Task supervisión
```
