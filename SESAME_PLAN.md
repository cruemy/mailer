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
    phrase: LockedBytes,      // compartida, mlock + zeroize en Drop
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

CIERRE DE PÁNICO CON F12:
  • Presiona F12 → cierre inmediato y seguro:
    1. zeroize() de TODAS las claves
    2. Cerrar conexiones TCP sin enviar "bye"
    3. Limpiar pantalla TUI
    4. Restaurar terminal
    5. Terminar el proceso
  • F12 NO cambia de modo y NO reconecta automáticamente.
    Para volver a entrar, el usuario debe iniciar el app de nuevo
    con la frase real o señuelo correspondiente.
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

Phase 3 — TUI + TERMINAL
  ────────────
  • ratatui::clear()
  • Limpiar input y mensajes visibles
  • Restaurar terminal: disable_raw_mode() + LeaveAlternateScreen

Phase 4 — EXIT
  ────────────
  • Terminar el proceso inmediatamente
  • NO reconectar
  • NO regenerar identidad en caliente
  • NO cambiar real ↔ decoy dentro del mismo proceso
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
| **Coerción: vigilancia en vivo** | F12 → zeroize + cierre inmediato del app |
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
  [ ] panic.rs: F12 handler + zeroise + cierre seguro del app
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

### Task 3 — F12: cierre seguro del proceso

**Archivos:** `src/main.rs`, `src/tui.rs`, `src/session.rs`, `src/peer.rs`

**Problema:** F12 debe ser una salida de pánico. No debe dejar tareas vivas, no debe reconectar y no debe cambiar a modo señuelo dentro del mismo proceso.

**Solución:**

```rust
pub struct SessionManager {
    // ... campos existentes ...
    cancel_tx: tokio::sync::watch::Sender<bool>,
}
```

- Cada peer task recibe un `cancel_rx: watch::Receiver<bool>` al registrarse
- En el `tokio::select!` del peer loop, se agrega una salida inmediata:
  ```rust
  _ = cancel_rx.changed() => {
      if *cancel_rx.borrow() { break; }
  }
  ```
- F12 ejecuta el flujo de cierre seguro:
  ```rust
  pub fn panic_shutdown(&self) {
      let _ = self.cancel_tx.send(true);
      self.sessions.lock().unwrap().clear();
      self.known_peers.lock().unwrap().clear();
  }
  ```
- Después de `panic_shutdown()`:
  - zeroize/drop de ratchets y claves al caer las tareas
  - cerrar canales y sockets por drop
  - limpiar/restaurar terminal
  - `std::process::exit(0)` o break final del `main`
- No hay reconexión post-F12. Si el usuario quiere entrar en real o señuelo, reinicia el binario con los flags correspondientes.

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
  [x] Task 3: F12 cierre seguro del proceso
  [x] Task 4: Self-connection
  [x] Task 5: Sesión duplicada
  [x] Task 6: Límite JSON
  [x] Task 7: Canales bounded
  [x] Task 8: Task supervisión

FASE 6 — ASEGURAMIENTO MÁXIMO    [ ]
  [x] Task 1: threat model formal + límites explícitos
  [x] Task 2: LockedSecret para frase + DH private keys
  [x] Task 3: PAKE real para frase humana
  [x] Task 4: transcript binding con TLS exporter + AAD completo
  [x] Task 5: anti-replay/reorder/downgrade exhaustivo
  [x] Task 6: OS hardening + crash/swap discipline
  [x] Task 7: DoS y límites antes de cómputo caro
  [x] Task 8: fuzzing + property tests + escenarios adversariales
  [ ] Task 9: auditoría cripto externa antes de producción
```

---

## 18. Fase 6 — Aseguramiento Máximo: Especificación

### Principios

- **Seguridad máxima no significa seguridad absoluta.** Significa reducir superficie, probar propiedades críticas y documentar límites restantes.
- El objetivo no es agregar features: es convertir el core en un sistema con garantías verificables.
- Ningún secreto sensible debe tener dueño largo en memoria desbloqueada.
- Ningún byte recibido de red debe influir en memoria/CPU sin límite explícito.
- Ningún mensaje debe ser válido fuera de su sesión, peer, dirección, versión y transcript.
- La frase humana es el punto más débil: Argon2 mitiga fuerza bruta, pero no reemplaza un PAKE.

### Amenazas cubiertas por Fase 6

| Amenaza | Mitigación objetivo |
|---|---|
| MITM activo con cert efímero falso | TLS signature verification + cert PeerId + TLS exporter + PAKE/transcript binding |
| Unknown-key-share / wrong peer binding | Transcript hash con peer IDs, salts, DH pubs, roles y versión |
| Replay / reorder / stale DH | Contadores autenticados, ventanas de recepción, skipped keys limitadas |
| Brute force offline de frase | Migrar de Argon2-only a PAKE; Argon2 queda como pre-KDF o factor de endurecimiento |
| Secretos en swap/core dump | `LockedSecret` RAII para frase, session/root/chains, DH private keys y msg keys temporales |
| DoS por handshake caro | Rate limits pre-Argon2, límites por IP, proof-of-work opcional o token bucket |
| Pánicos/tareas fantasma | Supervisión real + cancelación obligatoria + tests de shutdown |
| Bugs de framing | Codec único + fuzzing + property tests + reject-by-default |
| Compromiso post-mortem | F12 shutdown, zeroize, crash dumps deshabilitados, sin persistencia |

---

### Task 1 — Threat model formal + límites explícitos

**Archivo:** `SECURITY.md`, `SESAME_PLAN.md`

**Estado:** Implementado en `SECURITY.md`. Mantener este archivo como fuente de verdad para garantías, límites, operación segura y criterios de producción.

**Problema:** El plan promete muchas propiedades, pero no separa claramente qué está garantizado, qué depende del entorno y qué queda fuera de alcance.

**Solución:** crear un threat model versionado:

```md
## In scope
- Atacante de red pasivo/activo
- Peers maliciosos que conocen IP:puerto pero no frase
- DoS razonable por red
- Robo posterior de memoria/swap/core dump

## Partially in scope
- Peer comprometido después de participar
- Frase humana débil
- Host con malware local

## Out of scope
- Kernel comprometido durante ejecución
- Captura física de RAM en vivo con privilegios
- Teclado/terminal comprometido
- Usuario obligado a revelar frase real
```

**Criterio de éxito:** cada propiedad de seguridad en la tabla del plan referencia una amenaza concreta y una mitigación concreta.

---

### Task 2 — `LockedSecret` para frase + DH private keys

**Archivos:** `src/crypto.rs`, `src/ratchet.rs`, `src/auth.rs`, `src/main.rs`

**Estado:** Implementado con `LockedBytes` para frase, `LockedKey` para claves de 32 bytes y `LockedDhSecret` para DH private keys. `DoubleRatchet` ya no guarda `ReusableSecret` como estado persistente.

**Problema resuelto:** `LockedKey` protegía claves de 32 bytes, pero la frase vivía como `String` y los DH private keys vivían dentro de `x25519_dalek::ReusableSecret`, fuera de nuestro RAII de `mlock()`.

**Solución estructural:**

1. Reemplazar `String phrase` por `LockedBytes`/`Zeroizing<Vec<u8>>`:
   - la CLI copia la frase a memoria bloqueada lo antes posible
   - el `String` original se zeroiza o se evita cuando sea viable
   - `SessionManager::phrase()` no debe clonar `String`; debe prestar bytes o derivar dentro de una closure

2. Crear `LockedDhSecret`:
   ```rust
   pub struct LockedDhSecret {
       bytes: LockedKey, // 32 bytes clamped/aleatorios
   }

   impl LockedDhSecret {
       pub fn generate() -> Self;
       pub fn public_key(&self) -> PublicKey;
       pub fn diffie_hellman(&self, peer: &PublicKey) -> [u8; 32];
   }
   ```

3. Usar `x25519_dalek::StaticSecret::from([u8;32])` solo en scopes temporales:
   - construir `StaticSecret` desde `LockedKey`
   - calcular public key o DH
   - zeroize/drop inmediato
   - no guardar `ReusableSecret` como estado largo

4. `DoubleRatchet` debe guardar `LockedDhSecret`, no `ReusableSecret`.

**Criterio de éxito:** no existe `String` largo para frase ni `ReusableSecret` largo para DH; `rg "String.*phrase|ReusableSecret" src` no debe mostrar ownership sensible en estado persistente.

---

### Task 3 — Migrar frase humana a PAKE real

**Archivos:** `src/auth.rs`, `src/crypto.rs`, `Cargo.toml`

**Estado:** Implementado con SPAKE2 sobre una clave de frase endurecida con Argon2id. El resultado PAKE se mezcla con TLS exporter, salts y PeerIds para producir `session_key`.

**Problema:** Argon2 + challenge-response reduce fuerza bruta, pero no es un PAKE completo. Si el transcript permite validación offline de guesses, una frase humana débil sigue siendo atacable.

**Solución:** migrar handshake de frase a PAKE:

Opciones aceptables:
- `opaque-ke` si se acepta complejidad mayor y flujo registration-like adaptado a frase efímera.
- SPAKE2/CPace si hay crate mantenido y auditado.
- Si no hay crate suficientemente confiable: mantener Argon2 solo como fase intermedia y documentar que frases deben ser alta entropía.

Flujo objetivo:

```
TLS 1.3 ephemeral listo
↓
PAKE(frase, transcript_tls, cert_peer_ids, salts)
↓
pake_secret
↓
HKDF(pake_secret, TLS exporter || cert IDs || DH pubs) → root material
```

**Criterio de éxito:** un atacante que captura el handshake no puede verificar guesses offline sin interactuar con un peer legítimo.

---

### Task 4 — Transcript binding con TLS exporter + AAD completo

**Archivos:** `src/auth.rs`, `src/peer.rs`, `src/protocol.rs`, `src/ratchet.rs`

**Estado:** Implementado con TLS exporter (`sesame transcript v1`), transcript canónico de sesión, root derivation ligada al transcript y AAD por frame con versión, transcript, sender/receiver, msg number, DH epoch y flags.

**Problema:** El binding actual incluye peer IDs y salts, pero no incluye TLS exporter ni todos los campos de protocolo en AAD.

**Solución:** definir un transcript hash canónico:

```
transcript = SHA256(
  "sesame-v1" ||
  role ||
  tls_exporter("sesame transcript", 32) ||
  initiator_peer_id || responder_peer_id ||
  initiator_salt || responder_salt ||
  initiator_x25519_pub || responder_x25519_pub ||
  cipher_suite_id || frame_version
)
```

Usar `transcript` en:
- auth proof / PAKE context
- HKDF root derivation
- AEAD AAD de cada frame
- dummy traffic key separation

Frame AAD objetivo:

```
AAD = frame_version || direction || peer_id_sender || peer_id_receiver || msg_number || dh_epoch || flags || padded_len
```

**Criterio de éxito:** un frame válido en una sesión/dirección/peer no descifra en otra.

---

### Task 5 — Anti-replay, reorder y downgrade exhaustivo

**Archivos:** `src/ratchet.rs`, `src/protocol.rs`, `src/types.rs`

**Estado:** Implementado parcialmente en core: versión de frame obligatoria, flags reject-by-default, AAD autenticado, replay/stale epoch rejection, límite de future gap y pruebas adversariales básicas. Reordenamiento avanzado con skipped keys sigue limitado por `MAX_SKIP` y requiere más pruebas de interoperabilidad.

**Problema:** El ratchet tiene contadores, pero falta enforcement completo de replay, reordenamiento y versiones.

**Solución:**

- Agregar `frame_version` obligatorio y rechazar versiones desconocidas.
- Autenticar `msg_number`, `previous_chain_len`, `dh_epoch` y dirección.
- Implementar ventana limitada para out-of-order:
  ```rust
  const MAX_SKIP: usize = 100;
  const MAX_FUTURE_GAP: u64 = 100;
  ```
- Guardar skipped keys en `LockedKey`, con zeroize al consumir/expirar.
- Rechazar replay por `(dh_epoch, msg_number)` ya visto.
- Rechazar downgrade si `frame_version < CURRENT_VERSION`.

**Criterio de éxito:** tests negativos para replay, reordenamiento excesivo, downgrade, wrong-direction y stale-DH.

---

### Task 6 — OS hardening + crash/swap discipline

**Archivos:** `src/os_hardening.rs`, `src/main.rs`, documentación de instalación

**Estado:** Implementado para Linux/POSIX básico: `RLIMIT_CORE=0` y `PR_SET_DUMPABLE=0` cuando está disponible. Queda documentar equivalentes Windows/macOS.

**Problema:** `mlock()` reduce swap, pero no controla core dumps, ptrace, logs, terminal history ni límites del sistema.

**Solución:** al inicio del proceso:

- POSIX:
  - `setrlimit(RLIMIT_CORE, 0)`
  - `prctl(PR_SET_DUMPABLE, 0)` cuando esté disponible
  - verificar `RLIMIT_MEMLOCK`
  - warning fuerte si `mlock` no puede bloquear lo mínimo
- Windows:
  - documentar y aplicar mitigaciones equivalentes disponibles
- Logs:
  - nunca imprimir frase, salts completos, claves, plaintext ni ciphertext largo
  - modo debug debe ser opt-in y sanitizado
- CLI:
  - preferir leer frase desde prompt oculto o fd/env temporal sobre `--phrase`, porque argumentos pueden aparecer en process lists/history

**Criterio de éxito:** en modo hardened, no hay core dumps, no hay secretos en logs y la app advierte si el OS no permite bloquear memoria.

---

### Task 7 — DoS y límites antes de cómputo caro

**Archivos:** `src/peer.rs`, `src/session.rs`, `src/auth.rs`

**Estado:** Implementado límite global de handshakes concurrentes y timeout por handshake antes/durante la fase PAKE/Argon2.

**Problema:** Argon2 cuesta CPU/RAM. Un atacante puede abrir conexiones y forzar derivaciones caras.

**Solución:**

- Token bucket por IP antes de Argon2.
- Límite global de handshakes concurrentes.
- Timeout corto por fase de handshake.
- Drop temprano si no hay client cert, versión correcta o framing esperado.
- Backoff para reconexión saliente.
- Métricas internas sin secretos: handshakes rejected, auth failed, rate limited.

**Criterio de éxito:** un atacante no puede forzar más de N derivaciones Argon2 simultáneas ni crecimiento no acotado de memoria.

---

### Task 8 — Fuzzing + property tests + escenarios adversariales

**Archivos:** `tests/`, `fuzz/`, `src/protocol.rs`, `src/ratchet.rs`

**Estado:** Implementadas pruebas adversariales unitarias para padding, versión/flags de frame, AAD incorrecto y replay. Fuzzing continuo queda como gate de auditoría/CI antes de release.

**Problema:** `cargo test` unitario no prueba comportamiento adversarial suficiente.

**Solución:**

- `cargo-fuzz` para:
  - `decode_ratchet_frame()`
  - `remove_padding()`
  - JSON message parsing
  - peer list parsing
- Property tests (`proptest`) para:
  - encode/decode frame roundtrip
  - padding/remove_padding roundtrip
  - wrong AAD never decrypts
  - replay rejected
- Integration tests con 2-3 peers reales:
  - frase correcta conecta
  - frase incorrecta falla
  - MITM/fake cert fails transcript binding
  - F12 kills sessions and process path
  - peer duplicate/self-connection rejected

**Criterio de éxito:** fuzzers corren en CI y ninguna entrada malformada paniquea, OOMea ni descifra como válida.

---

### Task 9 — Auditoría cripto externa antes de producción

**Archivos:** todo el core

**Estado:** Preparado `AUDIT.md` con scope y preguntas obligatorias. La auditoría externa real no puede completarse dentro del repo; sigue siendo gate de producción.

**Problema:** Un protocolo propio con ratchet, PAKE, padding y panic mode no debe considerarse seguro solo por revisión interna.

**Solución:** freeze de protocolo antes de release:

- especificación formal del wire format
- vectores de prueba reproducibles
- revisión externa de `auth.rs`, `ratchet.rs`, `protocol.rs`, `tls.rs`, `crypto.rs`
- checklist de invariantes:
  - no nonce reuse
  - no frame unauthenticated metadata crítico
  - no offline password oracle
  - no accept-all signatures
  - no unbounded allocation
  - no long-lived unlocked key material

**Criterio de éxito:** no marcar Sesame como producción hasta resolver hallazgos críticos/altos de auditoría.

---

### Qué NO hacer

- No inventar un PAKE propio.
- No implementar X25519 manualmente.
- No guardar identidad persistente si el objetivo sigue siendo efímero.
- No confiar en `mlock()` como única defensa: es defense-in-depth.
- No agregar logs de debugging con secretos para “facilitar pruebas”.
- No aceptar “compila” como evidencia de seguridad.
- No prometer seguridad contra kernel/host comprometido en vivo.

### Definición de terminado para Fase 6

La fase se considera completa solo si:

- `cargo check`, `cargo test`, integration tests y fuzz smoke tests pasan.
- No quedan secretos largos fuera de `LockedSecret`/tipos con zeroize equivalente.
- El handshake no permite validación offline práctica de frases humanas.
- Los frames tienen AAD completo y rechazan replay/downgrade/wrong-peer.
- F12 elimina sesiones, corta tareas, restaura terminal y termina proceso.
- `SECURITY.md` documenta garantías, límites y operación segura del sistema.
