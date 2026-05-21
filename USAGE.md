# Sesame — Uso

## Ayuda rápida

```bash
cargo run -- --help
```

```
Usage: sesame --peer IP:PORT [--peer IP:PORT ...] (--phrase "frase" | --phrase-fd FD)
             [--decoy] [--port 9000] [--inactivity-timeout 300]

Flags:
  --peer IP:PORT              Peer conocido al que conectarse (repetible)
  --phrase "frase"            Frase de autenticación
  --phrase-fd FD              Leer frase desde file descriptor
  --decoy                     Arrancar con frase señuelo (la app antepone "decoy-")
  --port N                    Puerto de escucha (default: 9000)
  --inactivity-timeout N      Segundos antes de dropear un peer inactivo (default: 300)
  --help, -h                  Mostrar esta ayuda
```

**Controles en la UI:**
- `Enter` — enviar mensaje
- `Esc` o `F12` — salir
- Escribir normalmente — ingresar texto

---

## Conexión entre 2 personas

### 1 → 1 (unidireccional)
Solo uno tiene `--peer` apuntando al otro. El que no tiene `--peer` solo escucha.

**Ana** (escucha, sin `--peer`):
```bash
cargo run -- --phrase "secreto"
```

**Bob** (se conecta a Ana):
```bash
cargo run -- --peer 192.168.1.42:9000 --phrase "secreto"
```

Si Ana se cae, Bob puede reconectar automáticamente (Ana necesita tener `--peer` apuntando a Bob para que Bob pueda reconectar). Si Bob se cae, él mismo reconecta porque tiene la dirección de Ana.

**Cuándo usarlo:** cuando una persona es fija (ej: servidor en casa) y la otra se conecta desde afuera. Simple, un solo `--peer`.

### 1 ↔ 1 (bidireccional)
Ambos tienen `--peer` apuntando al otro.

**Ana:**
```bash
cargo run -- --peer 192.168.1.99:9000 --phrase "secreto"
```

**Bob:**
```bash
cargo run -- --peer 192.168.1.42:9000 --phrase "secreto"
```

Cualquiera de los dos puede caerse y el otro lo reconecta automáticamente.

**Cuándo usarlo:** cuando ambos son pares iguales (peer-to-peer real). Máxima resiliencia. Si ambos se caen a la vez, no hay reconexión posible.

---

## Conexión entre 3 o más personas

Todas las personas deben tener la **misma frase**. Cada una se conecta a al menos una otra persona de la red — el peer discovery se encarga de propagar el resto.

Ejemplo con 3 personas (Ana `192.168.1.42`, Bob `192.168.1.99`, Carlos `192.168.1.77`):

**Ana:**
```bash
cargo run -- --phrase "secreto"
```

**Bob:**
```bash
cargo run -- --peer 192.168.1.42:9000 --phrase "secreto"
```

**Carlos:**
```bash
cargo run -- --peer 192.168.1.42:9000 --phrase "secreto"
```

Ana no necesita `--peer` porque los demás se conectan a ella. Bob y Carlos se conectan a Ana. Una vez conectados, el peer discovery propaga las direcciones y todos ven a todos.

Para máxima resiliencia (cualquiera puede reconectar a cualquiera):

**Ana:**
```bash
cargo run -- --peer 192.168.1.99:9000 --peer 192.168.1.77:9000 --phrase "secreto"
```

**Bob:**
```bash
cargo run -- --peer 192.168.1.42:9000 --peer 192.168.1.77:9000 --phrase "secreto"
```

**Carlos:**
```bash
cargo run -- --peer 192.168.1.42:9000 --peer 192.168.1.99:9000 --phrase "secreto"
```

---

## Cómo averiguar tu IP

```bash
# Windows
ipconfig

# Linux / macOS
ip a
# o
ifconfig
```

Usá la IP local (empieza con `192.168.`, `10.`, `172.16.`) — la que termina en `9000` en el `--peer`.

---

## Comportamiento ante caídas de conexión

| Escenario | Qué pasa |
|---|---|
| Se cae 1 peer, quedan ≥ 2 | Los demás peers reconectan automáticamente al caído |
| Se cae 1 peer, queda 1 | El que quedó solo regenera identidad y espera nuevas conexiones |
| 2 personas, se cae 1 | El que quedó solo regenera identidad |
| Se cae la red completa | Cada uno queda solo, regenera identidad. Hay que volver a conectar con `--peer` |

**Regenerar identidad** significa nuevo certificado TLS + nuevo PeerId. Es como arrancar de cero — otros peers te ven como alguien nuevo cuando te reconectás.

---

## Puerto y firewall

Por defecto `9000`. Cambiá con `--port` si hace falta. Asegurate de tener el puerto abierto en el firewall para conexiones entrantes.
