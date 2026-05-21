# Sesame — Uso

## Ayuda rápida

```bash
cargo run -- --help
```

```
Usage: sesame --peer IP:PORT [--peer IP:PORT ...] (--phrase "frase" | --phrase-fd FD)
              [--decoy] [--port 9000] [--inactivity-timeout 300]
              [--display-name "Nombre"]

Flags:
  --peer IP:PORT              Peer conocido al que conectarse (repetible)
  --phrase "frase"            Frase de autenticación
  --phrase-fd FD              Leer frase desde file descriptor
  --decoy                     Arrancar con frase señuelo (la app antepone "decoy-")
  --port N                    Puerto de escucha (default: 9000)
  --inactivity-timeout N      Segundos antes de dropear un peer inactivo (default: 300)
  --display-name "Name"       Setear o actualizar tu nombre visible (se persiste)
  --help, -h                  Mostrar esta ayuda
```

**Controles en la UI:**
- `Enter` — enviar mensaje
- `Esc` — salir (envía goodbye a peers conectados)
- `F12` — pánico: regenera identidad, borra sesiones y known_peers (nuevo certificado TLS + nuevo PeerId)
- `Re Pág` / `Av Pág` — desplazar historial
- Escribir normalmente — ingresar texto

---

## Cierre de sesión

### `Esc` — Cierre limpio

Envía un mensaje `GOODBYE` a todos los peers conectados, espera 200ms para que se entregue, y termina el proceso.

**Del otro lado:**
- Recibe el goodbye → borra al emisor de `known_peers` (no intenta reconectarlo)
- Si era el único peer (1:1 o 1→N) → también cierra la app automáticamente
- Si hay más peers conectados (mesh) → solo muestra `[peer] disconnected` y sigue

### `F12` — Pánico / Identity rotation

**No envía goodbye.** En su lugar:
1. Envía `FLAG_SYSTEM_ALONE` a todos los peers
2. Genera un **nuevo certificado TLS** → nuevo PeerId
3. Actualiza acceptor/connector con el nuevo certificado
4. Borra todas las sesiones y `known_peers`
5. El proceso sigue corriendo con identidad nueva

**Del otro lado:**
- Los peers rotan también su identidad
- `known_peers` se limpia del lado que hizo F12
- Es como arrancar de cero: los demás te ven como un peer nuevo

### Matar el proceso (kill, taskkill, Ctrl+Break)

Sin goodbye. El otro lado lo trata como caída de red → el loop de reconexión lo reintenta cada 5s. Para que deje de reconectar, el peer debe cerrar con `Esc` (si el receptor cierra, manda goodbye y el otro para de reconectar).

---

## Display name

Podés elegir un nombre visible con `--display-name`. Se persiste en `~/.config/sesame/config.json` (Linux/macOS) o `%APPDATA%\sesame\config.json` (Windows). La próxima vez que arranques sin `--display-name`, se usa el guardado.

```bash
# Setear o actualizar
sesame --phrase "secreto" --display-name "Sesame"

# La próxima vez, el nombre persiste aunque no pases --display-name
sesame --phrase "secreto"
```

El nombre se envía a los peers cuando te conectás, y se muestra en:
- **Lista de peers**: en vez de la IP
- **Chat**: como prefijo de cada mensaje (en vez del PeerId hex)

Si no se ha seteado un display name, se muestra el PeerId corto como antes.

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
| Se cae 1 peer, quedan ≥ 2 | Los demás peers reconectan automáticamente al caído (cada 5s) |
| Se cae 1 peer, queda 1, sin goodbye | El que quedó solo regenera identidad y espera nuevas conexiones |
| 2 personas, se cae 1 sin goodbye | El que quedó solo regenera identidad |
| Se cae la red completa | Cada uno queda solo, regenera identidad. Hay que volver a conectar con `--peer` |
| Peer cierra con `Esc` | Envía goodbye → los demás lo borran de known_peers y no reconectan. Si era 1:1, el receptor también cierra |
| Peer cierra con `F12` | Identity rotation. Todos los peers rotan su identidad, known_peers se limpia |

**Regenerar identidad** significa nuevo certificado TLS + nuevo PeerId. Es como arrancar de cero — otros peers te ven como alguien nuevo cuando te reconectás.

---

## Puerto y firewall

Por defecto `9000`. Cambiá con `--port` si hace falta.

### Firewall de Windows

Si el otro peer no puede conectarse — incluso estando en la misma red — lo más probable es que Windows Firewall esté bloqueando el puerto.

**Paso 1 — Crear regla de entrada** (PowerShell como Administrador):

```powershell
New-NetFirewallRule -DisplayName "Sesame P2P" -Direction Inbound -Protocol TCP -LocalPort 9000 -Action Allow
```

Esto permite tráfico TCP entrante en el puerto `9000` desde cualquier perfil de red (pública, privada, dominio). Cambiá el puerto si usaste `--port` con otro valor.

**Paso 2 — Si el problema persiste, desactivar temporalmente el firewall** (solo para diagnóstico):

```powershell
Set-NetFirewallProfile -Profile (Get-NetConnectionProfile).NetworkCategory -Enabled False
```

Esto apaga el firewall **solo para el perfil de red activo** (Private, Public o Domain). Probá la conexión; si funciona, reactivalo con `-Enabled True`. Si el problema sigue incluso con el firewall desactivado, no es el firewall — revisá que estén en la misma red/subred y que las IPs sean correctas.

**Para verificar conectividad local:**

```powershell
Test-NetConnection -ComputerName 127.0.0.1 -Port 9000
```

Si `TcpTestSucceeded` es `True`, sesame está escuchando bien. Si es `False`, revisá que el proceso esté corriendo. Luego probá el mismo comando desde la otra PC reemplazando `127.0.0.1` por la IP del que escucha.
