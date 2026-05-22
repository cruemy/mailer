use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::Instant;

// ═══════════════════════════════════════════════════════════════════════════
// TIPOS Y CONSTANTES DEL PROTOCOLO
// ═══════════════════════════════════════════════════════════════════════════
// Este archivo define los tipos de datos que se usan en todo el programa.
// Aca estan los mensajes que viajan por la red, las identidades de los
// peers, las direcciones IP:puerto, y los estados de las conexiones.
// ═══════════════════════════════════════════════════════════════════════════

/// Un mensaje de chat que viaja entre peers, serializado como JSON.
///
/// Este struct se convierte a JSON con serde, se cifra con el Double
/// Ratchet, y se manda por la conexion TLS. Del otro lado se recibe,
/// se descifra, y se muestra en la TUI.
///
/// Campos
/// * `peer_id` — quien envio este mensaje (identidad unica de 32 bytes)
/// * `text` — el texto del mensaje (vacio para mensajes dummy o flags)
/// * `timestamp` — (sin usar por ahora, siempre 0)
/// * `flags` — que tipo de mensaje es (real, dummy, sistema, etc.)
///
/// Por que flags en vez de tipos separados
/// Porque todo viaja por el mismo canal cifrado. En lugar de tener
/// multiples tipos de mensajes, usamos un unico struct con un byte
/// de "flag" que dice de que va la cosa. Esto simplifica el
/// serializado y el enrutamiento.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ChatMessage {
    pub peer_id: PeerId,
    pub text: String,
    pub timestamp: u64,
    pub flags: u8,
}

// ─── Flags de mensajes ──────────────────────────────────────────────────
// Cada mensaje lleva un byte "flags" que indica que tipo de mensaje es.
//
// FLAG_REAL              = 0 — mensaje de chat real escrito por el usuario
// FLAG_DUMMY             = 1 — mensaje ficticio para ofuscar trafico
// FLAG_PEER_LIST_REQ     = 2 — pide la lista de peers conocidos
// FLAG_PEER_LIST_RES     = 3 — respuesta con la lista de peers
// FLAG_SYSTEM_JOIN       = 4 — aviso: un peer se conecto al mesh
// FLAG_SYSTEM_LEAVE      = 5 — aviso: un peer se desconecto
// FLAG_SYSTEM_ALONE      = 6 — indica que no quedan peers, regenerar ID
// FLAG_SYSTEM_INFO       = 7 — mensaje informativo del sistema
// FLAG_SYSTEM_GOODBYE    = 8 — despedida: cierre limpio de sesion
// FLAG_SYSTEM_DISPLAY_NAME = 9 — intercambio de nombre visible
//
// Por que numeros y no un enum?
// Porque los enums de Rust con serde no son tan eficientes en redes.
// Con un u8 tenemos 256 flags posibles y es trivial de serializar.

/// Mensaje de chat real (escrito por el usuario)
pub const FLAG_REAL: u8 = 0;
/// Mensaje dummy para ofuscar trafico (se ignora al recibir)
pub const FLAG_DUMMY: u8 = 1;
/// Solicitud de lista de peers conocidos
pub const FLAG_PEER_LIST_REQ: u8 = 2;
/// Respuesta con lista de peers conocidos
pub const FLAG_PEER_LIST_RES: u8 = 3;
/// Aviso: un peer se unio al grupo
pub const FLAG_SYSTEM_JOIN: u8 = 4;
/// Aviso: un peer abandono el grupo
pub const FLAG_SYSTEM_LEAVE: u8 = 5;
/// No quedan peers conectados — regenerar identidad TLS
pub const FLAG_SYSTEM_ALONE: u8 = 6;
/// Mensaje informativo del sistema (conexion perdida, error, etc.)
pub const FLAG_SYSTEM_INFO: u8 = 7;
/// Despedida: cierre limpio de sesion (no reconectar)
pub const FLAG_SYSTEM_GOODBYE: u8 = 8;
/// Intercambio de nombre visible (display name)
pub const FLAG_SYSTEM_DISPLAY_NAME: u8 = 9;

/// Identificador unico de un peer (32 bytes = SHA-256 de su certificado).
///
/// Cuando dos peers se conectan, intercambian certificados TLS. Cada
/// certificado tiene una clave publica Ed25519. Hacemos SHA-256 del
/// certificado en DER y obtenemos 32 bytes que identifican a ese peer
/// de forma unica.
///
/// Por que 32 bytes
/// Porque es el output de SHA-256. Es suficientemente grande para
/// evitar colisiones (2^128 de seguridad por birthday attack) y
/// suficientemente chico para mandarlo en cada mensaje sin ocupar
/// mucho ancho de banda.
///
/// PeerId vs IP
/// La IP de un peer puede cambiar (DHCP, VPN, etc). El PeerId es
/// estable mientras el certificado no cambie. Como generamos un
/// certificado nuevo en cada ejecucion, el PeerId cambia cada vez
/// que arranca el programa.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Debug)]
pub struct PeerId(pub [u8; 32]);

impl PeerId {
    /// Crea un PeerId haciendo SHA-256 del certificado TLS en formato DER.
    ///
    /// Parametros
    /// * `der` — el certificado TLS del peer en formato binario DER.
    ///   Se recibe durante el handshake TLS.
    ///
    /// Por que del certificado y no de la clave publica
    /// Porque el certificado incluye metadata adicional (nombre del
    /// emisor, fecha de expiracion, etc.) que hace mas dificil que
    /// dos peers diferentes tengan el mismo PeerId accidentalmente.
    pub fn from_cert_der(der: &[u8]) -> Self {
        let hash = Sha256::digest(der);
        Self(hash.into())
    }
}

/// Muestra el PeerId como hex (solo primeros 8 bytes) para lectura humana.
///
/// Ejemplo
/// `a1b2c3d4e5f6a7b8`
///
/// Por que solo 8 bytes
/// 16 caracteres hex son suficientes para distinguir peers en una
/// sesion tipica. Mostrar los 64 caracteres completos seria ilegible.
impl std::fmt::Display for PeerId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for byte in &self.0[..8] {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

/// Direccion de red de un peer: IP + puerto.
///
/// Ejemplos
/// * `192.168.1.42:9000`
/// * `[::1]:9000` (IPv6)
///
/// Por que separar IP y puerto en vez de un string
/// Porque necesitamos comparar direcciones, serializarlas a JSON,
/// y convertirlas a SocketAddr. Tenerlos como campos separados
/// hace todo mas facil y type-safe.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct PeerAddr {
    pub ip: std::net::IpAddr,
    pub port: u16,
}

/// Parsea un string "IP:PORT" a un PeerAddr.
///
/// Ejemplo
/// `"192.168.1.1:9000".parse::<PeerAddr>()` -> Ok(PeerAddr { ip: 192.168.1.1, port: 9000 })
///
/// Errores posibles
/// * Falta el puerto (no hay `:`)
/// * El puerto no es un numero valido
/// * La IP no es una direccion IP valida
impl std::str::FromStr for PeerAddr {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (ip, port) = s.split_once(':').ok_or("missing port in peer address")?;
        let port: u16 = port.parse().map_err(|_| "invalid port".to_string())?;
        let ip: std::net::IpAddr = ip.parse().map_err(|_| "invalid IP address".to_string())?;
        Ok(Self { ip, port })
    }
}

/// Muestra un PeerAddr como "IP:PORT".
impl std::fmt::Display for PeerAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.ip, self.port)
    }
}

/// Estado de una sesion con un peer.
///
/// Variantes
/// * `Handshaking` — estamos negociando la conexion (TLS + SPAKE2 + DH)
/// * `Connected` — sesion establecida, podemos enviar/recibir mensajes
/// * `Disconnected` — la sesion termino
///
/// Por que un enum y no bools
/// Porque un enum es mas claro: cada estado es mutuamente excluyente.
/// Con bools tendrias que verificar combinaciones invalidas
/// (ej: handshaking && connected = true).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[allow(dead_code)]
pub enum SessionState {
    Handshaking,
    Connected,
    Disconnected,
}

/// Modo de panico: real (frase verdadera) o decoy (frase señuelo).
///
/// `Real`
/// Usas la frase de paso verdadera. Tus mensajes son reales.
///
/// `Decoy`
/// Usas una frase señuelo. La UI muestra "PANIC MODE" en rojo.
/// Si alguien te obliga a mostrar el chat, ven una conversacion
/// falsa con una identidad diferente.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[allow(dead_code)]
pub enum PanicMode {
    Real,
    Decoy,
}

impl PanicMode {
    /// Cambia al modo opuesto.
    /// Real -> Decoy, Decoy -> Real.
    #[allow(dead_code)]
    pub fn toggle(&self) -> Self {
        match self {
            PanicMode::Real => PanicMode::Decoy,
            PanicMode::Decoy => PanicMode::Real,
        }
    }
}

/// Informacion resumida de una sesion activa.
///
/// Se usa para mostrar la lista de peers conectados en la UI y
/// para que el sistema de timeout sepa cuando fue el ultimo mensaje.
///
/// Campos
/// * `peer_id` — quien es este peer
/// * `peer_addr` — donde esta (IP:puerto)
/// * `connected_since` — cuando se conecto (para calcular uptime)
/// * `last_message` — cuando fue el ultimo mensaje (para timeout)
#[derive(Clone, Debug)]
pub struct SessionInfo {
    pub peer_id: PeerId,
    pub peer_addr: PeerAddr,
    #[allow(dead_code)]
    pub connected_since: Instant,
    #[allow(dead_code)]
    pub last_message: Instant,
}
