use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use sha2::Digest;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

// ═══════════════════════════════════════════════════════════════════════════
// PRIMITIVAS CRIPTOGRAFICAS
// ═══════════════════════════════════════════════════════════════════════════
// Este archivo contiene las operaciones matematicas de bajo nivel que
// usamos para proteger los mensajes: generacion de claves, hashing,
// derivacion, Diffie-Hellman, etc.
//
// Tambien tiene los wrappers de memoria segura (LockedBytes, LockedKey)
// que garantizan que los secretos se borren al terminar y no se vayan
// al swap del disco.
// ═══════════════════════════════════════════════════════════════════════════

/// Un bloque de bytes generico con proteccion de memoria.
///
/// Que hace
/// 1. Al crear, llama a `mlock` para evitar que el SO mueva estos bytes
///    al disco (swap).
/// 2. Al destruir (Drop), llama a `zeroize` para sobrescribir los bytes
///    con ceros, y luego `munlock` para liberar la memoria.
///
/// Para que sirve
/// Si el programa crashea y el SO hace un core dump, o si alguien
/// fuerza un intercambio de memoria a disco, los secretos no quedan
/// al descubierto.
///
/// Diferencia con LockedKey
/// LockedBytes es generico (cualquier longitud). LockedKey es
/// estrictamente para claves de 32 bytes (tamaño tipico de AES-256,
/// ChaCha20, SHA-256, X25519, etc.).
pub struct LockedBytes {
    bytes: Box<[u8]>,
}

impl LockedBytes {
    /// Crea un nuevo LockedBytes, lockea la memoria y devuelve el wrapper.
    ///
    /// Parametros
    /// * `bytes` — los datos secretos (se mueven adentro, el caller pierde acceso)
    pub fn new(bytes: Vec<u8>) -> Self {
        let locked = Self {
            bytes: bytes.into_boxed_slice(),
        };
        try_mlock(locked.as_bytes());
        locked
    }

    /// Devuelve una referencia a los bytes internos.
    /// Solo lectura — no se puede modificar desde afuera.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl Drop for LockedBytes {
    /// Al destruir: sobrescribe con ceros y desbloquea la memoria.
    fn drop(&mut self) {
        self.bytes.zeroize();
        try_munlock(self.as_bytes());
    }
}

/// Una clave criptografica de exactamente 32 bytes, con proteccion de memoria.
///
/// Por que 32 bytes exactos
/// - SHA-256 output: 32 bytes
/// - ChaCha20 key: 32 bytes
/// - X25519 secret: 32 bytes
/// - HKDF output tipico: 32 bytes
///
/// Tener un tipo dedicado previene errores de tamaño (pasar 16 bytes
/// donde se esperan 32, etc.).
pub struct LockedKey {
    bytes: Box<[u8; 32]>,
}

impl LockedKey {
    /// Crea un nuevo LockedKey a partir de 32 bytes.
    pub fn new(bytes: [u8; 32]) -> Self {
        let key = Self {
            bytes: Box::new(bytes),
        };
        try_mlock(key.as_bytes());
        key
    }

    /// Referencia de solo lectura a los 32 bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }

    /// Reemplaza la clave interna con otros 32 bytes.
    /// La clave vieja se sobrescribe con zeroize antes de copiar la nueva.
    ///
    /// Por que no se puede tener as_bytes_mut(): para evitar que por
    /// accidente se modifique la clave sin que el LockedKey sepa que
    /// cambio. Con replace() explicitamente indicas "quiero cambiar la
    /// clave" y el LockedKey se encarga de limpiar la vieja primero.
    pub fn replace(&mut self, bytes: [u8; 32]) {
        self.bytes.zeroize();
        self.bytes.copy_from_slice(&bytes);
        let mut new_bytes = bytes;
        new_bytes.zeroize();
        try_mlock(self.as_bytes());
    }
}

impl Drop for LockedKey {
    fn drop(&mut self) {
        self.bytes.zeroize();
        try_munlock(self.as_bytes());
    }
}

/// Un secreto Diffie-Hellman (clave privada X25519) con proteccion de memoria.
///
/// Para que sirve
/// El Double Ratchet necesita generar nuevas claves Diffie-Hellman en
/// cada "ratchet step". LockedDhSecret encapsula ese secreto y puede:
/// - Generar uno nuevo aleatorio
/// - Calcular su clave publica correspondiente
/// - Hacer DH con la clave publica del peer para obtener un secreto compartido
///
/// Por que una struct separada de LockedKey
/// Porque operacionalmente es diferente: LockedDhSecret GENERA pares
/// de claves (privada + publica) y hace la operacion matematica DH.
/// LockedKey solo guarda bytes.
pub struct LockedDhSecret {
    bytes: LockedKey,
}

impl LockedDhSecret {
    /// Genera un nuevo secreto DH aleatorio de 32 bytes.
    ///
    /// Usa `OsRng` (random criptografico del sistema operativo).
    pub fn generate() -> Self {
        Self {
            bytes: LockedKey::new(generate_random_bytes::<32>()),
        }
    }

    /// Calcula la clave publica X25519 correspondiente a este secreto.
    ///
    /// Como funciona X25519
    /// X25519 es un algoritmo de curva eliptica (Curve25519). Dado un
    /// secreto privado (32 bytes aleatorios), se multiplica por un punto
    /// base fijo de la curva para obtener la clave publica.
    ///
    /// Devuelve
    /// Un `PublicKey` de x25519-dalek que se puede enviar al otro peer.
    pub fn public_key(&self) -> PublicKey {
        let secret = StaticSecret::from(*self.bytes.as_bytes());
        PublicKey::from(&secret)
    }

    /// Calcula el secreto compartido DH con la clave publica de otro peer.
    ///
    /// Como funciona
    /// Hace: nuestro_secreto * su_publica = punto compartido en la curva.
    /// Ambos peers obtienen el MISMO punto porque:
    ///   Peer A: secreto_A * publica_B = compartido
    ///   Peer B: secreto_B * publica_A = compartido (mismo resultado!)
    ///
    /// Parametros
    /// * `peer` — la clave publica X25519 del otro peer
    ///
    /// Devuelve
    /// Un LockedKey con los 32 bytes del secreto compartido.
    pub fn diffie_hellman(&self, peer: &PublicKey) -> LockedKey {
        let secret = StaticSecret::from(*self.bytes.as_bytes());
        LockedKey::new(secret.diffie_hellman(peer).to_bytes())
    }
}

/// Deriva una clave de 32 bytes a partir de una frase de paso usando Argon2id.
///
/// Argon2id es un KDF (Key Derivation Function) "memory-hard" — para
/// calcularlo necesitas reservar MUCHA RAM (64 MB por defecto). Eso
/// hace que sea muy costoso para un atacante probar muchas frases
/// por segundo, incluso con GPUs o ASICs.
///
/// Parametros
/// * `phrase` — la frase de paso (ej: "mi frase secreta")
/// * `salt_a` — salt del primer peer (32 bytes)
/// * `salt_b` — salt del segundo peer (32 bytes)
///
/// Los salts se ordenan (menor primero) para que ambos peers obtengan
/// la misma clave aunque intercambien los roles.
///
/// Devuelve
/// `LockedKey` con los 32 bytes derivados, o error si Argon2 falla.
///
/// Parametros de Argon2id
/// - Memoria: 65536 KB (64 MB)
/// - Iteraciones: 3
/// - Paralelismo: 4 hilos
/// - Output: 32 bytes
///
/// Estos valores son un balance entre seguridad (costo para atacante)
/// y velocidad (el usuario espera 1-2 segundos al conectar).
pub fn derive_key(
    phrase: &[u8],
    salt_a: &[u8; 32],
    salt_b: &[u8; 32],
) -> Result<LockedKey, String> {
    let combined_salt = {
        let mut s = [0u8; 64];
        if salt_a < salt_b {
            s[..32].copy_from_slice(salt_a);
            s[32..].copy_from_slice(salt_b);
        } else {
            s[..32].copy_from_slice(salt_b);
            s[32..].copy_from_slice(salt_a);
        }
        s
    };

    let params = Params::new(65536, 3, 4, Some(32)).map_err(|e| e.to_string())?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut output = [0u8; 32];
    argon2
        .hash_password_into(phrase, &combined_salt, &mut output)
        .map_err(|e| e.to_string())?;

    Ok(LockedKey::new(output))
}

/// Deriva 32 bytes a partir de un Input Key Material (IKM) usando HKDF-SHA256
/// sin salt (salt = empty).
///
/// Cuando se usa
/// Para derivar las cadenas iniciales de envio y recepcion del Double Ratchet.
///
/// Parametros
/// * `ikm` — material clave de entrada (ej: la root key)
/// * `info` — contexto de derivacion (ej: b"sesame-send" o b"sesame-recv")
///
/// Devuelve
/// 32 bytes derivados.
///
/// Por que HKDF y no solo SHA-256
/// HKDF es un "extractor" + "expand". Si el IKM no es uniforme
/// (tiene sesgo estadistico), HKDF lo "extrae" a una clave uniforme
/// y luego la "expande" a la longitud deseada. SHA-256 directo no
/// garantiza eso.
pub fn hkdf_derive(ikm: &[u8], info: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, ikm);
    let mut okm = [0u8; 32];
    hk.expand(info, &mut okm).expect("HKDF expand failed");
    okm
}

/// Deriva N bytes usando HKDF-SHA256 CON salt.
///
/// Diferencia con `hkdf_derive`
/// `hkdf_derive` usa salt = None. Esta version permite pasar un salt
/// especifico, que anade entropia adicional. Se usa para la root chain
/// del ratchet, donde el salt es la session_key y el IKM incluye el
/// shared_secret DH + transcript.
///
/// Parametros
/// * `salt` — salt adicional (opcional, pero aca siempre presente)
/// * `ikm` — material clave de entrada
/// * `info` — contexto
/// * `output` — buffer de salida (puede ser de cualquier tamaño)
pub fn hkdf_expand_with_salt(salt: &[u8], ikm: &[u8], info: &[u8], output: &mut [u8]) {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    hk.expand(info, output).expect("HKDF expand failed");
}

/// Calcula SHA-256 de multiples partes concatenadas.
///
/// Para que sirve
/// Para crear hashes compuestos de varios elementos: claves + IDs + contextos.
/// En lugar de hacer varias operaciones SHA-256 separadas, hacemos una sola
/// con todos los componentes, que es mas seguro (evita ataques de colision
/// parcial).
///
/// Parametros
/// * `parts` — slice de slices de bytes (todas las partes a hashear juntas)
///
/// Devuelve
/// 32 bytes: el hash SHA-256 de la concatenacion de todas las partes.
pub fn sha256_many(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

/// Genera N bytes aleatorios criptograficamente seguros usando el
/// generador aleatorio del sistema operativo (OsRng).
///
/// Por que OsRng y no rand::thread_rng()
/// `thread_rng()` es un PRNG (pseudo-random) que puede ser predecible
/// si un atacante conoce el estado interno. `OsRng` usa la fuente de
/// entropia del kernel (/dev/urandom en Linux, CryptGenRandom en
/// Windows) que es impredecible incluso para el mismo proceso.
///
/// Parametro de const generic
/// `N` se define en el caller: `generate_random_bytes::<32>()` genera
/// 32 bytes. Esto evita tener que pasar la longitud como parametro
/// en runtime.
pub fn generate_random_bytes<const N: usize>() -> [u8; N] {
    use rand::RngCore;
    let mut bytes = [0u8; N];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    bytes
}

/// Intenta bloquear (mlock) una region de memoria para que el SO no la
/// mueva al disco (swap).
///
/// Por que puede fallar
/// - La plataforma no soporta mlock (ej: algunos containers)
/// - Limite de memoria lockeable alcanzado (RLIMIT_MEMLOCK)
///
/// Devuelve
/// `true` si se lockeo exitosamente, `false` si no (no es fatal).
pub fn try_mlock(data: &[u8]) -> bool {
    let ptr = data.as_ptr() as *const std::ffi::c_void;
    match unsafe { os_memlock::mlock(ptr, data.len()) } {
        Ok(()) => true,
        Err(e) if e.kind() == std::io::ErrorKind::Unsupported => false,
        Err(e) => {
            eprintln!("[sesame] mlock failed: {e}");
            false
        }
    }
}

/// Intenta desbloquear (munlock) una region de memoria previamente lockeada.
pub fn try_munlock(data: &[u8]) {
    let ptr = data.as_ptr() as *const std::ffi::c_void;
    let _ = unsafe { os_memlock::munlock(ptr, data.len()) };
}
