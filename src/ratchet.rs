use std::collections::{HashMap, HashSet};

use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use sha2::{Digest, Sha256};
use x25519_dalek::PublicKey;
use zeroize::Zeroize;

use crate::crypto::{LockedDhSecret, LockedKey, hkdf_derive};

// ═══════════════════════════════════════════════════════════════════════════
// DOUBLE RATCHET (ALGORITMO DE CIFRADO POR SESION)
// ═══════════════════════════════════════════════════════════════════════════
// Implementacion del algoritmo Double Ratchet (Signal Protocol). Este es
// el corazon criptografico de Sesame: genera claves de cifrado unicas
// para cada mensaje, de forma que si una clave se compromete, los
// mensajes anteriores y posteriores siguen siendo seguros.
//
// "Ratcheting" = avanzar un mecanismo que solo va hacia adelante,
// como un trinquete. No se puede volver atras.
// ═══════════════════════════════════════════════════════════════════════════

/// Cada cuantos mensajes hacemos un DH ratchet (intercambio de claves
/// Diffie-Hellman). Con DH_RATCHET_INTERVAL = 3, cada 3 mensajes
/// generamos nuevas claves efimeras.
///
/// Por que cada 3 mensajes
/// - Si es cada 1: demasiado overhead (cada mensaje lleva 32 bytes
///   extra de clave publica + computacion DH)
/// - Si es cada muchos: si se compromete la clave actual, se pierden
///   muchos mensajes (falta de "forward secrecy" temporal)
/// - 3 es un balance aceptado en implementaciones reales (Signal usa
///   un esquema similar aunque mas complejo)
const DH_RATCHET_INTERVAL: u32 = 3;

/// Implementacion del Double Ratchet.
///
/// Como funciona (conceptual)
///
/// Hay DOS "ratchets" (trinquetes) que avanzan juntos:
///
/// 1. **Ratchet simetrico (chain ratchet)**: Cada vez que enviamos o
///    recibimos un mensaje, hacemos SHA-256 de la clave actual para
///    obtener la siguiente. Esto asegura "forward secrecy" dentro de
///    la misma epoch DH: si alguien obtiene la clave de este mensaje,
///    NO puede descifrar el mensaje anterior (porque SHA-256 es
///    one-way) ni el siguiente (porque necesita el hash).
///
/// 2. **Ratchet asimetrico (DH ratchet)**: Cada ciertos mensajes,
///    generamos un nuevo par de claves Diffie-Hellman y hacemos DH
///    con la clave publica del otro. Esto genera una nueva "raiz"
///    (root key) de la cual derivamos nuevas cadenas de envio y
///    recepcion. Esto asegura "future secrecy" o "self-healing":
///    si un atacante obtiene todas las claves actuales, cuando
///    cualquiera de los dos envie un mensaje con nuevo DH, el
///    atacante pierde la capacidad de descifrar.
///
/// Estructura interna
/// - `root_chain` — la clave raiz, de la cual se derivan las cadenas
///   de envio y recepcion cada vez que hacemos DH ratchet
/// - `send_chain` — la cadena de claves para ENVIAR mensajes (avanza
///   con cada mensaje que enviamos)
/// - `recv_chain` — la cadena de claves para RECIBIR mensajes (avanza
///   con cada mensaje que recibimos)
/// - `our_secret` — nuestro secreto DH actual
/// - `our_public` — nuestra clave publica DH actual
/// - `their_public` — la ultima clave publica DH conocida del otro
/// - `dh_counter` — contador de mensajes desde el ultimo DH ratchet
/// - `msg_number_send/recv` — contadores de mensajes enviados/recibidos
/// - `dh_epoch` — contador de cuantos DH ratchets hicimos
/// - `skipped_keys` — claves salteadas (mensajes fuera de orden)
/// - `seen_messages` — mensajes ya vistos (para prevenir replay)
pub struct DoubleRatchet {
    root_chain: LockedKey,
    send_chain: LockedKey,
    recv_chain: LockedKey,
    our_secret: Option<LockedDhSecret>,
    our_public: PublicKey,
    their_public: Option<PublicKey>,
    dh_counter: u32,
    msg_number_send: u64,
    msg_number_recv: u64,
    dh_epoch: u64,
    #[allow(dead_code)]
    max_skip: usize,
    skipped_keys: HashMap<(u64, [u8; 32]), [u8; 32]>,
    seen_messages: HashSet<(u64, u64)>,
}

/// Un frame cifrado listo para ser enviado por la red.
///
/// Campos
/// * `nonce` — 12 bytes aleatorios (unique por mensaje con la misma clave)
/// * `msg_number` — numero de mensaje en esta epoch (para ordenar)
/// * `dh_epoch` — en que epoch DH se envio
/// * `ciphertext` — el mensaje cifrado (sin el tag)
/// * `tag` — 16 bytes de autenticacion Poly1305
/// * `dh_public_key` — clave publica DH si este mensaje hace DH ratchet
///
/// Por que nonce aleatorio en vez de secuencial
/// Seguridad: si mandas dos mensajes con el MISMO nonce y la MISMA
/// clave, ChaCha20Poly1305 se rompe (se puede recuperar la clave).
/// Con nonce aleatorio (12 bytes) la probabilidad de colision es
/// esencialmente 0 (2^96 mensajes para tener 50% de colision).
pub struct EncryptedFrame {
    pub nonce: [u8; 12],
    pub msg_number: u64,
    pub dh_epoch: u64,
    pub ciphertext: Vec<u8>,
    pub tag: [u8; 16],
    pub dh_public_key: Option<PublicKey>,
}

/// Un frame recibido (sin descifrar) listo para ser procesado por el ratchet.
///
/// Es identico a EncryptedFrame pero separado semanticamente:
/// EncryptedFrame = lo que CREAMOS para enviar
/// ReceivedFrame = lo que RECIBIMOS del otro lado
pub struct ReceivedFrame {
    pub nonce: [u8; 12],
    pub msg_number: u64,
    pub dh_epoch: u64,
    pub ciphertext: Vec<u8>,
    pub tag: [u8; 16],
    pub dh_public_key: Option<PublicKey>,
}

impl DoubleRatchet {
    /// Crea un nuevo DoubleRatchet con la clave raiz inicial.
    ///
    /// Flujo de creacion
    /// 1. Recibe la root_key derivada del handshake
    /// 2. Genera las cadenas iniciales (send y recv) usando HKDF
    /// 3. Si somos initiator, send = "sesame-send", recv = "sesame-recv"
    /// 4. Si somos responder, se invierten (porque el send del initiator
    ///    es el recv del responder y viceversa)
    ///
    /// Parametros
    /// * `root_key` — 32 bytes: la clave raiz derivada del handshake
    ///   (session_key + shared_secret DH + transcript)
    /// * `our_secret` — nuestro secreto DH (LockedDhSecret, con mlocks)
    /// * `our_public` — nuestra clave publica DH (se envia al otro)
    /// * `their_public` — clave publica del otro (None = desconocemos)
    /// * `initiator` — true si nosotros iniciamos la conexion
    /// * `max_skip` — maximo de mensajes salteados permitidos (100 es tipico)
    pub fn new(
        root_key: &[u8; 32],
        our_secret: LockedDhSecret,
        our_public: PublicKey,
        their_public: Option<PublicKey>,
        initiator: bool,
        max_skip: usize,
    ) -> Self {
        let (send_chain, recv_chain) = if initiator {
            (
                hkdf_derive(root_key, b"sesame-send"),
                hkdf_derive(root_key, b"sesame-recv"),
            )
        } else {
            (
                hkdf_derive(root_key, b"sesame-recv"),
                hkdf_derive(root_key, b"sesame-send"),
            )
        };

        Self {
            root_chain: LockedKey::new(*root_key),
            send_chain: LockedKey::new(send_chain),
            recv_chain: LockedKey::new(recv_chain),
            our_secret: Some(our_secret),
            our_public,
            their_public,
            dh_counter: 0,
            msg_number_send: 0,
            msg_number_recv: 0,
            dh_epoch: 0,
            max_skip,
            skipped_keys: HashMap::new(),
            seen_messages: HashSet::new(),
        }
    }

    /// Cifra un mensaje usando el Double Ratchet.
    ///
    /// Que hace paso a paso
    /// 1. Verifica si toca hacer DH ratchet (cada DH_RATCHET_INTERVAL mensajes)
    /// 2. Si toca, genera nuevo par de claves DH y calcula nuevo secreto
    ///    compartido, derivando nuevas cadenas send/recv
    /// 3. Deriva una "message key" de la send_chain actual usando HKDF
    /// 4. Avanza la send_chain (SHA-256 de la actual)
    /// 5. Genera nonce aleatorio de 12 bytes
    /// 6. Cifra con ChaCha20-Poly1305 usando la message key
    /// 7. Arma el EncryptedFrame con todo (nonce, ciphertext, tag, etc.)
    ///
    /// Parametros
    /// * `plaintext` — los bytes a cifrar (ej: JSON serializado)
    /// * `aad_prefix` — datos asociados que se autentican pero NO se cifran
    ///   (AAD = Authenticated Associated Data). Incluye el transcript de
    ///   sesion + PeerIDs para prevenir ataques de "key confusion".
    ///
    /// Devuelve
    /// `EncryptedFrame` listo para serializar y enviar.
    pub fn encrypt(&mut self, plaintext: &[u8], aad_prefix: &[u8]) -> EncryptedFrame {
        let msg_number = self.msg_number_send;
        let dh_epoch = self.dh_epoch;
        let dh_public_key = if self.dh_counter % DH_RATCHET_INTERVAL == 0 {
            if let Some(their_pub) = self.their_public {
                let new_pub = self.dh_ratchet_send(their_pub);
                Some(new_pub)
            } else {
                None
            }
        } else {
            None
        };

        // Derivamos la message key de la send_chain y avanzamos la cadena
        let msg_key = hkdf_derive(self.send_chain.as_bytes(), b"sesame-msg");
        self.send_chain
            .replace(Sha256::digest(self.send_chain.as_bytes()).into());
        self.msg_number_send += 1;
        self.dh_counter += 1;

        // Nonce aleatorio + cifrado ChaCha20-Poly1305
        let nonce = crate::crypto::generate_random_bytes::<12>();
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&msg_key));
        let aad = frame_aad(aad_prefix, msg_number, dh_epoch, dh_public_key.is_some());

        let mut ciphertext = plaintext.to_vec();
        let tag = cipher
            .encrypt_in_place_detached(&Nonce::from_slice(&nonce), &aad, &mut ciphertext)
            .expect("ChaCha20Poly1305 encryption failed");

        EncryptedFrame {
            nonce,
            msg_number,
            dh_epoch,
            ciphertext,
            tag: tag.into(),
            dh_public_key,
        }
    }

    /// Descifra un mensaje recibido.
    ///
    /// Que hace paso a paso
    /// 1. Verifica que no sea replay o mensaje viejo (checkea seen_messages)
    /// 2. Si viene con nueva clave publica DH, ejecuta dh_ratchet_recv
    /// 3. Deriva la message key de la recv_chain (lado del receptor)
    /// 4. Avanza la recv_chain
    /// 5. Descifra y verifica con ChaCha20-Poly1305
    /// 6. Marca el mensaje como visto (para prevenir replay)
    ///
    /// Parametros
    /// * `frame` — el frame recibido (ReceivedFrame)
    /// * `aad_prefix` — mismo AAD que uso el que cifro (para verificar)
    ///
    /// Devuelve
    /// `Ok(Vec<u8>)` con el texto plano, o error si:
    /// - Replay attack (mismo dh_epoch + msg_number ya visto)
    /// - Mensaje muy futuro (salto muy grande en msg_number)
    /// - Falla de autenticacion Poly1305 (tampering o clave incorrecta)
    pub fn decrypt(
        &mut self,
        frame: &ReceivedFrame,
        aad_prefix: &[u8],
    ) -> Result<Vec<u8>, &'static str> {
        if frame.dh_epoch < self.dh_epoch
            || self
                .seen_messages
                .contains(&(frame.dh_epoch, frame.msg_number))
        {
            return Err("replay or stale message");
        }
        if frame.dh_epoch > self.dh_epoch + 1
            || frame.msg_number > self.msg_number_recv + self.max_skip as u64
        {
            return Err("message too far in the future");
        }

        if let Some(new_pub) = &frame.dh_public_key {
            self.dh_ratchet_recv(*new_pub);
        }

        let msg_key = hkdf_derive(self.recv_chain.as_bytes(), b"sesame-msg");
        self.recv_chain
            .replace(Sha256::digest(self.recv_chain.as_bytes()).into());
        self.msg_number_recv += 1;

        let cipher = ChaCha20Poly1305::new(Key::from_slice(&msg_key));
        let mut plaintext = frame.ciphertext.clone();
        let aad = frame_aad(
            aad_prefix,
            frame.msg_number,
            frame.dh_epoch,
            frame.dh_public_key.is_some(),
        );
        cipher
            .decrypt_in_place_detached(
                &Nonce::from_slice(&frame.nonce),
                &aad,
                &mut plaintext,
                &frame.tag.into(),
            )
            .map_err(|_| "decryption failed")?;

        self.seen_messages
            .insert((frame.dh_epoch, frame.msg_number));

        Ok(plaintext)
    }

    /// Ejecuta DH ratchet del lado del que ENVIA.
    ///
    /// Cuando se llama
    /// Cada DH_RATCHET_INTERVAL (3) mensajes enviados.
    ///
    /// Que hace
    /// 1. Genera NUEVO secreto DH efimero
    /// 2. Calcula secreto compartido con la clave publica del otro
    /// 3. Deriva nueva root_key de la anterior + shared_secret
    /// 4. Deriva nuevas cadenas send y recv de la nueva root_key
    ///    (NOTA: send y recv se intercambian porque ahora send usa la
    ///    clave del otro rol — es un detalle del protocolo)
    /// 5. Incrementa dh_epoch
    ///
    /// Devuelve
    /// La nueva clave publica (para enviarsela al otro peer en el frame).
    fn dh_ratchet_send(&mut self, their_public: PublicKey) -> PublicKey {
        let new_secret = LockedDhSecret::generate();
        let new_public = new_secret.public_key();
        let shared = new_secret.diffie_hellman(&their_public);
        let shared_bytes = shared.as_bytes();

        let mut new_root = [0u8; 32];
        crate::crypto::hkdf_expand_with_salt(
            self.root_chain.as_bytes(),
            shared_bytes,
            b"sesame-dh-ratchet",
            &mut new_root,
        );

        let new_send = hkdf_derive(&new_root, b"sesame-recv");
        let new_recv = hkdf_derive(&new_root, b"sesame-send");
        self.send_chain.replace(new_send);
        self.recv_chain.replace(new_recv);
        self.root_chain.replace(new_root);
        new_root.zeroize();
        self.dh_epoch += 1;

        self.our_secret = Some(new_secret);

        new_public
    }

    /// Ejecuta DH ratchet del lado del que RECIBE.
    ///
    /// Diferencia con dh_ratchet_send: el receptor usa el secreto
    /// ANTERIOR (el que tenia antes de que el otro generara uno nuevo)
    /// para calcular el shared_secret. Luego tambien genera un nuevo
    /// par propio, de forma que ambos peers tienen claves frescas.
    ///
    /// Cuando se llama
    /// Cuando recibimos un frame que incluye dh_public_key (indicando
    /// que el emisor hizo DH ratchet).
    fn dh_ratchet_recv(&mut self, their_new_public: PublicKey) {
        let old_secret = self.our_secret.take().expect("no DH secret available");
        let shared = old_secret.diffie_hellman(&their_new_public);
        let shared_bytes = shared.as_bytes();

        let mut new_root = [0u8; 32];
        crate::crypto::hkdf_expand_with_salt(
            self.root_chain.as_bytes(),
            shared_bytes,
            b"sesame-dh-ratchet",
            &mut new_root,
        );

        let new_send = hkdf_derive(&new_root, b"sesame-send");
        let new_recv = hkdf_derive(&new_root, b"sesame-recv");
        self.send_chain.replace(new_send);
        self.recv_chain.replace(new_recv);
        self.root_chain.replace(new_root);
        new_root.zeroize();
        self.their_public = Some(their_new_public);
        self.dh_counter = 0;
        self.dh_epoch += 1;

        // Generamos nuevo par propio para el proximo ratchet
        let new_secret = LockedDhSecret::generate();
        let new_public = new_secret.public_key();
        self.our_secret = Some(new_secret);
        self.our_public = new_public;
    }
}

impl Drop for DoubleRatchet {
    /// Al destruir el ratchet, limpia todas las claves salteadas.
    fn drop(&mut self) {
        for (_, key) in self.skipped_keys.iter_mut() {
            key.zeroize();
        }
    }
}

/// Construye los datos AAD (Authenticated Associated Data) para ChaCha20-Poly1305.
///
/// AAD son bytes que se autentican (se incluyen en el tag Poly1305) pero
/// NO se cifran. Esto previene que un atacante modifique los metadatos
/// del frame sin ser detectado.
///
/// Que incluye
/// - `prefix`: datos contextuales (transcript de sesion + PeerIDs)
/// - `msg_number`: numero de mensaje (evita reordenamiento malicioso)
/// - `dh_epoch`: epoch del ratchet
/// - `has_dh_pub`: 1 byte flag si este frame incluye clave publica DH
///
/// Por que es necesario
/// Si un atacante intercepta el frame y cambia msg_number o dh_epoch,
/// la verificacion Poly1305 falla y el mensaje se rechaza. Sin AAD,
/// el atacante podria modificar los metadatos sin ser detectado.
fn frame_aad(prefix: &[u8], msg_number: u64, dh_epoch: u64, has_dh_pub: bool) -> Vec<u8> {
    let mut aad = Vec::with_capacity(prefix.len() + 17);
    aad.extend_from_slice(prefix);
    aad.extend_from_slice(&msg_number.to_be_bytes());
    aad.extend_from_slice(&dh_epoch.to_be_bytes());
    aad.push(u8::from(has_dh_pub));
    aad
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Crea un par de ratchets (Alice y Bob) con la misma root key
    /// y claves DH complementarias, para usar en tests.
    fn ratchet_pair() -> (DoubleRatchet, DoubleRatchet) {
        let root = [7u8; 32];
        let a_secret = LockedDhSecret::generate();
        let a_public = a_secret.public_key();
        let b_secret = LockedDhSecret::generate();
        let b_public = b_secret.public_key();
        (
            DoubleRatchet::new(&root, a_secret, a_public, Some(b_public), true, 100),
            DoubleRatchet::new(&root, b_secret, b_public, Some(a_public), false, 100),
        )
    }

    /// Verifica que descifrar con un AAD diferente al que se uso para
    /// cifrar da error (Poly1305 detecta la modificacion).
    #[test]
    fn decrypt_rejects_wrong_aad() {
        let (mut sender, mut receiver) = ratchet_pair();
        let frame = sender.encrypt(b"hello", b"aad-a");

        assert!(
            receiver
                .decrypt(
                    &ReceivedFrame {
                        nonce: frame.nonce,
                        msg_number: frame.msg_number,
                        dh_epoch: frame.dh_epoch,
                        ciphertext: frame.ciphertext,
                        tag: frame.tag,
                        dh_public_key: frame.dh_public_key,
                    },
                    b"aad-b"
                )
                .is_err()
        );
    }

    /// Verifica que el mismo mensaje no se puede descifrar dos veces
    /// (proteccion contra replay attacks).
    #[test]
    fn decrypt_rejects_replay() {
        let (mut sender, mut receiver) = ratchet_pair();
        let frame = sender.encrypt(b"hello", b"aad");
        let received = ReceivedFrame {
            nonce: frame.nonce,
            msg_number: frame.msg_number,
            dh_epoch: frame.dh_epoch,
            ciphertext: frame.ciphertext.clone(),
            tag: frame.tag,
            dh_public_key: frame.dh_public_key,
        };

        // Primera vez: ok
        assert_eq!(receiver.decrypt(&received, b"aad").unwrap(), b"hello");
        // Segunda vez: debe fallar (replay detected)
        assert!(receiver.decrypt(&received, b"aad").is_err());
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    fn ratchet_pair() -> (DoubleRatchet, DoubleRatchet) {
        let root = [7u8; 32];
        let a_secret = LockedDhSecret::generate();
        let a_public = a_secret.public_key();
        let b_secret = LockedDhSecret::generate();
        let b_public = b_secret.public_key();
        (
            DoubleRatchet::new(&root, a_secret, a_public, Some(b_public), true, 100),
            DoubleRatchet::new(&root, b_secret, b_public, Some(a_public), false, 100),
        )
    }

    proptest! {
        #[test]
        fn decrypt_rejects_modified_ciphertext(payload in proptest::collection::vec(any::<u8>(), 1..10000)) {
            let (mut sender, mut receiver) = ratchet_pair();
            let mut frame = sender.encrypt(&payload, b"aad");
            frame.ciphertext[0] ^= 1;

            let received = ReceivedFrame {
                nonce: frame.nonce,
                msg_number: frame.msg_number,
                dh_epoch: frame.dh_epoch,
                ciphertext: frame.ciphertext,
                tag: frame.tag,
                dh_public_key: frame.dh_public_key,
            };

            prop_assert!(receiver.decrypt(&received, b"aad").is_err());
        }
    }
}
