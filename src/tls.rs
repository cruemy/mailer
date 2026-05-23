use std::sync::Arc;

use rcgen::{CertificateParams, KeyPair, PKCS_ED25519};
use rustls::client::danger::HandshakeSignatureValid;
use rustls::client::danger::ServerCertVerifier;
use rustls::crypto::{WebPkiSupportedAlgorithms, ring};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{
    ClientConfig, DigitallySignedStruct, DistinguishedName, Error, ServerConfig, SignatureScheme,
};

use crate::types::PeerId;

// ═══════════════════════════════════════════════════════════════════════════
// CONFIGURACION TLS 1.3 CON CERTIFICADOS AUTOFIRMADOS
// ═══════════════════════════════════════════════════════════════════════════
// Usamos TLS 1.3 con autenticacion mutua (mTLS) para el transporte
// cifrado entre peers. Cada vez que arranca el programa, genera un
// par de claves Ed25519 nuevo y un certificado autofirmado.
//
// Como no tenemos una CA (Certificate Authority), aceptamos cualquier
// certificado que el otro peer presente. La seguridad real viene de
// SPAKE2 + Double Ratchet, no de la validacion de certificados TLS.
// ═══════════════════════════════════════════════════════════════════════════

/// Verificador de certificados de cliente que acepta TODO.
///
/// En TLS normal, el servidor verifica que el certificado del cliente
/// este firmado por una CA de confianza. Aca no nos importa porque
/// la autenticacion real la hace SPAKE2 (el PAKE con la frase).
///
/// Seguridad
/// Esto NO es inseguro porque:
/// 1. El handshake SPAKE2 verifica que el peer conoce la frase
/// 2. El TLS exporter se usa en la derivacion de claves -> si un
///    atacante esta en medio (MITM), no tiene acceso al TLS exporter
///    real y la sesion falla
/// 3. Los certificados son efimeros (se regeneran cada ejecucion)
#[derive(Debug)]
struct AcceptAllClientVerifier;

fn signature_algorithms() -> WebPkiSupportedAlgorithms {
    ring::default_provider().signature_verification_algorithms
}

impl ClientCertVerifier for AcceptAllClientVerifier {
    /// Ofrecemos autenticacion de cliente (si, mandame tu certificado)
    fn offer_client_auth(&self) -> bool {
        true
    }

    /// Es OBLIGATORIO que el cliente mande un certificado
    fn client_auth_mandatory(&self) -> bool {
        true
    }

    /// No tenemos hints de CAs raiz (porque no usamos CA)
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    /// Aceptamos cualquier certificado que no este vacio
    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, Error> {
        if end_entity.is_empty() {
            return Err(Error::General("empty client certificate".into()));
        }
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &signature_algorithms())
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &signature_algorithms())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        signature_algorithms().supported_schemes()
    }
}

/// Verificador de certificados de servidor que acepta TODO.
///
/// Misma logica que AcceptAllClientVerifier pero del lado del cliente.
/// En TLS normal el cliente verifica que el certificado del servidor
/// coincida con el hostname al que se conecta. Aca no nos importa.
#[derive(Debug)]
struct AcceptAllServerVerifier;

impl ServerCertVerifier for AcceptAllServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, Error> {
        if end_entity.is_empty() {
            return Err(Error::General("empty server certificate".into()));
        }
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &signature_algorithms())
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &signature_algorithms())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        signature_algorithms().supported_schemes()
    }

    fn requires_raw_public_keys(&self) -> bool {
        false
    }
}

/// Genera un par clave-certificado Ed25519 autofirmado.
///
/// Que produce
/// - Un `CertificateDer` con el certificado en formato DER
/// - Una `PrivateKeyDer` con la clave privada
///
/// Por que Ed25519 y no RSA o ECDSA
/// - Ed25519 es mas rapido que RSA
/// - Las claves son mas chicas (32 bytes vs 256+ bytes)
/// - Es resistente a ataques de canal lateral
/// - Es el estandar moderno para firmas digitales
///
/// Por que nuevo cada ejecucion
/// Para que el PeerId cambie cada vez. Esto es deliberado:
/// si regeneras tu identidad (con F12), los peers anteriores no
/// pueden rastrearte. Es una propiedad de privacidad/fisica.
pub fn generate_cert()
-> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), Box<dyn std::error::Error>> {
    let key_pair = KeyPair::generate_for(&PKCS_ED25519)?;
    let params = CertificateParams::new(vec!["sesame.local".to_string()])?;
    let cert = params.self_signed(&key_pair)?;
    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::try_from(key_pair.serialize_der().to_vec())?;
    Ok((vec![cert_der], key_der))
}

/// Crea la configuracion TLS para el SERVIDOR (el que escucha conexiones).
///
/// Que incluye
/// - Provider criptografico ring (implementacion Rust de TLS)
/// - Solo TLS 1.3 (nada de 1.2 o inferior)
/// - Client cert verification con AcceptAllClientVerifier
/// - El certificado y clave generados
///
/// Parametros
/// * `certs` — vector con el certificado propio (generado por generate_cert)
/// * `key` — la clave privada correspondiente
pub fn make_server_config(
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<Arc<ServerConfig>, Box<dyn std::error::Error>> {
    let provider = Arc::new(ring::default_provider());

    let config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_client_cert_verifier(Arc::new(AcceptAllClientVerifier))
        .with_single_cert(certs, key)?;

    Ok(Arc::new(config))
}

/// Crea la configuracion TLS para el CLIENTE (el que conecta).
///
/// Diferencia con ServerConfig
/// El cliente necesita ServerCertVerifier en vez de ClientCertVerifier.
/// Usamos `.dangerous()` porque el verifier "acepta todo" no es
/// considerado seguro por rustls (`dangerous` es solo un nombre).
///
/// Parametros
/// * `certs` — certificado propio
/// * `key` — clave privada correspondiente
pub fn make_client_config(
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<Arc<ClientConfig>, Box<dyn std::error::Error>> {
    let provider = Arc::new(ring::default_provider());

    let config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAllServerVerifier))
        .with_client_auth_cert(certs, key)?;

    Ok(Arc::new(config))
}

/// Extrae el PeerId del certificado del peer desde un stream TLS.
///
/// Como funciona
/// 1. Obtiene `peer_certificates()` de la conexion rustls
/// 2. Toma el primer certificado de la cadena (end-entity)
/// 3. Calcula SHA-256 del DER -> PeerId
///
/// Devuelve
/// `Some(PeerId)` si hay certificado, `None` si no (no deberia pasar
/// porque la autenticacion de cliente es mandatory).
pub fn get_peer_id(stream: &tokio_rustls::TlsStream<tokio::net::TcpStream>) -> Option<PeerId> {
    let (_, conn) = stream.get_ref();
    let certs = conn.peer_certificates()?;
    let cert = certs.first()?;
    Some(PeerId::from_cert_der(cert.as_ref()))
}

/// Exporta material clave unico de la sesion TLS ("keying material export").
///
/// Que es esto
/// TLS 1.3 permite exportar bytes derivados de las claves de sesion.
/// Es un mecanismo estandar (RFC 5705) para que aplicaciones arriba
/// de TLS puedan "anclar" su seguridad a la sesion TLS.
///
/// Por que lo necesitamos
/// Para prevenir ataques MITM (Man In The Middle). Incluso si un
/// atacante intercepta la conexion TCP y hace su propio TLS con
/// cada lado, NO va a tener el mismo TLS exporter porque las claves
/// TLS son diferentes en cada pata del MITM.
///
/// Al mezclar este exporter en la session_key del PAKE, si hay un
/// MITM, las session_keys seran diferentes y la autenticacion falla.
///
/// Parametros
/// * `stream` — el stream TLS (puede ser Client o Server)
///
/// Devuelve
/// 32 bytes del export, o `rustls::Error` si falla.
pub fn export_transcript_key(
    stream: &tokio_rustls::TlsStream<tokio::net::TcpStream>,
) -> Result<[u8; 32], rustls::Error> {
    let mut output = [0u8; 32];
    match stream {
        tokio_rustls::TlsStream::Client(s) => {
            let (_, conn) = s.get_ref();
            conn.export_keying_material(&mut output, b"sesame transcript v1", None)?;
        }
        tokio_rustls::TlsStream::Server(s) => {
            let (_, conn) = s.get_ref();
            conn.export_keying_material(&mut output, b"sesame transcript v1", None)?;
        }
    }
    Ok(output)
}
