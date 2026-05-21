use std::sync::Arc;

use rcgen::{CertificateParams, KeyPair, PKCS_ED25519};
use rustls::client::danger::ServerCertVerifier;
use rustls::crypto::{ring, WebPkiSupportedAlgorithms};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::client::danger::HandshakeSignatureValid;
use rustls::{
    ClientConfig, DigitallySignedStruct, DistinguishedName, Error, ServerConfig, SignatureScheme,
};

use crate::types::PeerId;

#[derive(Debug)]
struct AcceptAllClientVerifier;

fn signature_algorithms() -> WebPkiSupportedAlgorithms {
    ring::default_provider().signature_verification_algorithms
}

impl ClientCertVerifier for AcceptAllClientVerifier {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        true
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

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

pub fn generate_cert() -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), Box<dyn std::error::Error>> {
    let key_pair = KeyPair::generate_for(&PKCS_ED25519)?;
    let params = CertificateParams::new(vec!["sesame.local".to_string()])?;
    let cert = params.self_signed(&key_pair)?;
    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::try_from(key_pair.serialize_der().to_vec())?;
    Ok((vec![cert_der], key_der))
}

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

pub fn get_peer_id(stream: &tokio_rustls::TlsStream<tokio::net::TcpStream>) -> Option<PeerId> {
    let (_, conn) = stream.get_ref();
    let certs = conn.peer_certificates()?;
    let cert = certs.first()?;
    Some(PeerId::from_cert_der(cert.as_ref()))
}

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
