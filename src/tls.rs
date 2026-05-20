use std::sync::Arc;

use rcgen::{CertificateParams, KeyPair, PKCS_ED25519};
use rustls::client::danger::ServerCertVerifier;
use rustls::crypto::ring;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::client::danger::HandshakeSignatureValid;
use rustls::{
    ClientConfig, DigitallySignedStruct, DistinguishedName, Error, ServerConfig, SignatureScheme,
};

use crate::types::PeerId;

#[derive(Debug)]
struct AcceptAllClientVerifier;

impl ClientCertVerifier for AcceptAllClientVerifier {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        false
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, Error> {
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519, SignatureScheme::ECDSA_NISTP256_SHA256]
    }
}

#[derive(Debug)]
struct AcceptAllServerVerifier;

impl ServerCertVerifier for AcceptAllServerVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519, SignatureScheme::ECDSA_NISTP256_SHA256]
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
