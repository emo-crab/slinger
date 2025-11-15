//! rustls backend
use crate::tls::{CustomTlsConnector, CustomTlsStream, InnerVersion, PeerCertificate, Version};
use crate::{impl_tls_stream, Socket, StreamWrapper};
use std::time::Duration;
use tokio_rustls::rustls::{
  self,
  client::danger::HandshakeSignatureValid,
  client::danger::ServerCertVerified,
  client::danger::ServerCertVerifier,
  crypto::WebPkiSupportedAlgorithms,
  pki_types::{ServerName, UnixTime},
  server::ParsedCertificate,
  DigitallySignedStruct, RootCertStore, SignatureScheme,
};

#[derive(Debug)]
pub(crate) struct NoVerifier;

impl ServerCertVerifier for NoVerifier {
  fn verify_server_cert(
    &self,
    _end_entity: &rustls_pki_types::CertificateDer,
    _intermediates: &[rustls_pki_types::CertificateDer],
    _server_name: &ServerName,
    _ocsp_response: &[u8],
    _now: UnixTime,
  ) -> Result<ServerCertVerified, tokio_rustls::rustls::Error> {
    Ok(ServerCertVerified::assertion())
  }

  fn verify_tls12_signature(
    &self,
    _message: &[u8],
    _cert: &rustls_pki_types::CertificateDer,
    _dss: &DigitallySignedStruct,
  ) -> Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
    Ok(HandshakeSignatureValid::assertion())
  }

  fn verify_tls13_signature(
    &self,
    _message: &[u8],
    _cert: &rustls_pki_types::CertificateDer,
    _dss: &DigitallySignedStruct,
  ) -> Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
    Ok(HandshakeSignatureValid::assertion())
  }

  fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
    vec![
      SignatureScheme::RSA_PKCS1_SHA1,
      SignatureScheme::ECDSA_SHA1_Legacy,
      SignatureScheme::RSA_PKCS1_SHA256,
      SignatureScheme::ECDSA_NISTP256_SHA256,
      SignatureScheme::RSA_PKCS1_SHA384,
      SignatureScheme::ECDSA_NISTP384_SHA384,
      SignatureScheme::RSA_PKCS1_SHA512,
      SignatureScheme::ECDSA_NISTP521_SHA512,
      SignatureScheme::RSA_PSS_SHA256,
      SignatureScheme::RSA_PSS_SHA384,
      SignatureScheme::RSA_PSS_SHA512,
      SignatureScheme::ED25519,
      SignatureScheme::ED448,
    ]
  }
}

#[derive(Debug)]
pub(crate) struct IgnoreHostname {
  roots: RootCertStore,
  signature_algorithms: WebPkiSupportedAlgorithms,
}

impl IgnoreHostname {
  pub(crate) fn new(roots: RootCertStore, signature_algorithms: WebPkiSupportedAlgorithms) -> Self {
    Self {
      roots,
      signature_algorithms,
    }
  }
}

impl ServerCertVerifier for IgnoreHostname {
  fn verify_server_cert(
    &self,
    end_entity: &rustls_pki_types::CertificateDer<'_>,
    intermediates: &[rustls_pki_types::CertificateDer<'_>],
    _server_name: &ServerName<'_>,
    _ocsp_response: &[u8],
    now: UnixTime,
  ) -> Result<ServerCertVerified, tokio_rustls::rustls::Error> {
    let cert = ParsedCertificate::try_from(end_entity)?;

    rustls::client::verify_server_cert_signed_by_trust_anchor(
      &cert,
      &self.roots,
      intermediates,
      now,
      self.signature_algorithms.all,
    )?;
    Ok(ServerCertVerified::assertion())
  }

  fn verify_tls12_signature(
    &self,
    message: &[u8],
    cert: &rustls_pki_types::CertificateDer<'_>,
    dss: &DigitallySignedStruct,
  ) -> Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
    rustls::crypto::verify_tls12_signature(message, cert, dss, &self.signature_algorithms)
  }

  fn verify_tls13_signature(
    &self,
    message: &[u8],
    cert: &rustls_pki_types::CertificateDer<'_>,
    dss: &DigitallySignedStruct,
  ) -> Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
    rustls::crypto::verify_tls13_signature(message, cert, dss, &self.signature_algorithms)
  }

  fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
    self.signature_algorithms.supported_schemes()
  }
}

/// enable rustls feature
pub struct RustTlsStream {
  inner: tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
}
impl_tls_stream!(RustTlsStream, inner);

/// Default rustls implementation of CustomTlsConnector
/// This struct wraps tokio_rustls::TlsConnector and implements the CustomTlsConnector trait,
/// providing a unified interface for TLS connections when the rustls feature is enabled.
pub struct RustlsTlsConnector {
  connector: tokio_rustls::TlsConnector,
  connect_timeout: Option<Duration>,
}

impl CustomTlsStream for RustTlsStream {
  fn peer_certificate(&self) -> Option<Vec<PeerCertificate>> {
    self.inner.get_ref().1.peer_certificates().map(|certs| {
      certs
        .iter()
        .map(|cert| PeerCertificate {
          inner: cert.to_vec(),
        })
        .collect()
    })
  }
  fn alpn_protocol(&self) -> Option<Vec<u8>> {
    self.inner.get_ref().1.alpn_protocol().map(|p| p.to_vec())
  }
}

impl RustlsTlsConnector {
  /// Create a new RustlsTlsConnector
  pub fn new(connector: tokio_rustls::TlsConnector, connect_timeout: Option<Duration>) -> Self {
    Self {
      connector,
      connect_timeout,
    }
  }
}

impl CustomTlsConnector for RustlsTlsConnector {
  fn connect<'a>(
    &'a self,
    domain: &'a str,
    stream: Socket,
  ) -> std::pin::Pin<Box<dyn std::future::Future<Output = crate::Result<Socket>> + Send + 'a>> {
    Box::pin(async move {
      let domain = ServerName::try_from(domain.to_owned())
        .map_err(|e| crate::errors::Error::Other(e.to_string()))?;
      let connect_timeout = self.connect_timeout.unwrap_or(Duration::from_secs(30));
      match stream.inner {
        StreamWrapper::Tcp(t) => {
          let s = tokio::time::timeout(connect_timeout, self.connector.connect(domain, t))
            .await
            .map_err(|e| crate::errors::new_io_error(std::io::ErrorKind::TimedOut, &e.to_string()))?
            .map_err(|e| crate::errors::Error::Other(format!("rustls handshake failed: {}", e)))?;
          let rust_stream = RustTlsStream { inner: s };
          let tls = Socket::new(
            StreamWrapper::Custom(Box::new(rust_stream)),
            stream.read_timeout,
            stream.write_timeout,
          );
          Ok(tls)
        }
        StreamWrapper::Custom(t) => Ok(Socket::new(
          StreamWrapper::Custom(t),
          stream.read_timeout,
          stream.write_timeout,
        )),
      }
    })
  }
}
impl Version {
  pub(crate) fn from_tls(version: rustls::ProtocolVersion) -> Option<Self> {
    match version {
      rustls::ProtocolVersion::SSLv2 => None,
      rustls::ProtocolVersion::SSLv3 => None,
      rustls::ProtocolVersion::TLSv1_0 => Some(Self(InnerVersion::Tls1_0)),
      rustls::ProtocolVersion::TLSv1_1 => Some(Self(InnerVersion::Tls1_1)),
      rustls::ProtocolVersion::TLSv1_2 => Some(Self(InnerVersion::Tls1_2)),
      rustls::ProtocolVersion::TLSv1_3 => Some(Self(InnerVersion::Tls1_3)),
      _ => None,
    }
  }
}
