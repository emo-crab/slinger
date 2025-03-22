//! TLS configuration and types
//!
use std::io::{BufRead, BufReader};
use std::ops::Deref;
use tokio_rustls::rustls;
use tokio_rustls::rustls::crypto::WebPkiSupportedAlgorithms;
use tokio_rustls::rustls::pki_types::{ServerName, UnixTime};
use tokio_rustls::rustls::server::ParsedCertificate;
use tokio_rustls::rustls::{
  client::danger::HandshakeSignatureValid, client::danger::ServerCertVerified,
  client::danger::ServerCertVerifier, DigitallySignedStruct, Error as TLSError, RootCertStore,
  SignatureScheme,
};
/// peer certificate
#[derive(Clone, Debug)]
pub struct PeerCertificate {
  pub(crate) inner: Vec<u8>,
}

impl Deref for PeerCertificate {
  type Target = Vec<u8>;

  fn deref(&self) -> &Self::Target {
    &self.inner
  }
}
/// Represents a server X509 certificate.
#[derive(Clone, Debug)]
pub struct Certificate {
  original: Cert,
}
#[derive(Clone, Debug)]
enum Cert {
  Der(Vec<u8>),
  Pem(Vec<u8>),
}
impl Certificate {
  /// Create a `Certificate` from a binary DER encoded certificate
  ///
  /// # Examples
  ///
  /// ```
  /// # use std::fs::File;
  /// # use std::io::Read;
  /// # fn cert() -> Result<(), Box<dyn std::error::Error>> {
  /// let mut buf = Vec::new();
  /// File::open("my_cert.der")?
  ///     .read_to_end(&mut buf)?;
  /// let cert = slinger::Certificate::from_der(&buf)?;
  /// # drop(cert);
  /// # Ok(())
  /// # }
  /// ```
  pub fn from_der(der: &[u8]) -> crate::Result<Certificate> {
    Ok(Certificate {
      original: Cert::Der(der.to_owned()),
    })
  }

  /// Create a `Certificate` from a PEM encoded certificate
  ///
  /// # Examples
  ///
  /// ```
  /// # use std::fs::File;
  /// # use std::io::Read;
  /// # fn cert() -> Result<(), Box<dyn std::error::Error>> {
  /// let mut buf = Vec::new();
  /// File::open("my_cert.pem")?
  ///     .read_to_end(&mut buf)?;
  /// let cert = slinger::Certificate::from_pem(&buf)?;
  /// # drop(cert);
  /// # Ok(())
  /// # }
  /// ```
  pub fn from_pem(pem: &[u8]) -> crate::Result<Certificate> {
    Ok(Certificate {
      original: Cert::Pem(pem.to_owned()),
    })
  }

  /// Create a collection of `Certificate`s from a PEM encoded certificate bundle.
  /// Example byte sources may be `.crt`, `.cer` or `.pem` files.
  ///
  /// # Examples
  ///
  /// ```
  /// # use std::fs::File;
  /// # use std::io::Read;
  /// # fn cert() -> Result<(), Box<dyn std::error::Error>> {
  /// let mut buf = Vec::new();
  /// File::open("ca-bundle.crt")?
  ///     .read_to_end(&mut buf)?;
  /// let certs = slinger::Certificate::from_pem_bundle(&buf)?;
  /// # drop(certs);
  /// # Ok(())
  /// # }
  /// ```
  pub fn from_pem_bundle(pem_bundle: &[u8]) -> crate::Result<Vec<Certificate>> {
    let mut reader = BufReader::new(pem_bundle);

    Self::read_pem_certs(&mut reader)?
      .iter()
      .map(|cert_vec| Certificate::from_der(cert_vec))
      .collect::<crate::Result<Vec<Certificate>>>()
  }

  pub(crate) fn add_to_tls(self, root_cert_store: &mut RootCertStore) -> crate::Result<()> {
    use std::io::Cursor;

    match self.original {
      Cert::Der(buf) => root_cert_store
        .add(buf.into())
        .map_err(crate::errors::builder)?,
      Cert::Pem(buf) => {
        let mut reader = Cursor::new(buf);
        let certs = Self::read_pem_certs(&mut reader)?;
        for c in certs {
          root_cert_store
            .add(c.into())
            .map_err(crate::errors::builder)?;
        }
      }
    }
    Ok(())
  }

  fn read_pem_certs(reader: &mut impl BufRead) -> crate::Result<Vec<Vec<u8>>> {
    rustls_pemfile::certs(reader)
      .map(|result| match result {
        Ok(cert) => Ok(cert.as_ref().to_vec()),
        Err(_) => Err(crate::errors::builder("invalid certificate encoding")),
      })
      .collect()
  }
}
/// Represents a private key and X509 cert as a client certificate.
#[derive(Clone)]
pub struct Identity {
  inner: ClientCert,
}
enum ClientCert {
  Pem {
    key: rustls_pki_types::PrivateKeyDer<'static>,
    certs: Vec<rustls_pki_types::CertificateDer<'static>>,
  },
}
impl Clone for ClientCert {
  fn clone(&self) -> Self {
    match self {
      ClientCert::Pem { key, certs } => ClientCert::Pem {
        key: key.clone_key(),
        certs: certs.clone(),
      },
    }
  }
}
impl Identity {
  /// Parses PEM encoded private key and certificate.
  ///
  /// The input should contain a PEM encoded private key
  /// and at least one PEM encoded certificate.
  ///
  /// Note: The private key must be in RSA, SEC1 Elliptic Curve or PKCS#8 format.
  ///
  /// # Examples
  ///
  /// ```
  /// # use std::fs::File;
  /// # use std::io::Read;
  /// # fn pem() -> Result<(), Box<dyn std::error::Error>> {
  /// let mut buf = Vec::new();
  /// File::open("my-ident.pem")?
  ///     .read_to_end(&mut buf)?;
  /// let id = slinger::tls::Identity::from_pem(&buf)?;
  /// # drop(id);
  /// # Ok(())
  /// # }
  /// ```
  ///
  /// # Optional
  ///
  /// This requires the `rustls-tls(-...)` Cargo feature enabled.

  pub fn from_pem(buf: &[u8]) -> crate::Result<Identity> {
    use rustls_pemfile::Item;
    use std::io::Cursor;

    let (key, certs) = {
      let mut pem = Cursor::new(buf);
      let mut sk = Vec::<rustls_pki_types::PrivateKeyDer>::new();
      let mut certs = Vec::<rustls_pki_types::CertificateDer>::new();

      for result in rustls_pemfile::read_all(&mut pem) {
        match result {
          Ok(Item::X509Certificate(cert)) => certs.push(cert),
          Ok(Item::Pkcs1Key(key)) => sk.push(key.into()),
          Ok(Item::Pkcs8Key(key)) => sk.push(key.into()),
          Ok(Item::Sec1Key(key)) => sk.push(key.into()),
          Ok(_) => {
            return Err(crate::errors::builder(TLSError::General(String::from(
              "No valid certificate was found",
            ))))
          }
          Err(_) => {
            return Err(crate::errors::builder(TLSError::General(String::from(
              "Invalid identity PEM file",
            ))))
          }
        }
      }

      if let (Some(sk), false) = (sk.pop(), certs.is_empty()) {
        (sk, certs)
      } else {
        return Err(crate::errors::builder(TLSError::General(String::from(
          "private key or certificate not found",
        ))));
      }
    };

    Ok(Identity {
      inner: ClientCert::Pem { key, certs },
    })
  }

  pub(crate) fn add_to_tls(
    self,
    config_builder: rustls::ConfigBuilder<
      rustls::ClientConfig,
      // Not sure here
      rustls::client::WantsClientCert,
    >,
  ) -> crate::Result<rustls::ClientConfig> {
    match self.inner {
      ClientCert::Pem { key, certs } => config_builder
        .with_client_auth_cert(certs, key)
        .map_err(crate::errors::builder),
    }
  }
}
/// A TLS protocol version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Version(InnerVersion);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
enum InnerVersion {
  Tls1_0,
  Tls1_1,
  Tls1_2,
  Tls1_3,
}
impl Version {
  /// Version 1.0 of the TLS protocol.
  pub const TLS_1_0: Version = Version(InnerVersion::Tls1_0);
  /// Version 1.1 of the TLS protocol.
  pub const TLS_1_1: Version = Version(InnerVersion::Tls1_1);
  /// Version 1.2 of the TLS protocol.
  pub const TLS_1_2: Version = Version(InnerVersion::Tls1_2);
  /// Version 1.3 of the TLS protocol.
  pub const TLS_1_3: Version = Version(InnerVersion::Tls1_3);
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
  ) -> Result<ServerCertVerified, TLSError> {
    Ok(ServerCertVerified::assertion())
  }

  fn verify_tls12_signature(
    &self,
    _message: &[u8],
    _cert: &rustls_pki_types::CertificateDer,
    _dss: &DigitallySignedStruct,
  ) -> Result<HandshakeSignatureValid, TLSError> {
    Ok(HandshakeSignatureValid::assertion())
  }

  fn verify_tls13_signature(
    &self,
    _message: &[u8],
    _cert: &rustls_pki_types::CertificateDer,
    _dss: &DigitallySignedStruct,
  ) -> Result<HandshakeSignatureValid, TLSError> {
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
  ) -> Result<ServerCertVerified, TLSError> {
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
  ) -> Result<HandshakeSignatureValid, TLSError> {
    rustls::crypto::verify_tls12_signature(message, cert, dss, &self.signature_algorithms)
  }

  fn verify_tls13_signature(
    &self,
    message: &[u8],
    cert: &rustls_pki_types::CertificateDer<'_>,
    dss: &DigitallySignedStruct,
  ) -> Result<HandshakeSignatureValid, TLSError> {
    rustls::crypto::verify_tls13_signature(message, cert, dss, &self.signature_algorithms)
  }

  fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
    self.signature_algorithms.supported_schemes()
  }
}
