//! TLS configuration and types
//!
#[cfg(feature = "rustls")]
pub mod rustls;
use std::ops::Deref;
use tokio::io::{AsyncRead, AsyncWrite};
use crate::Socket;
#[cfg(feature = "rustls")]
use std::io::{BufRead, BufReader};
/// Trait for custom TLS connector implementations.
///
/// This trait allows users to implement their own TLS handshake logic when the `tls` feature
/// is enabled. Both rustls and custom TLS implementations use this unified interface.
///
/// # Example
///
/// ```ignore
/// use slinger::connector::CustomTlsConnector;
/// use slinger::Socket;
/// use tokio::net::TcpStream;
///
/// struct MyTlsConnector;
///
/// impl CustomTlsConnector for MyTlsConnector {
///     fn connect<'a>(
///         &'a self,
///         domain: &'a str,
///         stream: Socket,
///     ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Socket>> + Send + 'a>> {
///         Box::pin(async move {
///             // Implement your custom TLS handshake here
///             // You can use openssl, boringssl, or any other TLS library
///             todo!("Implement custom TLS handshake")
///         })
///     }
/// }
/// ```
pub trait CustomTlsConnector: Send + Sync + 'static {
  /// Perform TLS handshake on the given TCP stream.
  ///
  /// # Arguments
  ///
  /// * `domain` - The domain name for SNI (Server Name Indication)
  /// * `stream` - The TCP socket to upgrade to TLS
  ///
  /// # Returns
  ///
  /// Returns a `Socket` wrapping the TLS stream on success.
  fn connect<'a>(
    &'a self,
    domain: &'a str,
    stream: Socket,
  ) -> std::pin::Pin<Box<dyn std::future::Future<Output =crate::Result<Socket>> + Send + 'a>>;
}

/// Macro to implement AsyncRead and AsyncWrite by delegating to an inner TlsStreamWrapper field
///
/// This macro reduces boilerplate when creating custom TLS stream wrappers.
/// It generates AsyncRead and AsyncWrite implementations that delegate to a field
/// containing a TlsStreamWrapper.
///
/// # Usage
///
/// ```ignore
/// struct MyTlsStream {
///   inner: TlsStreamWrapper<SomeTlsStream>,
/// }
///
/// slinger::impl_tls_stream!(MyTlsStream, inner);
/// ```
///
/// The first argument is the type name, and the second is the field name containing
/// the TlsStreamWrapper.
#[macro_export]
macro_rules! impl_tls_stream {
  ($type:ty, $field:ident) => {
    impl tokio::io::AsyncRead for $type {
      fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
      ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.$field).poll_read(cx, buf)
      }
    }

    impl tokio::io::AsyncWrite for $type {
      fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
      ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.$field).poll_write(cx, buf)
      }

      fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
      ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.$field).poll_flush(cx)
      }

      fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
      ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.$field).poll_shutdown(cx)
      }
    }
  };
}
/// Trait for custom TLS stream implementations
pub trait CustomTlsStream: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static {
  /// Get the peer certificate from the TLS connection, if available
  fn peer_certificate(&self) -> Option<Vec<PeerCertificate>> {
    None
  }
  /// Get the alpn_protocol
  fn alpn_protocol(&self) -> Option<Vec<u8>> {
    None
  }
}
/// peer certificate
#[derive(Clone, Debug)]
pub struct PeerCertificate {
  /// The DER-encoded certificate data
  pub inner: Vec<u8>,
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
/// Cert
#[derive(Clone, Debug)]
pub enum Cert {
  /// Der
  Der(Vec<u8>),
  /// Pem
  Pem(Vec<u8>),
}
impl Cert {
  /// Returns the DER-encoded bytes if this is a DER certificate.
  pub fn as_der(&self) -> Option<&[u8]> {
    match self {
      Cert::Der(data) => Some(data),
      Cert::Pem(_) => None,
    }
  }

  /// Returns the PEM-encoded bytes if this is a PEM certificate.
  pub fn as_pem(&self) -> Option<&[u8]> {
    match self {
      Cert::Pem(data) => Some(data),
      Cert::Der(_) => None,
    }
  }

  /// Returns the raw bytes regardless of format.
  pub fn to_bytes(&self) -> Vec<u8> {
    match self {
      Cert::Der(data) | Cert::Pem(data) => data.clone(),
    }
  }
}
impl Certificate {
  /// Returns the inner certificate representation.
  pub fn original(&self) -> &Cert {
    &self.original
  }
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
  /// let cert = slinger::tls::Certificate::from_der(&buf)?;
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
  /// let cert = slinger::tls::Certificate::from_pem(&buf)?;
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
  /// let certs = slinger::tls::Certificate::from_pem_bundle(&buf)?;
  /// # drop(certs);
  /// # Ok(())
  /// # }
  /// ```
  pub fn from_pem_bundle(pem_bundle: &[u8]) -> crate::Result<Vec<Certificate>> {
    #[cfg(feature = "rustls")]
    {
      let mut reader = BufReader::new(pem_bundle);
      Self::read_pem_certs(&mut reader)?
        .iter()
        .map(|cert_vec| Certificate::from_der(cert_vec))
        .collect::<crate::Result<Vec<Certificate>>>()
    }
    #[cfg(not(feature = "rustls"))]
    {
      // Without rustls backend, just store as PEM
      Ok(vec![Certificate::from_pem(pem_bundle)?])
    }
  }

  #[cfg(feature = "rustls")]
  pub(crate) fn add_to_tls(self, root_cert_store: &mut tokio_rustls::rustls::RootCertStore) -> crate::Result<()> {
    match self.original {
      Cert::Der(buf) => root_cert_store
        .add(buf.into())
        .map_err(crate::errors::builder)?,
      Cert::Pem(buf) => {
        use std::io::Cursor;
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

  #[cfg(feature = "rustls")]
  fn read_pem_certs(reader: &mut impl BufRead) -> crate::Result<Vec<Vec<u8>>> {
    rustls_pemfile::certs(reader)
      .map(|result| match result {
        Ok(cert) => Ok(cert.as_ref().to_vec()),
        Err(_) => Err(crate::errors::builder("invalid certificate encoding")),
      })
      .collect()
  }
}
#[allow(dead_code)]
/// Represents a private key and X509 cert as a client certificate.
#[derive(Clone)]
pub struct Identity {
  inner: ClientCert,
}
enum ClientCert {
  #[cfg(feature = "rustls")]
  RustlsPem {
    key: rustls_pki_types::PrivateKeyDer<'static>,
    certs: Vec<rustls_pki_types::CertificateDer<'static>>,
  },
  #[cfg(not(feature = "rustls"))]
  CustomPem { pem_data: Vec<u8> },
}
impl Clone for ClientCert {
  fn clone(&self) -> Self {
    match self {
      #[cfg(feature = "rustls")]
      ClientCert::RustlsPem { key, certs } => ClientCert::RustlsPem {
        key: key.clone_key(),
        certs: certs.clone(),
      },
      #[cfg(not(feature = "rustls"))]
      ClientCert::CustomPem { pem_data } => ClientCert::CustomPem {
        pem_data: pem_data.clone(),
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
  /// This requires the `tls` Cargo feature enabled.
  ///
  pub fn from_pem(buf: &[u8]) -> crate::Result<Identity> {
    #[cfg(feature = "rustls")]
    {
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
              return Err(crate::errors::builder(tokio_rustls::rustls::Error::General(String::from(
                "No valid certificate was found",
              ))))
            }
            Err(_) => {
              return Err(crate::errors::builder(tokio_rustls::rustls::Error::General(String::from(
                "Invalid identity PEM file",
              ))))
            }
          }
        }
        if let (Some(sk), false) = (sk.pop(), certs.is_empty()) {
          (sk, certs)
        } else {
          return Err(crate::errors::builder(tokio_rustls::rustls::Error::General(String::from(
            "private key or certificate not found",
          ))));
        }
      };
      Ok(Identity {
        inner: ClientCert::RustlsPem { key, certs },
      })
    }
    #[cfg(not(feature = "rustls"))]
    {
      // For custom TLS backend, store the PEM data
      return Ok(Identity {
        inner: ClientCert::CustomPem {
          pem_data: buf.to_vec(),
        },
      });
    }
  }

  #[cfg(feature = "rustls")]
  pub(crate) fn add_to_tls(
    self,
    config_builder: tokio_rustls::rustls::ConfigBuilder<tokio_rustls::rustls::ClientConfig, tokio_rustls::rustls::client::WantsClientCert>,
  ) -> crate::Result<tokio_rustls::rustls::ClientConfig> {
    let ClientCert::RustlsPem { key, certs } = self.inner;
    config_builder
      .with_client_auth_cert(certs, key)
      .map_err(crate::errors::builder)
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
}
