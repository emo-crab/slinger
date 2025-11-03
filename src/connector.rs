use crate::errors::Result;
use crate::proxy::{Proxy, ProxySocket};
use crate::socket::{MaybeTlsStream, Socket};
#[cfg(feature = "tls")]
use crate::tls::Identity;
#[cfg(feature = "rustls")]
use crate::tls::{IgnoreHostname, NoVerifier};
#[cfg(feature = "tls")]
use crate::{tls, Certificate};
use socket2::Socket as RawSocket;
use socket2::{Domain, Protocol, Type};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::TcpSocket;
#[cfg(feature = "rustls")]
use tokio_rustls::rustls;
#[cfg(feature = "rustls")]
use tokio_rustls::rustls::pki_types::ServerName;

/// TLS connector type enum to support rustls and custom connectors
#[cfg(feature = "tls")]
#[derive(Clone)]
pub enum TlsConnectorType {
  /// Rustls-based TLS connector
  #[cfg(feature = "rustls")]
  Rustls(tokio_rustls::TlsConnector),
  /// Custom TLS connector callback
  #[cfg(not(feature = "rustls"))]
  Custom(std::sync::Arc<dyn CustomTlsConnector>),
}

#[cfg(all(feature = "tls", not(feature = "rustls")))]
/// Trait for custom TLS connector implementations.
///
/// This trait allows users to implement their own TLS handshake logic when the `tls` feature
/// is enabled without the `rustls` backend.
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
  ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Socket>> + Send + 'a>>;
}

/// ConnectorBuilder
#[derive(Clone)]
pub struct ConnectorBuilder {
  #[cfg(feature = "http2")]
  http2: bool,
  hostname_verification: bool,
  certs_verification: bool,
  read_timeout: Option<Duration>,
  write_timeout: Option<Duration>,
  connect_timeout: Option<Duration>,
  #[cfg(feature = "tls")]
  min_tls_version: Option<tls::Version>,
  #[cfg(feature = "tls")]
  max_tls_version: Option<tls::Version>,
  nodelay: bool,
  keepalive: bool,
  #[cfg(feature = "tls")]
  tls_sni: bool,
  #[cfg(feature = "tls")]
  identity: Option<Identity>,
  #[cfg(feature = "tls")]
  certificate: Vec<Certificate>,
  proxy: Option<Proxy>,
  #[cfg(all(feature = "tls", not(feature = "rustls")))]
  custom_tls_connector: Option<std::sync::Arc<dyn CustomTlsConnector>>,
}

impl Default for ConnectorBuilder {
  fn default() -> Self {
    Self {
      #[cfg(feature = "http2")]
      http2: false,
      hostname_verification: true,
      certs_verification: true,
      read_timeout: Some(Duration::from_secs(30)),
      write_timeout: Some(Duration::from_secs(30)),
      connect_timeout: Some(Duration::from_secs(10)),
      #[cfg(feature = "tls")]
      min_tls_version: None,
      #[cfg(feature = "tls")]
      max_tls_version: None,
      nodelay: false,
      keepalive: false,
      #[cfg(feature = "tls")]
      tls_sni: true,
      #[cfg(feature = "tls")]
      identity: None,
      #[cfg(feature = "tls")]
      certificate: vec![],
      proxy: None,
      #[cfg(all(feature = "tls", not(feature = "rustls")))]
      custom_tls_connector: None,
    }
  }
}

impl ConnectorBuilder {
  #[cfg(feature = "http2")]
  /// Enable HTTP/2 support.
  pub fn enable_http2(mut self, http2: bool) -> Self {
    self.http2 = http2;
    self
  }
  /// Controls the use of hostname verification.
  ///
  /// Defaults to `false`.
  ///
  /// # Warning
  ///
  /// You should think very carefully before using this method. If invalid hostnames are trusted, *any* valid
  /// certificate for *any* site will be trusted for use. This introduces significant vulnerabilities, and should
  /// only be used as a last resort.
  pub fn hostname_verification(mut self, value: bool) -> ConnectorBuilder {
    self.hostname_verification = value;
    self
  }
  /// Controls the use of certificate validation.
  ///
  /// Defaults to `false`.
  ///
  /// # Warning
  ///
  /// You should think very carefully before using this method. If invalid certificates are trusted, *any*
  /// certificate for *any* site will be trusted for use. This includes expired certificates. This introduces
  /// significant vulnerabilities, and should only be used as a last resort.
  pub fn certs_verification(mut self, value: bool) -> ConnectorBuilder {
    self.certs_verification = value;
    self
  }
  /// Set that all sockets have `SO_NODELAY` set to the supplied value `nodelay`.
  ///
  /// Default is `false`.
  pub fn nodelay(mut self, value: bool) -> ConnectorBuilder {
    self.nodelay = value;
    self
  }
  /// Sets value for the `SO_KEEPALIVE` option on this socket.
  ///
  /// Default is `false`.
  pub fn keepalive(mut self, value: bool) -> ConnectorBuilder {
    self.keepalive = value;
    self
  }
  /// Controls the use of Server Name Indication (SNI).
  ///
  /// Defaults to `true`.
  #[cfg(feature = "tls")]
  pub fn tls_sni(mut self, value: bool) -> ConnectorBuilder {
    self.tls_sni = value;
    self
  }
  /// Adds a certificate to the set of roots that the connector will trust.
  #[cfg(feature = "tls")]
  pub fn certificate(mut self, value: Vec<Certificate>) -> ConnectorBuilder {
    self.certificate = value;
    self
  }
  /// Sets the identity to be used for client certificate authentication.
  #[cfg(feature = "tls")]
  pub fn identity(mut self, value: Identity) -> ConnectorBuilder {
    self.identity = Some(value);
    self
  }
  /// Enables a read timeout.
  ///
  /// The timeout applies to each read operation, and resets after a
  /// successful read. This is more appropriate for detecting stalled
  /// connections when the size isn't known beforehand.
  ///
  /// Default is 30 seconds.
  pub fn read_timeout(mut self, timeout: Option<Duration>) -> ConnectorBuilder {
    self.read_timeout = timeout;
    self
  }
  /// Enables a write timeout.
  ///
  /// The timeout applies to each read operation, and resets after a
  /// successful read. This is more appropriate for detecting stalled
  /// connections when the size isn't known beforehand.
  ///
  /// Default is 30 seconds.
  pub fn write_timeout(mut self, timeout: Option<Duration>) -> ConnectorBuilder {
    self.write_timeout = timeout;
    self
  }
  /// Set a timeout for only the connect phase of a `Client`.
  ///
  /// Default is 10 seconds.
  ///
  /// # Note
  ///
  /// This **requires** the futures be executed in a tokio runtime with
  /// a tokio timer enabled.
  pub fn connect_timeout(mut self, timeout: Option<Duration>) -> ConnectorBuilder {
    self.connect_timeout = timeout;
    self
  }
  // Proxy options

  /// Add a `Proxy` to the list of proxies the `Client` will use.
  ///
  /// # Note
  ///
  /// Adding a proxy will disable the automatic usage of the "system" proxy.
  pub fn proxy(mut self, addr: Option<Proxy>) -> ConnectorBuilder {
    self.proxy = addr;
    self
  }
  /// Set the minimum required TLS version for connections.
  ///
  /// By default, the `native_tls::Protocol` default is used.
  ///
  /// # Optional
  ///
  /// This requires the optional `tls` feature to be enabled.
  #[cfg(feature = "tls")]
  pub fn min_tls_version(mut self, version: Option<tls::Version>) -> ConnectorBuilder {
    self.min_tls_version = version;
    self
  }
  /// Set the maximum required TLS version for connections.
  ///
  /// By default, the `native_tls::Protocol` default is used.
  ///
  /// # Optional
  ///
  /// This requires the optional `tls` feature to be enabled.
  #[cfg(feature = "tls")]
  pub fn max_tls_version(mut self, version: Option<tls::Version>) -> ConnectorBuilder {
    self.max_tls_version = version;
    self
  }

  /// Set a custom TLS connector for custom TLS handshake implementations.
  ///
  /// This is only available when the `tls` feature is enabled without the
  /// `rustls` backend. It allows you to provide your own TLS
  /// implementation using libraries like openssl, boringssl, native-tls, or any other TLS library.
  ///
  /// # Example
  ///
  /// ```ignore
  /// use slinger::connector::{ConnectorBuilder, CustomTlsConnector};
  /// use slinger::{Result, Socket};
  /// use std::sync::Arc;
  ///
  /// struct MyTlsConnector;
  ///
  /// impl CustomTlsConnector for MyTlsConnector {
  ///     fn connect<'a>(
  ///         &'a self,
  ///         stream: Socket,
  ///         domain: &'a str,
  ///     ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Socket>> + Send + 'a>> {
  ///         Box::pin(async move {
  ///             // Your custom TLS handshake logic here
  ///             todo!()
  ///         })
  ///     }
  /// }
  ///
  /// let connector = ConnectorBuilder::default()
  ///     .custom_tls_connector(Arc::new(MyTlsConnector))
  ///     .build()?;
  /// ```
  #[cfg(all(feature = "tls", not(feature = "rustls")))]
  pub fn custom_tls_connector(
    mut self,
    connector: std::sync::Arc<dyn CustomTlsConnector>,
  ) -> ConnectorBuilder {
    self.custom_tls_connector = Some(connector);
    self
  }
}

impl ConnectorBuilder {
  #[cfg(feature = "rustls")]
  /// Use rustls only
  fn only_rustls(&self) -> Result<TlsConnectorType> {
    let mut root_cert_store = rustls::RootCertStore::empty();
    for cert in self.certificate.clone() {
      cert.add_to_tls(&mut root_cert_store)?;
    }
    let certs = rustls_native_certs::load_native_certs().certs;
    for cert in certs {
      root_cert_store.add(cert)?;
    }
    let mut versions = rustls::ALL_VERSIONS.to_vec();

    if let Some(min_tls_version) = self.min_tls_version {
      versions.retain(|&supported_version| {
        match tls::Version::from_tls(supported_version.version) {
          Some(version) => version >= min_tls_version,
          // Assume it's so new we don't know about it, allow it
          // (as of writing this is unreachable)
          None => true,
        }
      });
    }

    if let Some(max_tls_version) = self.max_tls_version {
      versions.retain(|&supported_version| {
        match tls::Version::from_tls(supported_version.version) {
          Some(version) => version <= max_tls_version,
          None => false,
        }
      });
    }

    if versions.is_empty() {
      return Err(crate::errors::builder("empty supported tls versions"));
    }
    let provider = rustls::crypto::CryptoProvider::get_default()
      .cloned()
      .unwrap_or_else(|| std::sync::Arc::new(rustls::crypto::ring::default_provider()));
    let signature_algorithms = provider.signature_verification_algorithms;
    let config_builder = rustls::ClientConfig::builder_with_provider(provider.clone())
      .with_protocol_versions(&versions)
      .map_err(|_| crate::errors::builder("invalid TLS versions"))?;
    let config_builder = if !self.certs_verification {
      config_builder
        .dangerous()
        .with_custom_certificate_verifier(std::sync::Arc::new(NoVerifier))
    } else if !self.hostname_verification {
      config_builder
        .dangerous()
        .with_custom_certificate_verifier(std::sync::Arc::new(IgnoreHostname::new(
          root_cert_store,
          signature_algorithms,
        )))
    } else {
      config_builder.with_root_certificates(root_cert_store)
    };
    let rustls_config = if let Some(id) = self.identity.clone() {
      id.add_to_tls(config_builder)?
    } else {
      config_builder.with_no_client_auth()
    };
    #[cfg(feature = "http2")]
    let rustls_config = {
      let mut config = rustls_config;
      if self.http2 {
        config.alpn_protocols = vec![b"http/1.1".to_vec(), b"h2".to_vec()];
      }
      config
    };
    Ok(TlsConnectorType::Rustls(tokio_rustls::TlsConnector::from(
      std::sync::Arc::new(rustls_config),
    )))
  }

  /// Combine the configuration of this builder with a connector to create a `Connector`.
  pub fn build(&self) -> Result<Connector> {
    #[cfg(feature = "tls")]
    let tls = {
      #[cfg(feature = "rustls")]
      {
        self.only_rustls()?
      }
      #[cfg(not(feature = "rustls"))]
      {
        // When only tls feature is enabled, require a custom connector
        if let Some(custom) = &self.custom_tls_connector {
          TlsConnectorType::Custom(custom.clone())
        } else {
          return Err(crate::errors::builder(
            "TLS feature enabled without backend: please enable 'rustls' feature, or provide a custom TLS connector using .custom_tls_connector()"
          ));
        }
      }
    };
    let conn = Connector {
      connect_timeout: self.connect_timeout,
      nodelay: self.nodelay,
      keepalive: self.keepalive,
      read_timeout: self.read_timeout,
      write_timeout: self.write_timeout,
      proxy: self.proxy.clone(),
      #[cfg(feature = "tls")]
      tls,
    };
    Ok(conn)
  }
}

/// Connector
// #[derive(Debug)]
pub struct Connector {
  connect_timeout: Option<Duration>,
  nodelay: bool,
  keepalive: bool,
  read_timeout: Option<Duration>,
  write_timeout: Option<Duration>,
  proxy: Option<Proxy>,
  #[cfg(feature = "tls")]
  tls: TlsConnectorType,
}

impl PartialEq for Connector {
  fn eq(&self, _other: &Self) -> bool {
    true
  }
}

impl Connector {
  /// Connect to a remote endpoint with addr
  pub async fn connect_with_addr<S: Into<SocketAddr>>(&self, addr: S) -> Result<Socket> {
    let addr = addr.into();
    let raw_socket = RawSocket::new(Domain::for_address(addr), Type::STREAM, Some(Protocol::TCP))?;
    raw_socket.set_nonblocking(true)?;
    // 阻塞才能设置超时，异步在这设置没意义
    // raw_socket.set_write_timeout(self.write_timeout)?;
    // raw_socket.set_read_timeout(self.read_timeout)?;
    let socket = TcpSocket::from_std_stream(raw_socket.into());
    if self.nodelay {
      socket.set_nodelay(self.nodelay)?;
    }
    if self.keepalive {
      socket.set_keepalive(self.keepalive)?;
    }
    let s = match self.connect_timeout {
      None => socket.connect(addr).await?,
      Some(timeout) => tokio::time::timeout(timeout, socket.connect(addr))
        .await
        .map_err(|x| crate::errors::new_io_error(std::io::ErrorKind::TimedOut, &x.to_string()))??,
    };
    Ok(Socket::new(
      MaybeTlsStream::Tcp(s),
      self.read_timeout,
      self.write_timeout,
    ))
  }
  /// Connect to a remote endpoint with url
  pub async fn connect_with_uri(&self, target: &http::Uri) -> Result<Socket> {
    ProxySocket::new(target, &self.proxy)
      .conn_with_connector(self)
      .await
  }
  #[cfg(feature = "tls")]
  /// A `Connector` will use transport layer security (TLS) by default to connect to destinations.
  pub async fn upgrade_to_tls(&self, stream: Socket, domain: &str) -> Result<Socket> {
    match &self.tls {
      #[cfg(feature = "rustls")]
      TlsConnectorType::Rustls(connector) => {
        // Rustls implementation
        let domain = ServerName::try_from(domain.to_owned())
          .map_err(|e| crate::errors::Error::Other(e.to_string()))?;
        let connect_timeout = self.connect_timeout.unwrap_or(Duration::from_secs(30));
        match stream.inner {
          MaybeTlsStream::Tcp(t) => {
            let s = tokio::time::timeout(connect_timeout, connector.connect(domain, t))
              .await
              .map_err(|e| {
                crate::errors::new_io_error(std::io::ErrorKind::TimedOut, &e.to_string())
              })?
              .map_err(|e| {
                crate::errors::Error::Other(format!("rustls handshake failed: {}", e))
              })?;
            let tls = Socket::new(
              MaybeTlsStream::Rustls(s.into()),
              stream.read_timeout,
              stream.write_timeout,
            );
            Ok(tls)
          }
          MaybeTlsStream::Rustls(t) => Ok(Socket::new(
            MaybeTlsStream::Rustls(t),
            stream.read_timeout,
            stream.write_timeout,
          )),
          #[cfg(all(feature = "tls", not(feature = "rustls")))]
          MaybeTlsStream::Custom(t) => Ok(Socket::new(
            MaybeTlsStream::Custom(t),
            stream.read_timeout,
            stream.write_timeout,
          )),
        }
      }
      #[cfg(not(feature = "rustls"))]
      TlsConnectorType::Custom(connector) => {
        // Custom TLS implementation
        // let connect_timeout = self.connect_timeout.unwrap_or(Duration::from_secs(30));
        let domain = domain.to_string();
        let tls = connector.connect(&domain, stream).await?;
        Ok(tls)
      }
    }
  }
}

//
impl Default for Connector {
  fn default() -> Self {
    ConnectorBuilder::default()
      .build()
      .expect("new default connector failure")
  }
}
