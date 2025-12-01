use crate::errors::Result;
use crate::proxy::{Proxy, ProxySocket};
use crate::socket::{Socket, StreamWrapper};
#[cfg(feature = "dns")]
use crate::dns::DnsResolver;
#[cfg(feature = "tls")]
use crate::tls::{self, Certificate, CustomTlsConnector, Identity};
use socket2::Socket as RawSocket;
use socket2::{Domain, Protocol, Type};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::TcpSocket;

/// ConnectorBuilder
#[derive(Clone)]
pub struct ConnectorBuilder {
  read_timeout: Option<Duration>,
  write_timeout: Option<Duration>,
  connect_timeout: Option<Duration>,
  nodelay: bool,
  keepalive: bool,
  proxy: Option<Proxy>,
  #[cfg(feature = "dns")]
  dns_resolver: Option<DnsResolver>,
  #[cfg(feature = "tls")]
  tls_config: TlsConfig,
  #[cfg(feature = "tls")]
  custom_tls_connector: Option<std::sync::Arc<dyn CustomTlsConnector>>,
}

impl Default for ConnectorBuilder {
  fn default() -> Self {
    Self {
      read_timeout: Some(Duration::from_secs(30)),
      write_timeout: Some(Duration::from_secs(30)),
      connect_timeout: Some(Duration::from_secs(10)),
      nodelay: false,
      keepalive: false,
      proxy: None,
      #[cfg(feature = "dns")]
      dns_resolver: None,
      #[cfg(feature = "tls")]
      tls_config: TlsConfig::default(),
      #[cfg(feature = "tls")]
      custom_tls_connector: None,
    }
  }
}

#[cfg(feature = "tls")]
/// TLS related configuration extracted from ConnectorBuilder.
#[derive(Clone)]
pub struct TlsConfig {
  #[cfg(feature = "http2")]
  pub http2: bool,
  pub hostname_verification: bool,
  pub certs_verification: bool,
  pub min_tls_version: Option<tls::Version>,
  pub max_tls_version: Option<tls::Version>,
  pub tls_sni: bool,
  pub identity: Option<Identity>,
  pub certificate: Vec<Certificate>,
}
#[cfg(feature = "rustls")]
impl TlsConfig {
  fn custom(
    &self,
    connect_timeout: Option<Duration>,
  ) -> Result<std::sync::Arc<dyn CustomTlsConnector>> {
    let mut root_cert_store = tokio_rustls::rustls::RootCertStore::empty();
    for cert in self.certificate.clone() {
      cert.add_to_tls(&mut root_cert_store)?;
    }
    let certs = rustls_native_certs::load_native_certs().certs;
    for cert in certs {
      root_cert_store.add(cert)?;
    }
    let mut versions = tokio_rustls::rustls::ALL_VERSIONS.to_vec();
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
    let provider = tokio_rustls::rustls::crypto::CryptoProvider::get_default()
      .cloned()
      .unwrap_or_else(|| {
        std::sync::Arc::new(tokio_rustls::rustls::crypto::ring::default_provider())
      });
    let signature_algorithms = provider.signature_verification_algorithms;
    let config_builder =
      tokio_rustls::rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&versions)
        .map_err(|_| crate::errors::builder("invalid TLS versions"))?;
    let config_builder = if !self.certs_verification {
      config_builder
        .dangerous()
        .with_custom_certificate_verifier(std::sync::Arc::new(tls::rustls::NoVerifier))
    } else if !self.hostname_verification {
      config_builder
        .dangerous()
        .with_custom_certificate_verifier(std::sync::Arc::new(tls::rustls::IgnoreHostname::new(
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
    Ok(std::sync::Arc::new(tls::rustls::RustlsTlsConnector::new(
      tokio_rustls::TlsConnector::from(std::sync::Arc::new(rustls_config)),
      connect_timeout,
    )))
  }
}
#[cfg(feature = "tls")]
impl Default for TlsConfig {
  fn default() -> Self {
    Self {
      #[cfg(feature = "http2")]
      http2: false,
      hostname_verification: true,
      certs_verification: true,
      min_tls_version: None,
      max_tls_version: None,
      tls_sni: true,
      identity: None,
      certificate: vec![],
    }
  }
}

impl ConnectorBuilder {
  #[cfg(feature = "http2")]
  /// Enable HTTP/2 support.
  pub fn enable_http2(mut self, http2: bool) -> Self {
    self.tls_config.http2 = http2;
    self
  }
  #[cfg(feature = "tls")]
  /// Controls the use of hostname verification.
  ///
  /// Defaults to `true`.
  pub fn hostname_verification(mut self, value: bool) -> ConnectorBuilder {
    self.tls_config.hostname_verification = value;
    self
  }
  #[cfg(feature = "tls")]
  /// Controls the use of certificate validation.
  ///
  /// Defaults to `true`.
  pub fn certs_verification(mut self, value: bool) -> ConnectorBuilder {
    self.tls_config.certs_verification = value;
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
    self.tls_config.tls_sni = value;
    self
  }
  /// Adds a certificate to the set of roots that the connector will trust.
  #[cfg(feature = "tls")]
  pub fn certificate(mut self, value: Vec<Certificate>) -> ConnectorBuilder {
    self.tls_config.certificate = value;
    self
  }
  /// Sets the identity to be used for client certificate authentication.
  #[cfg(feature = "tls")]
  pub fn identity(mut self, value: Identity) -> ConnectorBuilder {
    self.tls_config.identity = Some(value);
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
  /// Set a custom DNS resolver for hostname resolution.
  ///
  /// This allows you to use custom DNS servers instead of the system's default DNS.
  ///
  /// # Optional
  ///
  /// This requires the optional `dns` feature to be enabled.
  ///
  /// # Example
  ///
  /// ```ignore
  /// use slinger::{ConnectorBuilder, dns::DnsResolver};
  ///
  /// # fn example() -> Result<(), slinger::Error> {
  /// let resolver = DnsResolver::new(vec![
  ///     "8.8.8.8:53".parse().unwrap(),
  /// ])?;
  ///
  /// let connector = ConnectorBuilder::default()
  ///     .dns_resolver(resolver)
  ///     .build()?;
  /// # Ok(())
  /// # }
  /// ```
  #[cfg(feature = "dns")]
  pub fn dns_resolver(mut self, resolver: DnsResolver) -> ConnectorBuilder {
    self.dns_resolver = Some(resolver);
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
    self.tls_config.min_tls_version = version;
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
    self.tls_config.max_tls_version = version;
    self
  }

  /// Set a custom TLS connector for custom TLS handshake implementations.
  ///
  /// This is available when the `tls` feature is enabled. It allows you to provide
  /// your own TLS implementation using libraries like openssl, boringssl, native-tls,
  /// or any other TLS library. When the `rustls` feature is enabled, a default rustls
  /// implementation is used if no custom connector is provided.
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
  ///         domain: &'a str,
  ///         stream: Socket,
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
  #[cfg(feature = "tls")]
  pub fn custom_tls_connector(
    mut self,
    connector: std::sync::Arc<dyn CustomTlsConnector>,
  ) -> ConnectorBuilder {
    self.custom_tls_connector = Some(connector);
    self
  }
}

impl ConnectorBuilder {
  /// Combine the configuration of this builder with a connector to create a `Connector`.
  pub fn build(&self) -> Result<Connector> {
    #[cfg(feature = "tls")]
    let tls = {
      // custom connector takes precedence; otherwise if rustls is enabled, build it from config
      if let Some(custom) = &self.custom_tls_connector {
        custom.clone()
      } else {
        #[cfg(feature = "rustls")]
        {
          // Try to convert the builder into a rustls connector. Clone self because TryInto consumes it.
          self.tls_config.custom(self.connect_timeout)?
        }
        #[cfg(not(feature = "rustls"))]
        {
          return Err(crate::errors::builder(
            "TLS feature enabled without backend: please enable 'rustls' feature, or provide a custom TLS connector using .custom_tls_connector()",
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
      #[cfg(feature = "dns")]
      dns_resolver: self.dns_resolver.clone(),
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
  #[cfg(feature = "dns")]
  dns_resolver: Option<DnsResolver>,
  #[cfg(feature = "tls")]
  tls: std::sync::Arc<dyn CustomTlsConnector>,
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
      StreamWrapper::Tcp(s),
      self.read_timeout,
      self.write_timeout,
    ))
  }
  /// Connect to a remote endpoint with url
  pub async fn connect_with_uri(&self, target: &http::Uri) -> Result<Socket> {
    #[allow(unused_mut)]
    let mut proxy_socket = ProxySocket::new(target, &self.proxy);
    #[cfg(feature = "dns")]
    {
      proxy_socket = proxy_socket.dns_resolver(self.dns_resolver.clone());
    }
    proxy_socket.conn_with_connector(self).await
  }
  #[cfg(feature = "tls")]
  /// A `Connector` will use transport layer security (TLS) by default to connect to destinations.
  pub async fn upgrade_to_tls(&self, stream: Socket, domain: &str) -> Result<Socket> {
    self.tls.connect(domain, stream).await
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
