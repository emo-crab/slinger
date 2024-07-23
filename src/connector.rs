#[cfg(feature = "tls")]
use crate::errors::new_io_error;
use crate::errors::Result;
use crate::proxy::{Proxy, ProxySocket};
use crate::socket::Socket;
#[cfg(feature = "tls")]
use native_tls::{Certificate, HandshakeError, Identity, TlsConnector};
use socket2::Socket as RawSocket;
use socket2::{Domain, Protocol, Type};
use std::net::SocketAddr;
use std::time::Duration;

/// ConnectorBuilder
#[derive(Clone)]
pub struct ConnectorBuilder {
  hostname_verification: bool,
  certs_verification: bool,
  read_timeout: Option<Duration>,
  write_timeout: Option<Duration>,
  connect_timeout: Option<Duration>,
  nodelay: bool,
  #[cfg(feature = "tls")]
  tls_sni: bool,
  #[cfg(feature = "tls")]
  identity: Option<Identity>,
  #[cfg(feature = "tls")]
  certificate: Vec<Certificate>,
  proxy: Option<Proxy>,
}

impl Default for ConnectorBuilder {
  fn default() -> Self {
    Self {
      hostname_verification: true,
      certs_verification: true,
      read_timeout: Some(Duration::from_secs(30)),
      write_timeout: Some(Duration::from_secs(30)),
      connect_timeout: Some(Duration::from_secs(10)),
      nodelay: false,
      #[cfg(feature = "tls")]
      tls_sni: true,
      #[cfg(feature = "tls")]
      identity: None,
      #[cfg(feature = "tls")]
      certificate: vec![],
      proxy: None,
    }
  }
}
impl ConnectorBuilder {
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
}

impl ConnectorBuilder {
  /// Combine the configuration of this builder with a connector to create a `Connector`.
  pub fn build(&self) -> Result<Connector> {
    #[cfg(feature = "tls")]
    let tls = {
      let mut binding = TlsConnector::builder();
      let mut tls_builder = binding
        .use_sni(self.tls_sni)
        .danger_accept_invalid_hostnames(!self.hostname_verification)
        .danger_accept_invalid_certs(!self.certs_verification);
      for c in self.certificate.iter() {
        tls_builder = tls_builder.add_root_certificate(c.clone());
      }
      if let Some(identity) = &self.identity {
        tls_builder.identity(identity.clone());
      };
      tls_builder.build()?
    };
    let conn = Connector {
      connect_timeout: self.connect_timeout,
      nodelay: self.nodelay,
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
#[derive(Debug)]
pub struct Connector {
  connect_timeout: Option<Duration>,
  nodelay: bool,
  read_timeout: Option<Duration>,
  write_timeout: Option<Duration>,
  proxy: Option<Proxy>,
  #[cfg(feature = "tls")]
  tls: TlsConnector,
}

impl PartialEq for Connector {
  fn eq(&self, _other: &Self) -> bool {
    true
  }
}

impl Connector {
  /// Connect to a remote endpoint with addr
  pub fn connect_with_addr<S: Into<SocketAddr>>(&self, addr: S) -> Result<Socket> {
    let addr = addr.into();
    let socket = RawSocket::new(Domain::for_address(addr), Type::STREAM, Some(Protocol::TCP))?;
    if self.nodelay {
      socket.set_nodelay(self.nodelay)?;
    }
    socket.set_read_timeout(self.read_timeout)?;
    socket.set_write_timeout(self.write_timeout)?;
    match self.connect_timeout {
      None => {
        socket.connect(&addr.into())?;
      }
      Some(timeout) => {
        socket.connect_timeout(&addr.into(), timeout)?;
      }
    }
    Ok(Socket::TCP(socket))
  }
  /// Connect to a remote endpoint with url
  pub fn connect_with_uri(&self, target: &http::Uri) -> Result<Socket> {
    ProxySocket::new(target, &self.proxy).conn_with_connector(self)
  }
  #[cfg(feature = "tls")]
  /// A `Connector` will use transport layer security (TLS) by default to connect to destinations.
  pub fn upgrade_to_tls(&self, stream: Socket, domain: &str) -> Result<Socket> {
    // 上面是原始socket
    let i = match stream {
      Socket::TCP(s) => {
        let mut stream = self.tls.connect(domain, s);
        while let Err(HandshakeError::WouldBlock(mid_handshake)) = stream {
          stream = mid_handshake.handshake();
        }
        Socket::TLS(stream?)
      }
      // 本来就是tls了
      Socket::TLS(_t) => {
        return Err(new_io_error(
          std::io::ErrorKind::ConnectionAborted,
          "it's already tls",
        ));
      }
    };
    Ok(i)
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
