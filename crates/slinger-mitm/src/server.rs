//! MITM Proxy server implementation

use crate::ca::CertificateManager;
use crate::error::{Error, Result};
use crate::interceptor::{InterceptorHandler, MitmRequest, MitmResponse};
use crate::proxy::MitmConfig;
use bytes::Bytes;
use http::Method;
use slinger::{Client, ClientBuilder, Request};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::TlsAcceptor;

/// Proxy server implementation
pub struct ProxyServer {
  config: MitmConfig,
  cert_manager: Arc<CertificateManager>,
  interceptor_handler: Arc<RwLock<InterceptorHandler>>,
  client: Client,
}

struct TunnelRouteContext {
  peer_addr: SocketAddr,
  cert_manager: Arc<CertificateManager>,
  interceptor: Arc<RwLock<InterceptorHandler>>,
  client: Client,
  upstream_proxy: Option<slinger::Proxy>,
  protocol_tag: &'static str,
}

struct ConnectionContext {
  peer_addr: SocketAddr,
  cert_manager: Arc<CertificateManager>,
  interceptor: Arc<RwLock<InterceptorHandler>>,
  client: Client,
  upstream_proxy: Option<slinger::Proxy>,
}

impl ConnectionContext {
  fn into_tunnel(self, protocol_tag: &'static str) -> TunnelRouteContext {
    TunnelRouteContext {
      peer_addr: self.peer_addr,
      cert_manager: self.cert_manager,
      interceptor: self.interceptor,
      client: self.client,
      upstream_proxy: self.upstream_proxy,
      protocol_tag,
    }
  }
}

/// Builder for `ProxyServer`.
///
/// Allows configuring the server and the inner `slinger::Client`.
#[derive(Default)]
pub struct ProxyServerBuilder {
  config: Option<MitmConfig>,
  cert_manager: Option<Arc<CertificateManager>>,
  interceptor_handler: Option<Arc<RwLock<InterceptorHandler>>>,
  client: Option<Client>,
  // Optional client configurator: takes a ClientBuilder and returns a configured ClientBuilder
  client_config: Option<Box<dyn Fn(ClientBuilder) -> ClientBuilder + Send + Sync>>,
}

impl ProxyServerBuilder {
  /// Start building from an existing `ProxyServer` configuration.
  pub fn from_server(server: &ProxyServer) -> Self {
    Self {
      config: Some(server.config.clone()),
      cert_manager: Some(server.cert_manager.clone()),
      interceptor_handler: Some(server.interceptor_handler.clone()),
      client: Some(server.client.clone()),
      client_config: None,
    }
  }

  /// Set the `MitmConfig` to use.
  pub fn config(mut self, config: MitmConfig) -> Self {
    self.config = Some(config);
    self
  }

  /// Set the `CertificateManager` to use.
  pub fn cert_manager(mut self, cert_manager: Arc<CertificateManager>) -> Self {
    self.cert_manager = Some(cert_manager);
    self
  }

  /// Set the `InterceptorHandler` to use.
  pub fn interceptor_handler(mut self, handler: Arc<RwLock<InterceptorHandler>>) -> Self {
    self.interceptor_handler = Some(handler);
    self
  }

  /// Provide a fully constructed `slinger::Client` to use.
  pub fn client(mut self, client: Client) -> Self {
    self.client = Some(client);
    self
  }

  /// Configure the internal `slinger::Client` using a closure that accepts a
  /// `ClientBuilder` and returns a configured `ClientBuilder`.
  pub fn configure_client<F>(mut self, f: F) -> Self
  where
    F: Fn(ClientBuilder) -> ClientBuilder + Send + Sync + 'static,
  {
    self.client_config = Some(Box::new(f));
    self
  }

  /// Build the `ProxyServer`.
  ///
  /// Priority for creating the inner `Client`:
  /// 1. If `client` is provided, use it.
  /// 2. Else if `client_config` is provided, call it with `Client::builder()`.
  /// 3. Else fall back to default behavior: honor `config.upstream_proxy` if present
  ///    and otherwise create a default client similar to `ProxyServer::new`.
  pub fn build(self) -> Result<ProxyServer> {
    // Resolve config
    let config = self.config.unwrap_or_default();

    // For synchronous build we require a pre-created CertificateManager because
    // creation is async. Callers who don't have one should use `build_async()`.
    let cert_manager = match self.cert_manager {
      Some(c) => c,
      None => {
        return Err(Error::proxy_error(
          "CertificateManager not provided; use ProxyServer::builder().build_async().await to create one automatically".to_string(),
        ))
      }
    };

    // Resolve interceptor handler
    let interceptor_handler = self.interceptor_handler.unwrap_or_else(|| {
      Arc::new(RwLock::new(
        InterceptorHandler::new().with_timeout(config.interceptor_timeout_secs),
      ))
    });

    // Resolve client
    let client = if let Some(client) = self.client {
      client
    } else if let Some(cfg_fn) = self.client_config {
      let builder = Client::builder();
      let configured = cfg_fn(builder);
      configured
        .build()
        .map_err(|e| Error::proxy_error(format!("Failed to build client: {}", e)))?
    } else {
      // Fallback: honor upstream_proxy in config similar to ProxyServer::new
      if let Some(proxy) = &config.upstream_proxy {
        Client::builder()
          .timeout(Some(Duration::from_secs(60)))
          .keepalive(true)
          .proxy(proxy.clone())
          .build()
          .map_err(|e| {
            Error::proxy_error(format!(
              "Failed to build client with proxy {}: {}",
              proxy.uri(),
              e
            ))
          })?
      } else {
        Client::builder()
          .keepalive(true)
          .build()
          .map_err(|e| Error::proxy_error(format!("Failed to build default client: {}", e)))?
      }
    };

    Ok(ProxyServer {
      config,
      cert_manager,
      interceptor_handler,
      client,
    })
  }
}

impl ProxyServer {
  /// Create a new proxy server
  pub fn new(
    config: MitmConfig,
    cert_manager: Arc<CertificateManager>,
    interceptor_handler: Arc<RwLock<InterceptorHandler>>,
  ) -> Result<Self> {
    let client = if let Some(proxy) = &config.upstream_proxy {
      // Enable HTTP keep-alive so the connector can reuse TCP connections
      Client::builder()
        .timeout(Some(Duration::from_secs(60)))
        .keepalive(true)
        .proxy(proxy.clone())
        .build()
        .map_err(|e| {
          Error::proxy_error(format!(
            "Failed to build client with proxy {}: {}",
            proxy.uri(),
            e
          ))
        })?
    } else {
      // Use a client configured to reuse connections (keep-alive)
      Client::builder()
        .keepalive(true)
        .build()
        .map_err(|e| Error::proxy_error(format!("Failed to build default client: {}", e)))?
    };
    Ok(Self {
      config,
      cert_manager,
      interceptor_handler,
      client,
    })
  }

  /// Run the proxy server
  pub async fn run(&self, addr: &str) -> Result<()> {
    let listener = TcpListener::bind(addr)
      .await
      .map_err(|e| Error::proxy_error(format!("Failed to bind to {}: {}", addr, e)))?;
    loop {
      match listener.accept().await {
        Ok((stream, peer_addr)) => {
          let cert_manager = self.cert_manager.clone();
          let interceptor = self.interceptor_handler.clone();
          let client = self.client.clone();
          let upstream_proxy = self.config.upstream_proxy.clone();

          tokio::spawn(async move {
            if let Err(e) = Self::handle_connection(
              stream,
              peer_addr,
              cert_manager,
              interceptor,
              client,
              upstream_proxy,
            )
            .await
            {
              tracing::error!("[MITM] Error handling connection: {}", e);
            }
          });
        }
        Err(e) => {
          tracing::error!("[MITM] Failed to accept connection: {}", e);
        }
      }
    }
  }

  /// Handle a client connection
  async fn handle_connection(
    mut stream: TcpStream,
    peer_addr: SocketAddr,
    cert_manager: Arc<CertificateManager>,
    interceptor: Arc<RwLock<InterceptorHandler>>,
    client: Client,
    upstream_proxy: Option<slinger::Proxy>,
  ) -> Result<()> {
    // Read the first byte to determine protocol
    let mut first_byte = [0u8; 1];
    stream.peek(&mut first_byte).await?;

    let ctx = ConnectionContext {
      peer_addr,
      cert_manager,
      interceptor,
      client,
      upstream_proxy,
    };

    // SOCKS5 version is 0x05, HTTP methods start with ASCII letters
    if first_byte[0] == 0x05 {
      // SOCKS5 handshake helper expects version byte to be consumed already.
      stream.read_exact(&mut first_byte).await?;
      return Self::handle_socks5_connection(stream, ctx).await;
    }

    Self::handle_http_connection(stream, ctx).await
  }

  async fn handle_socks5_connection(
    mut stream: TcpStream,
    ctx: ConnectionContext,
  ) -> Result<()> {
    use crate::socks5::Socks5Server;

    // Handle as SOCKS5 - we already consumed the version byte.
    let target_addr = Socks5Server::handle_handshake_with_version(&mut stream).await?;
    let target_host_port = target_addr.to_host_port();
    Self::handle_tunnel_route(stream, &target_host_port, ctx.into_tunnel("SOCKS5")).await
  }

  async fn handle_http_connection(stream: TcpStream, ctx: ConnectionContext) -> Result<()> {
    let mut reader = BufReader::new(stream);
    let request = Request::from_http_reader(&mut reader).await?;
    if request.method() == Method::CONNECT {
      let uri = request.uri().to_string();
      let mut stream = reader.into_inner();

      // Send HTTP/1.1 200 Connection Established first, then auto-detect
      // the underlying protocol to decide how to handle the tunnel.
      stream
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;
      stream.flush().await.map_err(Error::Io)?;

      return Self::handle_tunnel_route(stream, &uri, ctx.into_tunnel("CONNECT")).await;
    }

    Self::handle_http_request(request, reader, ctx.interceptor, ctx.client).await
  }

  /// Shared tunnel routing for SOCKS5 and HTTP CONNECT.
  async fn handle_tunnel_route(
    stream: TcpStream,
    target_addr: &str,
    ctx: TunnelRouteContext,
  ) -> Result<()> {
    if Self::peek_tls_client_hello(&stream, ctx.protocol_tag).await {
      let (domain, port) = Self::parse_host_port(target_addr)?;
      return Self::accept_tls_and_handle(
        stream,
        &domain,
        port,
        false,
        ctx.cert_manager,
        ctx.interceptor,
        ctx.client,
      )
      .await;
    }

    let has_interceptors = ctx.interceptor.read().await.has_interceptors();
    let socket = slinger::Socket::new(slinger::StreamWrapper::Tcp(stream), None, None);

    if has_interceptors {
      Self::handle_tcp_tunnel_with_interception(
        socket,
        target_addr,
        ctx.peer_addr,
        ctx.interceptor,
        ctx.upstream_proxy,
      )
      .await
    } else {
      Self::tcp_tunnel(socket, target_addr, false, ctx.upstream_proxy).await
    }
  }

  async fn peek_tls_client_hello(stream: &TcpStream, protocol_tag: &str) -> bool {
    // A TLS ClientHello is client-first and starts with TLS record prefix 0x16 0x03.
    let mut peek_buf = [0u8; 5];
    let peeked = match tokio::time::timeout(Duration::from_millis(100), stream.peek(&mut peek_buf)).await {
      Ok(Ok(n)) => n,
      Ok(Err(e)) => {
        tracing::debug!(
          "[MITM {}] Peek failed, defaulting to TCP tunnel: {}",
          protocol_tag,
          e
        );
        0
      }
      Err(_) => {
        tracing::debug!(
          "[MITM {}] Peek timed out, defaulting to TCP tunnel",
          protocol_tag
        );
        0
      }
    };

    Self::is_tls_client_hello(&peek_buf[..peeked])
  }

  /// Returns `true` when `bytes` begins with a TLS handshake record header.
  ///
  /// A TLS record starts with:
  ///   byte 0  – content type 0x16 (Handshake)
  ///   byte 1  – major version 0x03 (TLS 1.0 / 1.1 / 1.2 / 1.3)
  ///
  /// This two-byte signature is sufficient to distinguish any TLS handshake
  /// (including ClientHello) from plaintext HTTP, SSH banners, raw TCP data,
  /// and virtually every other protocol.
  fn is_tls_client_hello(bytes: &[u8]) -> bool {
    bytes.len() >= 2 && bytes[0] == 0x16 && bytes[1] == 0x03
  }


  /// Accept TLS on an incoming stream (using certs from CertificateManager) and handle HTTPS requests over it.
  /// If `send_response` is true, send an HTTP/1.1 200 Connection Established before performing the TLS handshake
  async fn accept_tls_and_handle(
    mut client_stream: TcpStream,
    domain: &str,
    port: u16,
    send_response: bool,
    cert_manager: Arc<CertificateManager>,
    interceptor: Arc<RwLock<InterceptorHandler>>,
    slinger_client: Client,
  ) -> Result<()> {
    if send_response {
      client_stream
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;
      client_stream
        .flush() // ensure response fully sent
        .await
        .map_err(Error::Io)?;
    }

    // Generate server certificate for this domain
    let (cert_chain, key) = cert_manager.get_server_cert(domain).await?;
    // Create TLS acceptor
    let tls_config = Self::create_tls_server_config(cert_chain, key)?;
    let acceptor = TlsAcceptor::from(Arc::new(tls_config));
    // Perform TLS handshake with client
    let tls_stream = acceptor
      .accept(client_stream)
      .await
      .map_err(|e| Error::tls_error(format!("TLS handshake failed: {}", e)))?;
    let domain_with_port = format!("{}:{}", domain, port);
    Self::handle_https_stream(tls_stream, domain_with_port, interceptor, slinger_client).await
  }

  /// Generic TCP tunnel helper. If `send_response` is true, sends HTTP/1.1 200 before tunneling.
  async fn tcp_tunnel(
    mut client_stream: slinger::Socket,
    uri: &str,
    send_response: bool,
    upstream_proxy: Option<slinger::Proxy>,
  ) -> Result<()> {
    // Connect to target server (through upstream proxy if configured)
    let target_socket = Self::connect_to_target(uri, upstream_proxy.as_ref()).await?;

    if send_response {
      client_stream
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;
    }

    let (mut client_read, mut client_write) = tokio::io::split(client_stream);
    let (mut target_read, mut target_write) = tokio::io::split(target_socket);

    let client_to_target = tokio::io::copy(&mut client_read, &mut target_write);
    let target_to_client = tokio::io::copy(&mut target_read, &mut client_write);

    tokio::select! {
        _ = client_to_target => {},
        _ = target_to_client => {},
    }

    Ok(())
  }

  /// TCP tunnel with interception capability for raw TCP traffic.
  /// This method intercepts both request and response data, passes them through
  /// the interceptors, and forwards the (potentially modified) data.
  async fn handle_tcp_tunnel_with_interception(
    client_stream: slinger::Socket,
    target_addr: &str,
    peer_addr: SocketAddr,
    interceptor: Arc<RwLock<InterceptorHandler>>,
    upstream_proxy: Option<slinger::Proxy>,
  ) -> Result<()> {
    use uuid::Uuid;

    // Generate a session ID for this TCP connection using UUID
    // All requests and responses for this connection will share this session_id
    let connection_session_id = Uuid::new_v4().as_u128();

    // Connect to target server (through upstream proxy if configured)
    let target_socket = Self::connect_to_target(target_addr, upstream_proxy.as_ref()).await?;

    let (mut client_read, mut client_write) = tokio::io::split(client_stream);
    let (mut target_read, mut target_write) = tokio::io::split(target_socket);

    let target_addr_clone = target_addr.to_string();
    let target_addr_clone2 = target_addr.to_string();
    let interceptor_clone = interceptor.clone();

    // Client to target with interception
    let client_to_target = tokio::spawn(async move {
      let mut buffer = vec![0u8; 8192];
      loop {
        match client_read.read(&mut buffer).await {
          Ok(0) => break, // Connection closed
          Ok(n) => {
            let data = Bytes::copy_from_slice(&buffer[..n]);
            let mut request = MitmRequest::raw_tcp_with_source(peer_addr, &target_addr_clone, data);
            // Override the auto-generated session_id with the connection's session_id
            request.set_session_id(connection_session_id);

            // Process through interceptors
            let handler = interceptor_clone.read().await;
            match handler.process_request(request).await {
              Ok(Some(modified_request)) => {
                // Forward modified data to target
                if let Some(body) = modified_request.body() {
                  if let Err(e) = target_write.write_all(body.as_ref()).await {
                    tracing::error!("[MITM TCP] Error writing to target: {}", e);
                    break;
                  }
                }
              }
              Ok(None) => {
                // Request blocked by interceptor
                tracing::debug!("[MITM TCP] Request blocked by interceptor");
              }
              Err(e) => {
                tracing::error!("[MITM TCP] Error processing request: {}", e);
                break;
              }
            }
          }
          Err(e) => {
            tracing::error!("[MITM TCP] Error reading from client: {}", e);
            break;
          }
        }
      }
    });

    // Target to client with interception
    let target_to_client = tokio::spawn(async move {
      let mut buffer = vec![0u8; 8192];
      loop {
        match target_read.read(&mut buffer).await {
          Ok(0) => break, // Connection closed
          Ok(n) => {
            let data = Bytes::copy_from_slice(&buffer[..n]);
            // Use the same connection_session_id to correlate with requests
            let response = MitmResponse::raw_tcp_with_destination(
              connection_session_id,
              &target_addr_clone2,
              peer_addr,
              data,
            );

            // Process through interceptors
            let handler = interceptor.read().await;
            match handler.process_response(response).await {
              Ok(Some(modified_response)) => {
                // Forward modified data to client
                if let Some(body) = modified_response.body() {
                  if let Err(e) = client_write.write_all(body.as_ref()).await {
                    tracing::error!("[MITM TCP] Error writing to client: {}", e);
                    break;
                  }
                }
              }
              Ok(None) => {
                // Response blocked by interceptor
                tracing::debug!("[MITM TCP] Response blocked by interceptor");
              }
              Err(e) => {
                tracing::error!("[MITM TCP] Error processing response: {}", e);
                break;
              }
            }
          }
          Err(e) => {
            tracing::error!("[MITM TCP] Error reading from target: {}", e);
            break;
          }
        }
      }
    });

    tokio::select! {
        _ = client_to_target => {},
        _ = target_to_client => {},
    }

    Ok(())
  }

  /// Connect to `target_addr` (in `"host:port"` format) routing through the
  /// upstream proxy when configured.  Delegates to slinger's own
  /// [`ConnectorBuilder`] and [`Connector::connect_with_uri`] so that HTTP
  /// CONNECT and SOCKS5/SOCKS5h proxy logic is not duplicated here.
  async fn connect_to_target(
    target_addr: &str,
    upstream_proxy: Option<&slinger::Proxy>,
  ) -> Result<slinger::Socket> {
    // Build a plain-text URI from the host:port string. Using the `http`
    // scheme ensures slinger treats this as a raw TCP target and does **not**
    // initiate a TLS upgrade after the proxy tunnel is established.
    let uri = format!("http://{}", target_addr)
      .parse::<http::Uri>()
      .map_err(|e| {
        Error::connection_error(format!("Invalid target address '{}': {}", target_addr, e))
      })?;

    let connector = slinger::ConnectorBuilder::default()
      .proxy(upstream_proxy.cloned())
      .build()
      .map_err(|e| Error::connection_error(format!("Failed to build connector: {}", e)))?;

    connector.connect_with_uri(&uri).await.map_err(Into::into)
  }

  /// Returns Some(response_bytes) if there is a response to write back to the caller, or None if
  /// the interceptor chain dropped the request/response.
  async fn forward_request_via_client(
    interceptor: Arc<RwLock<InterceptorHandler>>,
    client: &Client,
    request: Request,
    destination: &str,
  ) -> Result<Option<Vec<u8>>> {
    let handler = interceptor.read().await;
    let mitm_request = MitmRequest::new(destination, request);
    // Store the session_id to correlate with the response
    let session_id = mitm_request.session_id();
    if let Some(modified_req) = handler.process_request(mitm_request).await? {
      let inner_req = modified_req.request();
      let uri = inner_req.uri().clone();
      let method = inner_req.method().clone();
      let headers = inner_req.headers().clone();
      let body_data = if let Some(body) = inner_req.body() {
        body.to_vec()
      } else {
        Vec::new()
      };
      let mut req_builder = client.request(method, uri);
      for (name, value) in headers.iter() {
        req_builder = req_builder.header(name, value);
      }
      req_builder = req_builder.body(body_data);
      match req_builder.send().await {
        Ok(response) => {
          // Pass the session_id from request to response for correlation
          let mitm_response = MitmResponse::new(session_id, destination, response);
          if let Some(final_response) = handler.process_response(mitm_response).await? {
            let response_bytes = Bytes::from(final_response.response()).to_vec();
            return Ok(Some(response_bytes));
          }
        }
        Err(_e) => {
          return Ok(Some(b"HTTP/1.1 502 Bad Gateway\r\n\r\n".to_vec()));
        }
      }
    }
    Ok(None)
  }

  /// Handle HTTPS requests over TLS connection
  async fn handle_https_stream<S>(
    tls_stream: S,
    domain: String,
    interceptor: Arc<RwLock<InterceptorHandler>>,
    client: Client,
  ) -> Result<()>
  where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
  {
    // `from_http_reader` requires a BufReader; reclaim the inner stream afterwards for writing.
    let mut reader = BufReader::new(tls_stream);
    let request_result = Request::from_http_reader(&mut reader).await;
    let mut tls_stream = reader.into_inner();

    let mut request = match request_result {
      Ok(req) => req,
      Err(e) => {
        tracing::debug!("[MITM HTTPS] Failed to parse request: {}", e);
        return Ok(());
      }
    };

    // Fix relative URI to be absolute (e.g., /path -> https://domain/path)
    if request.uri().host().is_none() {
      let pq = request.uri().path_and_query().map(|pq| pq.as_str()).unwrap_or("/");
      let absolute_uri = format!("https://{}{}", domain, pq)
        .parse::<http::Uri>()
        .map_err(|e| Error::invalid_request(format!("Invalid URI: {}", e)))?;
      *request.uri_mut() = absolute_uri;
    }

    if let Some(response_bytes) =
      Self::forward_request_via_client(interceptor, &client, request, &domain).await?
    {
      tls_stream.write_all(&response_bytes).await?;
    }

    Ok(())
  }

  /// Handle HTTP request (non-HTTPS)
  async fn handle_http_request<R>(
    request: Request,
    reader: BufReader<R>,
    interceptor: Arc<RwLock<InterceptorHandler>>,
    client: Client,
  ) -> Result<()>
  where
    R: AsyncReadExt + AsyncWriteExt + Unpin,
  {
    let uri = request.uri().to_string();

    // Process through interceptors and forward
    if let Some(response_bytes) =
      Self::forward_request_via_client(interceptor, &client, request, &uri).await?
    {
      let mut stream = reader.into_inner();
      stream.write_all(&response_bytes).await?;
    }

    Ok(())
  }

  /// Create TLS server configuration
  fn create_tls_server_config(
    cert_chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
  ) -> Result<ServerConfig> {
    let config = ServerConfig::builder()
      .with_no_client_auth()
      .with_single_cert(cert_chain, key)
      .map_err(|e| Error::tls_error(format!("Failed to create TLS config: {}", e)))?;

    Ok(config)
  }

  /// Parse host and port from URI
  fn parse_host_port(uri: &str) -> Result<(String, u16)> {
    let parts: Vec<&str> = uri.split(':').collect();
    if parts.len() != 2 {
      return Err(Error::invalid_request(format!("Invalid URI: {}", uri)));
    }

    let host = parts[0].to_string();
    let port = parts[1]
      .parse::<u16>()
      .map_err(|_| Error::invalid_request(format!("Invalid port: {}", parts[1])))?;

    Ok((host, port))
  }

}
