//! MITM Proxy server implementation

use crate::ca::CertificateManager;
use crate::error::{Error, Result};
use crate::interceptor::{InterceptorHandler, MitmRequest, MitmResponse};
use crate::proxy::MitmConfig;
use bytes::Bytes;
use http::Version;
use slinger::{Client, ClientBuilder, Request, Response};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
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
    let interceptor_handler = self
      .interceptor_handler
      .unwrap_or_else(|| Arc::new(RwLock::new(InterceptorHandler::new())));

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
          let config = self.config.clone();
          let cert_manager = self.cert_manager.clone();
          let interceptor = self.interceptor_handler.clone();
          let client = self.client.clone();

          tokio::spawn(async move {
            if let Err(e) =
              Self::handle_connection(stream, peer_addr, config, cert_manager, interceptor, client)
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
    config: MitmConfig,
    cert_manager: Arc<CertificateManager>,
    interceptor: Arc<RwLock<InterceptorHandler>>,
    client: Client,
  ) -> Result<()> {
    use crate::socks5::Socks5Server;

    // Read the first byte to determine protocol
    let mut first_byte = [0u8; 1];
    stream.read_exact(&mut first_byte).await?;

    // SOCKS5 version is 0x05, HTTP methods start with ASCII letters
    if first_byte[0] == 0x05 {
      // Handle as SOCKS5 - we already consumed the version byte
      // Put it back by handling the rest of the handshake
      match Socks5Server::handle_handshake_with_version(&mut stream).await {
        Ok(target_addr) => {
          let target_host_port = target_addr.to_host_port();

          // Check if TCP interception is enabled and if there are interceptors
          let has_interceptors = interceptor.read().await.has_interceptors();

          if config.enable_tcp_interception && has_interceptors {
            // Use TCP interception for raw TCP traffic
            Self::handle_tcp_tunnel_with_interception(
              stream,
              &target_host_port,
              peer_addr,
              interceptor,
            )
            .await
          } else if config.enable_https_interception {
            Self::handle_https_connect_socks5(
              stream,
              &target_host_port,
              cert_manager,
              interceptor,
              client,
            )
            .await
          } else {
            Self::handle_tcp_tunnel(stream, &target_host_port).await
          }
        }
        Err(e) => Err(e),
      }
    } else {
      let mut request_line = vec![first_byte[0]];
      let mut buffer = [0u8; 1];
      loop {
        stream.read_exact(&mut buffer).await?;
        request_line.push(buffer[0]);
        if buffer[0] == b'\n' {
          break;
        }
        if request_line.len() > 8192 {
          return Err(Error::invalid_request("Request line too long".to_string()));
        }
      }

      let request_line_str = String::from_utf8_lossy(&request_line);
      let parts: Vec<&str> = request_line_str.split_whitespace().collect();
      if parts.len() < 3 {
        return Err(Error::invalid_request("Invalid request line".to_string()));
      }

      let method = parts[0].to_string();
      let uri = parts[1].to_string();
      if method == "CONNECT" {
        let mut reader = BufReader::new(stream);
        const MAX_CONNECT_HEADERS: usize = 16 * 1024; // 16KB max for proxy headers
        let mut headers_acc = 0usize;
        loop {
          let mut line = String::new();
          let n = reader.read_line(&mut line).await?;
          // n==0 indicates EOF; bail out
          if n == 0 {
            break;
          }
          headers_acc += n;
          if headers_acc > MAX_CONNECT_HEADERS {
            return Err(Error::invalid_request(
              "CONNECT headers size exceeds maximum allowed".to_string(),
            ));
          }
          // End of headers is an empty line (CRLF)
          if line == "\r\n" || line == "\n" || line.is_empty() {
            break;
          }
        }
        let stream = reader.into_inner();
        if config.enable_https_interception {
          Self::handle_https_connect(stream, &uri, cert_manager, interceptor, client).await
        } else {
          Self::handle_https_tunnel(stream, &uri).await
        }
      } else {
        let buf_reader = BufReader::new(stream);
        Self::handle_http_request(&method, &uri, buf_reader, interceptor, client).await
      }
    }
  }

  /// Handle HTTPS CONNECT with MITM interception
  async fn handle_https_connect(
    client_stream: TcpStream,
    uri: &str,
    cert_manager: Arc<CertificateManager>,
    interceptor: Arc<RwLock<InterceptorHandler>>,
    slinger_client: Client,
  ) -> Result<()> {
    // Parse domain and port
    let (domain, port) = Self::parse_host_port(uri)?;
    // Perform TLS accept + MITM handling, send HTTP 200 before TLS handshake
    Self::accept_tls_and_handle(
      client_stream,
      &domain,
      port,
      true,
      cert_manager,
      interceptor,
      slinger_client,
    )
    .await
  }

  /// Handle HTTPS tunnel without interception (transparent proxy)
  async fn handle_https_tunnel(client_stream: TcpStream, uri: &str) -> Result<()> {
    Self::tcp_tunnel(client_stream, uri, true).await
  }

  /// Handle TCP tunnel without interception (for SOCKS5)
  /// This function doesn't send any response - the SOCKS5 handshake already sent the reply
  async fn handle_tcp_tunnel(client_stream: TcpStream, target_addr: &str) -> Result<()> {
    Self::tcp_tunnel(client_stream, target_addr, false).await
  }

  /// Handle HTTPS CONNECT with MITM interception for SOCKS5
  /// This function doesn't send HTTP response - the SOCKS5 handshake already sent the reply
  async fn handle_https_connect_socks5(
    client_stream: TcpStream,
    uri: &str,
    cert_manager: Arc<CertificateManager>,
    interceptor: Arc<RwLock<InterceptorHandler>>,
    slinger_client: Client,
  ) -> Result<()> {
    // Parse domain and port
    let (domain, port) = Self::parse_host_port(uri)?;

    // Perform TLS accept + MITM handling, do NOT send HTTP 200 (SOCKS5 already responded)
    Self::accept_tls_and_handle(
      client_stream,
      &domain,
      port,
      false,
      cert_manager,
      interceptor,
      slinger_client,
    )
    .await
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
  async fn tcp_tunnel(mut client_stream: TcpStream, uri: &str, send_response: bool) -> Result<()> {
    let (host, port) = Self::parse_host_port(uri)?;
    let addr = format!("{}:{}", host, port);

    // Connect to target server
    let mut target_stream = TcpStream::connect(&addr)
      .await
      .map_err(|e| Error::connection_error(format!("Failed to connect to {}: {}", addr, e)))?;

    if send_response {
      client_stream
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;
    }

    let (mut client_read, mut client_write) = client_stream.split();
    let (mut target_read, mut target_write) = target_stream.split();

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
    client_stream: TcpStream,
    target_addr: &str,
    peer_addr: SocketAddr,
    interceptor: Arc<RwLock<InterceptorHandler>>,
  ) -> Result<()> {
    let (host, port) = Self::parse_host_port(target_addr)?;
    let addr = format!("{}:{}", host, port);

    // Connect to target server
    let target_stream = TcpStream::connect(&addr)
      .await
      .map_err(|e| Error::connection_error(format!("Failed to connect to {}: {}", addr, e)))?;

    let (mut client_read, mut client_write) = client_stream.into_split();
    let (mut target_read, mut target_write) = target_stream.into_split();

    let target_addr_clone = addr.clone();
    let interceptor_clone = interceptor.clone();

    // Client to target with interception
    let client_to_target = tokio::spawn(async move {
      let mut buffer = vec![0u8; 8192];
      loop {
        match client_read.read(&mut buffer).await {
          Ok(0) => break, // Connection closed
          Ok(n) => {
            let data = Bytes::copy_from_slice(&buffer[..n]);
            let request = MitmRequest::raw_tcp_with_source(peer_addr, &target_addr_clone, data);

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
            let response = MitmResponse::raw_tcp_with_destination(&addr, peer_addr, data);

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

  /// Forward a prepared `Request` through the inner `slinger::Client` and run interceptors.
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
          let mitm_response = MitmResponse::new(destination, response);
          if let Some(final_response) = handler.process_response(mitm_response).await? {
            let response_bytes = Self::serialize_http_response(final_response.response())?;
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
    mut tls_stream: S,
    domain: String,
    interceptor: Arc<RwLock<InterceptorHandler>>,
    client: Client,
  ) -> Result<()>
  where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
  {
    // Read HTTP request from TLS stream with size limit
    const MAX_REQUEST_SIZE: usize = 1024 * 1024; // 1MB limit
    let mut buffer = Vec::new();
    let mut temp_buf = [0u8; 8192];

    loop {
      match tls_stream.read(&mut temp_buf).await {
        Ok(0) => break,
        Ok(n) => {
          buffer.extend_from_slice(&temp_buf[..n]);
          if buffer.len() > MAX_REQUEST_SIZE {
            return Err(Error::invalid_request(
              "Request size exceeds maximum allowed".to_string(),
            ));
          }
          if buffer.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
          }
        }
        Err(e) => return Err(Error::Io(e)),
      }
    }

    // Parse request
    if let Ok(request) = Self::parse_http_request(&buffer, &domain) {
      if let Some(response_bytes) =
        Self::forward_request_via_client(interceptor, &client, request, &domain).await?
      {
        tls_stream.write_all(&response_bytes).await?;
      }
    }

    Ok(())
  }

  /// Handle HTTP request (non-HTTPS)
  async fn handle_http_request<R>(
    method: &str,
    uri: &str,
    mut reader: BufReader<R>,
    interceptor: Arc<RwLock<InterceptorHandler>>,
    client: Client,
  ) -> Result<()>
  where
    R: AsyncReadExt + AsyncWriteExt + Unpin,
  {
    // Read headers with size limit
    const MAX_HEADERS_SIZE: usize = 64 * 1024; // 64KB limit for headers
    let mut headers_buf = Vec::new();
    loop {
      let mut line = String::new();
      reader.read_line(&mut line).await?;
      if line == "\r\n" || line == "\n" {
        break;
      }
      headers_buf.extend_from_slice(line.as_bytes());

      // Check headers size limit
      if headers_buf.len() > MAX_HEADERS_SIZE {
        return Err(Error::invalid_request(
          "Headers size exceeds maximum allowed".to_string(),
        ));
      }
    }

    // Build request using http::Request::builder, then convert to slinger::Request
    let mut request_builder = http::Request::builder()
      .method(method)
      .uri(uri)
      .version(Version::HTTP_11);

    // Parse headers
    for line in String::from_utf8_lossy(&headers_buf).lines() {
      if let Some(idx) = line.find(':') {
        let (name, value) = line.split_at(idx);
        let value = value[1..].trim();
        request_builder = request_builder.header(name.trim(), value);
      }
    }

    let http_request = request_builder.body(Bytes::new())?;
    let request: Request = http_request.into();

    // Process through interceptors and forward
    if let Some(response_bytes) =
      Self::forward_request_via_client(interceptor, &client, request, uri).await?
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

  /// Parse HTTP request from bytes
  fn parse_http_request(buffer: &[u8], domain: &str) -> Result<Request> {
    let request_str = String::from_utf8_lossy(buffer);
    let mut lines = request_str.lines();

    let request_line = lines
      .next()
      .ok_or_else(|| Error::invalid_request("Empty request".to_string()))?;
    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 3 {
      return Err(Error::invalid_request("Invalid request line".to_string()));
    }

    let method = parts[0];
    let path = parts[1];
    let uri = if path.starts_with("http://") || path.starts_with("https://") {
      path.to_string()
    } else {
      format!("https://{}{}", domain, path)
    };

    let mut request_builder = http::Request::builder()
      .method(method)
      .uri(uri)
      .version(Version::HTTP_11);

    for line in lines {
      if line.is_empty() {
        break;
      }
      if let Some(idx) = line.find(':') {
        let (name, value) = line.split_at(idx);
        let value = value[1..].trim();
        request_builder = request_builder.header(name.trim(), value);
      }
    }

    let http_request = request_builder.body(Bytes::new())?;
    Ok(http_request.into())
  }

  /// Serialize HTTP response to bytes
  fn serialize_http_response(response: &Response) -> Result<Vec<u8>> {
    let mut buf = Vec::new();

    // Status line
    let status = response.status_code();
    let status_line = format!(
      "HTTP/1.1 {} {}\r\n",
      status.as_u16(),
      status.canonical_reason().unwrap_or("Unknown")
    );
    buf.extend_from_slice(status_line.as_bytes());

    // Headers
    for (name, value) in response.headers() {
      buf.extend_from_slice(name.as_str().as_bytes());
      buf.extend_from_slice(b": ");
      buf.extend_from_slice(value.as_bytes());
      buf.extend_from_slice(b"\r\n");
    }
    // Empty line before body
    buf.extend_from_slice(b"\r\n");
    // Body
    if let Some(body) = response.body() {
      buf.extend_from_slice(body.as_ref());
    }
    Ok(buf)
  }
}
