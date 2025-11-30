//! Traffic interception and modification interfaces

use crate::error::Result;
use bytes::Bytes;
use slinger::{Body, Request, Response};
use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// MITM Request wrapper that wraps slinger::Request with connection metadata.
/// Used for both HTTP and non-HTTP (raw TCP) traffic interception.
#[derive(Clone)]
pub struct MitmRequest {
  /// Source address and port (client)
  pub source: Option<SocketAddr>,
  /// Destination address (host:port)
  pub destination: String,
  /// Timestamp when the request was intercepted
  pub timestamp: u64,
  /// Whether this is an HTTP request (true) or raw TCP (false)
  is_http: bool,
  /// The underlying request (contains body for both HTTP and raw TCP)
  pub request: Request,
}

impl MitmRequest {
  /// Create a new MITM request wrapper for HTTP traffic
  pub fn new(destination: impl Into<String>, request: Request) -> Self {
    Self {
      source: None,
      destination: destination.into(),
      timestamp: SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0),
      is_http: true,
      request,
    }
  }

  /// Create a new MITM request with source address for HTTP traffic
  pub fn with_source(source: SocketAddr, destination: impl Into<String>, request: Request) -> Self {
    Self {
      source: Some(source),
      destination: destination.into(),
      timestamp: SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0),
      is_http: true,
      request,
    }
  }

  /// Create a MITM request for raw TCP data (non-HTTP)
  pub fn raw_tcp(destination: impl Into<String>, body: impl Into<Bytes>) -> Self {
    let request = Request {
      body: Some(Body::from(body.into())),
      ..Default::default()
    };
    Self {
      source: None,
      destination: destination.into(),
      timestamp: SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0),
      is_http: false,
      request,
    }
  }

  /// Create a MITM request for raw TCP data with source address
  pub fn raw_tcp_with_source(
    source: SocketAddr,
    destination: impl Into<String>,
    body: impl Into<Bytes>,
  ) -> Self {
    let request = Request {
      body: Some(Body::from(body.into())),
      ..Default::default()
    };
    Self {
      source: Some(source),
      destination: destination.into(),
      timestamp: SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0),
      is_http: false,
      request,
    }
  }

  /// Get the source address
  pub fn source(&self) -> Option<SocketAddr> {
    self.source
  }

  /// Get the destination address
  pub fn destination(&self) -> &str {
    &self.destination
  }

  /// Get the timestamp
  pub fn timestamp(&self) -> u64 {
    self.timestamp
  }

  /// Get the underlying request
  pub fn request(&self) -> &Request {
    &self.request
  }

  /// Get a mutable reference to the underlying request
  pub fn request_mut(&mut self) -> &mut Request {
    &mut self.request
  }

  /// Get the body as bytes (for raw TCP traffic)
  pub fn body(&self) -> Option<&Body> {
    self.request.body.as_ref()
  }

  /// Set the body (for raw TCP traffic)
  pub fn set_body(&mut self, body: impl Into<Bytes>) {
    self.request.body = Some(Body::from(body.into()));
  }

  /// Check if this is an HTTP request (true) or raw TCP (false)
  pub fn is_http(&self) -> bool {
    self.is_http
  }
}

impl fmt::Debug for MitmRequest {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("MitmRequest")
      .field("source", &self.source)
      .field("destination", &self.destination)
      .field("timestamp", &self.timestamp)
      .field("is_http", &self.is_http())
      .field("request", &self.request)
      .finish()
  }
}

/// MITM Response wrapper that wraps slinger::Response with connection metadata.
/// Used for both HTTP and non-HTTP (raw TCP) traffic interception.
#[derive(Clone)]
pub struct MitmResponse {
  /// Source address (where the response came from, host:port)
  pub source: String,
  /// Destination address and port (client)
  pub destination: Option<SocketAddr>,
  /// Timestamp when the response was intercepted
  pub timestamp: u64,
  /// Whether this is an HTTP response (true) or raw TCP (false)
  is_http: bool,
  /// The underlying response (contains body for both HTTP and raw TCP)
  pub response: Response,
}

impl MitmResponse {
  /// Create a new MITM response wrapper for HTTP traffic
  pub fn new(source: impl Into<String>, response: Response) -> Self {
    Self {
      source: source.into(),
      destination: None,
      timestamp: SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0),
      is_http: true,
      response,
    }
  }

  /// Create a new MITM response with destination address for HTTP traffic
  pub fn with_destination(
    source: impl Into<String>,
    destination: SocketAddr,
    response: Response,
  ) -> Self {
    Self {
      source: source.into(),
      destination: Some(destination),
      timestamp: SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0),
      is_http: true,
      response,
    }
  }

  /// Create a MITM response for raw TCP data (non-HTTP)
  pub fn raw_tcp(source: impl Into<String>, body: impl Into<Bytes>) -> Self {
    let response = Response {
      body: Some(Body::from(body.into())),
      ..Default::default()
    };
    Self {
      source: source.into(),
      destination: None,
      timestamp: SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0),
      is_http: false,
      response,
    }
  }

  /// Create a MITM response for raw TCP data with destination address
  pub fn raw_tcp_with_destination(
    source: impl Into<String>,
    destination: SocketAddr,
    body: impl Into<Bytes>,
  ) -> Self {
    let response = Response {
      body: Some(Body::from(body.into())),
      ..Default::default()
    };
    Self {
      source: source.into(),
      destination: Some(destination),
      timestamp: SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0),
      is_http: false,
      response,
    }
  }

  /// Get the source address
  pub fn source(&self) -> &str {
    &self.source
  }

  /// Get the destination address
  pub fn destination(&self) -> Option<SocketAddr> {
    self.destination
  }

  /// Get the timestamp
  pub fn timestamp(&self) -> u64 {
    self.timestamp
  }

  /// Get the underlying response
  pub fn response(&self) -> &Response {
    &self.response
  }

  /// Get a mutable reference to the underlying response
  pub fn response_mut(&mut self) -> &mut Response {
    &mut self.response
  }

  /// Get the body as bytes (for raw TCP traffic)
  pub fn body(&self) -> Option<&Body> {
    self.response.body.as_ref()
  }

  /// Set the body (for raw TCP traffic)
  pub fn set_body(&mut self, body: impl Into<Bytes>) {
    self.response.body = Some(Body::from(body.into()));
  }

  /// Check if this is an HTTP response (true) or raw TCP (false)
  pub fn is_http(&self) -> bool {
    self.is_http
  }
}

impl fmt::Debug for MitmResponse {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("MitmResponse")
      .field("source", &self.source)
      .field("destination", &self.destination)
      .field("timestamp", &self.timestamp)
      .field("is_http", &self.is_http())
      .field("response", &self.response)
      .finish()
  }
}

/// Trait for intercepting and modifying requests (both HTTP and raw TCP)
#[async_trait::async_trait]
pub trait RequestInterceptor: Send + Sync {
  /// Intercept and optionally modify a request
  ///
  /// Return `None` to block the request, or return a modified request
  async fn intercept_request(&self, request: MitmRequest) -> Result<Option<MitmRequest>>;
}

/// Trait for intercepting and modifying responses (both HTTP and raw TCP)
#[async_trait::async_trait]
pub trait ResponseInterceptor: Send + Sync {
  /// Intercept and optionally modify a response
  ///
  /// Return `None` to block the response, or return a modified response
  async fn intercept_response(&self, response: MitmResponse) -> Result<Option<MitmResponse>>;
}

/// Combined interceptor handler for both HTTP and TCP traffic
pub struct InterceptorHandler {
  request_interceptors: Vec<Arc<dyn RequestInterceptor>>,
  response_interceptors: Vec<Arc<dyn ResponseInterceptor>>,
}

impl InterceptorHandler {
  /// Create a new interceptor handler
  pub fn new() -> Self {
    Self {
      request_interceptors: Vec::new(),
      response_interceptors: Vec::new(),
    }
  }

  /// Add a request interceptor
  pub fn add_request_interceptor(&mut self, interceptor: Arc<dyn RequestInterceptor>) {
    self.request_interceptors.push(interceptor);
  }

  /// Add a response interceptor
  pub fn add_response_interceptor(&mut self, interceptor: Arc<dyn ResponseInterceptor>) {
    self.response_interceptors.push(interceptor);
  }

  /// Process a request through all interceptors
  pub async fn process_request(&self, mut request: MitmRequest) -> Result<Option<MitmRequest>> {
    for interceptor in &self.request_interceptors {
      match interceptor.intercept_request(request).await? {
        Some(modified) => request = modified,
        None => return Ok(None), // Request blocked
      }
    }
    Ok(Some(request))
  }

  /// Process a response through all interceptors
  pub async fn process_response(&self, mut response: MitmResponse) -> Result<Option<MitmResponse>> {
    for interceptor in &self.response_interceptors {
      match interceptor.intercept_response(response).await? {
        Some(modified) => response = modified,
        None => return Ok(None), // Response blocked
      }
    }
    Ok(Some(response))
  }

  /// Check if any interceptors are registered
  pub fn has_interceptors(&self) -> bool {
    !self.request_interceptors.is_empty() || !self.response_interceptors.is_empty()
  }
}

impl Default for InterceptorHandler {
  fn default() -> Self {
    Self::new()
  }
}

/// Default pass-through interceptor
pub struct Interceptor;

impl Interceptor {
  /// Create a logging interceptor that prints requests/responses
  pub fn logging() -> LoggingInterceptor {
    LoggingInterceptor
  }
}

/// Logging interceptor implementation that handles both HTTP and TCP traffic
pub struct LoggingInterceptor;

#[async_trait::async_trait]
impl RequestInterceptor for LoggingInterceptor {
  async fn intercept_request(&self, request: MitmRequest) -> Result<Option<MitmRequest>> {
    if request.is_http() {
      tracing::info!(
        "[MITM] HTTP Request: {} {}",
        request.request().method(),
        request.request().uri()
      );
      for (name, value) in request.request().headers() {
        tracing::info!("  {}: {:?}", name, value);
      }
    } else {
      tracing::info!(
        "[MITM] TCP Request to {}: {} bytes",
        request.destination(),
        request.body().map(|b| b.len()).unwrap_or(0)
      );
    }
    if let Some(source) = request.source() {
      tracing::info!("  From: {}", source);
    }
    tracing::info!("  Timestamp: {}", request.timestamp());
    Ok(Some(request))
  }
}

#[async_trait::async_trait]
impl ResponseInterceptor for LoggingInterceptor {
  async fn intercept_response(&self, response: MitmResponse) -> Result<Option<MitmResponse>> {
    if response.is_http() {
      tracing::info!(
        "[MITM] HTTP Response: {}",
        response.response().status_code()
      );
      for (name, value) in response.response().headers() {
        tracing::info!("  {}: {:?}", name, value);
      }
    } else {
      tracing::info!(
        "[MITM] TCP Response from {}: {} bytes",
        response.source(),
        response.body().map(|b| b.len()).unwrap_or(0)
      );
    }
    if let Some(destination) = response.destination() {
      tracing::info!("  To: {}", destination);
    }
    tracing::info!("  Timestamp: {}", response.timestamp());
    Ok(Some(response))
  }
}
