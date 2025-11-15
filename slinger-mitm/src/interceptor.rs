//! Traffic interception and modification interfaces

use crate::error::Result;
use slinger::{Request, Response};
use std::sync::Arc;

/// Trait for intercepting and modifying HTTP requests
#[async_trait::async_trait]
pub trait RequestInterceptor: Send + Sync {
  /// Intercept and optionally modify an HTTP request
  ///
  /// Return `None` to block the request, or return a modified request
  async fn intercept_request(&self, request: Request) -> Result<Option<Request>>;
}

/// Trait for intercepting and modifying HTTP responses
#[async_trait::async_trait]
pub trait ResponseInterceptor: Send + Sync {
  /// Intercept and optionally modify an HTTP response
  ///
  /// Return `None` to block the response, or return a modified response
  async fn intercept_response(&self, response: Response) -> Result<Option<Response>>;
}

/// Combined interceptor handler
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
  pub async fn process_request(&self, mut request: Request) -> Result<Option<Request>> {
    for interceptor in &self.request_interceptors {
      match interceptor.intercept_request(request).await? {
        Some(modified) => request = modified,
        None => return Ok(None), // Request blocked
      }
    }
    Ok(Some(request))
  }

  /// Process a response through all interceptors
  pub async fn process_response(&self, mut response: Response) -> Result<Option<Response>> {
    for interceptor in &self.response_interceptors {
      match interceptor.intercept_response(response).await? {
        Some(modified) => response = modified,
        None => return Ok(None), // Response blocked
      }
    }
    Ok(Some(response))
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

/// Logging interceptor implementation
pub struct LoggingInterceptor;

#[async_trait::async_trait]
impl RequestInterceptor for LoggingInterceptor {
  async fn intercept_request(&self, request: Request) -> Result<Option<Request>> {
    println!("[MITM] Request: {} {}", request.method(), request.uri());
    for (name, value) in request.headers() {
      println!("  {}: {:?}", name, value);
    }
    Ok(Some(request))
  }
}

#[async_trait::async_trait]
impl ResponseInterceptor for LoggingInterceptor {
  async fn intercept_response(&self, response: Response) -> Result<Option<Response>> {
    println!("[MITM] Response: {}", response.status_code());
    for (name, value) in response.headers() {
      println!("  {}: {:?}", name, value);
    }
    // println!("[MITM] Response Body: {:?}", response.body());
    Ok(Some(response))
  }
}
