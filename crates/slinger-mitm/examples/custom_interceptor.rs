//! MITM proxy with custom traffic modification
//!
//! This example demonstrates how to create custom interceptors
//! to modify HTTP requests and responses, and how to use session_id
//! to correlate requests with their responses.
//!
//! To run:
//! ```bash
//! cargo run --example custom_interceptor
//! ```

use async_trait::async_trait;
use http::HeaderValue;
use slinger_mitm::{
  Interceptor, MitmConfig, MitmProxy, MitmRequest, MitmResponse, Result,
};
use std::sync::Arc;

/// Unified custom interceptor that handles both requests and responses
/// This is the recommended approach - using the Interceptor trait
struct UnifiedCustomInterceptor;

#[async_trait]
impl Interceptor for UnifiedCustomInterceptor {
  async fn intercept_request(&self, mut request: MitmRequest) -> Result<Option<MitmRequest>> {
    // Session ID is automatically managed - correlates with the response
    println!(
      "[UNIFIED] Intercepting request (session_id={}) to: {}",
      request.session_id(),
      request.destination()
    );

    if request.is_http() {
      request
        .request_mut()
        .headers_mut()
        .insert("X-Slinger-Unified", HeaderValue::from_static("true"));
    }

    Ok(Some(request))
  }

  async fn intercept_response(&self, mut response: MitmResponse) -> Result<Option<MitmResponse>> {
    // This response's session_id matches the request's session_id automatically
    println!(
      "[UNIFIED] Intercepting response (session_id={}) from: {}",
      response.session_id(),
      response.source()
    );

    if response.is_http() {
      response.response_mut().headers_mut().insert(
        "X-Slinger-Unified-Response",
        HeaderValue::from_static("modified"),
      );
    }

    Ok(Some(response))
  }
}

/// Legacy custom request interceptor (for backward compatibility example)
struct CustomHeaderInterceptor;

#[async_trait]
impl Interceptor for CustomHeaderInterceptor {
  async fn intercept_request(&self, mut request: MitmRequest) -> Result<Option<MitmRequest>> {
    // Use session_id to track and correlate this request with its response
    println!(
      "[CUSTOM] Intercepting request (session_id={}) to: {}",
      request.session_id(),
      request.destination()
    );
    println!("[CUSTOM] Timestamp: {}", request.timestamp());

    if request.is_http() {
      // Add a custom header
      request
        .request_mut()
        .headers_mut()
        .insert("X-Slinger-MITM", HeaderValue::from_static("true"));

      // Modify User-Agent
      if request.request().headers().contains_key("User-Agent") {
        request.request_mut().headers_mut().insert(
          "User-Agent",
          HeaderValue::from_static("Slinger-MITM-Proxy/1.0"),
        );
      }
    }

    Ok(Some(request))
  }
  async fn intercept_response(&self, mut response: MitmResponse) -> Result<Option<MitmResponse>> {
    // Use session_id to correlate this response with its original request
    println!(
      "[CUSTOM] Intercepting response (session_id={}) from: {}",
      response.session_id(),
      response.source()
    );
    println!("[CUSTOM] Timestamp: {}", response.timestamp());

    if response.is_http() {
      println!(
        "[CUSTOM] HTTP Status: {}",
        response.response().status_code()
      );

      // Add a custom header to the response
      response.response_mut().headers_mut().insert(
        "X-Slinger-MITM-Response",
        HeaderValue::from_static("modified"),
      );
    }

    Ok(Some(response))
  }
}


#[tokio::main]
async fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
  println!("=== Slinger MITM Proxy with Custom Interceptors ===\n");

  // Create proxy with custom storage path
  let config = MitmConfig {
    ca_storage_path: std::path::PathBuf::from(".slinger-mitm"),
    enable_https_interception: true,
    enable_tcp_interception: false,
    max_connections: 1000,
    connection_timeout: 30,
    upstream_proxy: None,
  };

  let proxy = MitmProxy::new(config).await?;

  // Add custom interceptors
  let interceptor_handler = proxy.interceptor_handler();
  let mut handler = interceptor_handler.write().await;

  // Recommended: Use unified interceptor (handles both request and response)
  // Note: In production, use either unified OR legacy interceptors, not both.
  // This example shows both approaches for demonstration purposes.
  println!("Adding unified interceptor (recommended approach)");
  handler.add_interceptor(Arc::new(UnifiedCustomInterceptor));
  handler.add_interceptor(Arc::new(CustomHeaderInterceptor));

  // Legacy: Separate request and response interceptors (for backward compatibility)
  // Uncomment below if you need to use legacy interceptors instead:
  // println!("Adding legacy separate interceptors (backward compatibility)");
  // handler.add_request_interceptor(Arc::new(CustomHeaderInterceptor));
  // handler.add_response_interceptor(Arc::new(ResponseModifierInterceptor));

  drop(handler); // Release write lock

  // Start the proxy
  println!("Starting MITM proxy on 127.0.0.1:8888");
  println!("CA certificate: {}\n", proxy.ca_cert_path().display());
  println!("This proxy demonstrates:");
  println!("  - Unified Interceptor (recommended): Handles both req & resp with automatic session correlation");
  println!("  - Legacy separate interceptors: For backward compatibility");
  println!("  - Session IDs automatically correlate requests with their responses");
  println!("  - Custom headers added to demonstrate interception\n");

  proxy.start("127.0.0.1:8888").await?;

  Ok(())
}
