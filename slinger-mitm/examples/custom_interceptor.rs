//! MITM proxy with custom traffic modification
//!
//! This example demonstrates how to create custom interceptors
//! to modify HTTP requests and responses.
//!
//! To run:
//! ```bash
//! cargo run --example custom_interceptor
//! ```

use async_trait::async_trait;
use http::HeaderValue;
use slinger_mitm::{MitmConfig, MitmProxy, MitmRequest, MitmResponse, RequestInterceptor, ResponseInterceptor, Result};
use std::sync::Arc;

/// Custom request interceptor that adds a custom header
struct CustomHeaderInterceptor;

#[async_trait]
impl RequestInterceptor for CustomHeaderInterceptor {
  async fn intercept_request(&self, mut request: MitmRequest) -> Result<Option<MitmRequest>> {
    println!("[CUSTOM] Intercepting request to: {}", request.destination());
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
}

/// Custom response interceptor that modifies response headers
struct ResponseModifierInterceptor;

#[async_trait]
impl ResponseInterceptor for ResponseModifierInterceptor {
  async fn intercept_response(&self, mut response: MitmResponse) -> Result<Option<MitmResponse>> {
    println!("[CUSTOM] Intercepting response from: {}", response.source());
    println!("[CUSTOM] Timestamp: {}", response.timestamp());

    if response.is_http() {
      println!("[CUSTOM] HTTP Status: {}", response.response().status_code());
      
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
    ca_storage_path: std::path::PathBuf::from(".slinger-mitm-custom"),
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

  // Add our custom interceptors
  handler.add_request_interceptor(Arc::new(CustomHeaderInterceptor));
  handler.add_response_interceptor(Arc::new(ResponseModifierInterceptor));

  drop(handler); // Release write lock

  // Start the proxy
  println!("Starting MITM proxy on 127.0.0.1:8888");
  println!("CA certificate: {}\n", proxy.ca_cert_path().display());
  println!("This proxy will:");
  println!("  - Add X-Slinger-MITM header to all requests");
  println!("  - Modify User-Agent header");
  println!("  - Add X-Slinger-MITM-Response header to all responses\n");

  proxy.start("127.0.0.1:8888").await?;

  Ok(())
}
