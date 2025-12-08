//! TCP traffic interception example
//!
//! This example demonstrates how to intercept and modify raw TCP traffic
//! (non-HTTP) using the slinger-mitm proxy. This is similar to InterceptSuite's
//! TCP/TLS interception capability.
//!
//! To run:
//! ```bash
//! cargo run --example tcp_interceptor
//! ```
//!
//! Then configure your application to use the SOCKS5 proxy at 127.0.0.1:4444
//!
//! Features demonstrated:
//! - Intercepting raw TCP request data
//! - Modifying TCP request data before forwarding
//! - Intercepting raw TCP response data
//! - Modifying TCP response data before returning to client
//! - Using session_id to correlate requests and responses

use async_trait::async_trait;
use slinger_mitm::{Interceptor, InterceptorFactory, MitmConfig, MitmProxy, MitmRequest, MitmResponse, Result};
use std::sync::Arc;

/// Custom interceptor that logs and optionally modifies requests/responses
struct CustomInterceptor;

#[async_trait]
impl Interceptor for CustomInterceptor {
  async fn intercept_request(&self, request: MitmRequest) -> Result<Option<MitmRequest>> {
    // session_id allows you to correlate this request with its response
    println!("[REQ] Session ID: {}", request.session_id());
    println!("[REQ] Destination: {}", request.destination());
    if let Some(source) = request.source() {
      println!("[REQ] Source: {}", source);
    }
    println!("[REQ] Timestamp: {}", request.timestamp());
    println!("[REQ] Is HTTP: {}", request.is_http());

    if request.is_http() {
      println!("[REQ] HTTP Method: {}", request.request().method());
      println!("[REQ] HTTP URI: {}", request.request().uri());
    } else {
      println!(
        "[REQ] Body length: {} bytes",
        request.body().map(|b| b.len()).unwrap_or(0)
      );
      // Log the raw data (first 100 bytes)
      if let Some(body) = request.body() {
        println!("[REQ] Data preview: {:?}", body);
      }
    }

    println!("---");
    Ok(Some(request))
  }
  async fn intercept_response(&self, response: MitmResponse) -> Result<Option<MitmResponse>> {
    // session_id allows you to correlate this response with its original request
    println!("[RSP] Session ID: {}", response.session_id());
    println!("[RSP] Source: {}", response.source());
    if let Some(destination) = response.destination() {
      println!("[RSP] Destination: {}", destination);
    }
    println!("[RSP] Timestamp: {}", response.timestamp());
    println!("[RSP] Is HTTP: {}", response.is_http());

    if response.is_http() {
      println!("[RSP] HTTP Status: {}", response.response().status_code());
    } else {
      println!(
        "[RSP] Body length: {} bytes",
        response.body().map(|b| b.len()).unwrap_or(0)
      );
      // Log the raw data (first 100 bytes)
      if let Some(body) = response.body() {
        println!("[RSP] Data preview: {:?}", body);
      }
    }

    println!("---");
    Ok(Some(response))
  }
}

#[tokio::main]
async fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
  println!("=== Slinger MITM Proxy with Unified Traffic Interception ===\n");

  // Create proxy with TCP interception enabled
  let config = MitmConfig {
    ca_storage_path: std::path::PathBuf::from(".slinger-mitm"),
    enable_https_interception: false, // Disable HTTPS interception for raw TCP mode
    enable_tcp_interception: true,    // Enable TCP interception
    max_connections: 1000,
    connection_timeout: 30,
    upstream_proxy: None,
  };

  let proxy = MitmProxy::new(config).await?;

  // Add interceptors
  let interceptor_handler = proxy.interceptor_handler();
  let mut handler = interceptor_handler.write().await;

  // Add HTTP interceptors (for HTTP traffic if any)
  handler.add_interceptor(Arc::new(InterceptorFactory::logging()));
  // Add custom interceptor for both HTTP and TCP traffic
  handler.add_interceptor(Arc::new(CustomInterceptor));
  drop(handler); // Release write lock

  // Start the proxy
  println!("Starting MITM proxy with TCP interception on 127.0.0.1:4444");
  println!("CA certificate: {}\n", proxy.ca_cert_path().display());
  println!("To use this proxy for traffic interception:");
  println!("1. Configure your application to use SOCKS5 proxy: 127.0.0.1:4444");
  println!("2. The proxy will intercept and log all traffic (HTTP and raw TCP)");
  println!("3. Request/response data with metadata will be shown in the console\n");
  println!("Features:");
  println!("- MitmRequest/MitmResponse contain: session_id, source/destination, timestamp, body");
  println!("- session_id allows you to correlate requests with their responses");
  println!("- Same interceptor handles both HTTP and non-HTTP protocols");
  println!("- Use is_http() to detect protocol type\n");

  proxy.start("127.0.0.1:1080").await?;

  Ok(())
}
