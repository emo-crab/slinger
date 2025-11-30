//! Simple MITM proxy example
//!
//! This example demonstrates how to start a basic MITM proxy server
//! with logging interceptor.
//!
//! To run:
//! ```bash
//! cargo run --example simple_proxy
//! ```
//!
//! Then configure your browser to use the proxy at 127.0.0.1:8080
//! Install the CA certificate from .slinger-mitm/ca_cert.pem

use slinger_mitm::{Interceptor, MitmConfig, MitmProxy};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
  println!("=== Slinger MITM Proxy ===\n");

  // Create proxy with default configuration
  let config = MitmConfig::default();
  let proxy = MitmProxy::new(config).await?;

  // Add a logging interceptor to see traffic
  let interceptor_handler = proxy.interceptor_handler();
  let mut handler = interceptor_handler.write().await;
  handler.add_request_interceptor(Arc::new(Interceptor::logging()));
  handler.add_response_interceptor(Arc::new(Interceptor::logging()));
  drop(handler); // Release write lock

  // Start the proxy
  println!("Starting MITM proxy on 127.0.0.1:8080");
  println!("CA certificate: {}\n", proxy.ca_cert_path().display());
  println!("To use this proxy:");
  println!("1. Configure your browser to use HTTP proxy: 127.0.0.1:8080");
  println!("2. Install the CA certificate in your browser/system");
  println!("3. Visit any HTTP/HTTPS website\n");

  proxy.start("127.0.0.1:2008").await?;

  Ok(())
}
