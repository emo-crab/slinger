//! SOCKS5 proxy example
//!
//! This example demonstrates how the MITM proxy can work as a SOCKS5 server
//! in addition to HTTP proxy. The server automatically detects the protocol.
//!
//! To run:
//! ```bash
//! cargo run --example socks5_proxy
//! ```
//!
//! Then configure your application to use SOCKS5 proxy at 127.0.0.1:1080
//! The proxy will handle both SOCKS5 and HTTP proxy connections on the same port

use slinger_mitm::{InterceptorFactory, MitmConfig, MitmProxy};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
  println!("=== Slinger MITM Proxy (HTTP + SOCKS5) ===\n");

  // Create proxy with default configuration
  let config = MitmConfig::default();
  let proxy = MitmProxy::new(config).await?;

  // Add a logging interceptor to see traffic
  let interceptor_handler = proxy.interceptor_handler();
  let mut handler = interceptor_handler.write().await;
  handler.add_interceptor(Arc::new(InterceptorFactory::logging()));
  drop(handler); // Release write lock

  // Start the proxy
  println!("Starting MITM proxy on 127.0.0.1:1080");
  println!("CA certificate: {}\n", proxy.ca_cert_path().display());
  println!("This proxy supports:");
  println!("  - HTTP proxy protocol (CONNECT method)");
  println!("  - SOCKS5 protocol");
  println!("  - Automatic protocol detection\n");
  println!("To use this proxy:");
  println!("1. Configure your application to use SOCKS5 proxy: 127.0.0.1:1080");
  println!("   OR HTTP proxy: 127.0.0.1:1080");
  println!("2. For HTTPS interception, install the CA certificate\n");

  proxy.start("127.0.0.1:1080").await?;

  Ok(())
}
