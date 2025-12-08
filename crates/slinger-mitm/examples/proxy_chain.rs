//! MITM proxy with upstream proxy support
//!
//! This example demonstrates how to configure slinger-mitm to forward
//! traffic through an upstream proxy (HTTP, HTTPS, SOCKS5, or SOCKS5h).
//!
//! This is useful for chaining proxies or using slinger-mitm with tools
//! like Tor, corporate proxies, or other SOCKS5 proxies.
//!
//! To run:
//! ```bash
//! cargo run --example proxy_chain
//! ```
//!
//! Then configure your browser to use the proxy at 127.0.0.1:8080
//! Install the CA certificate from .slinger-mitm/ca_cert.pem
//!
//! ## Example proxy types:
//! - SOCKS5: socks5://127.0.0.1:1080
//! - SOCKS5h (with remote DNS): socks5h://127.0.0.1:1080
//! - HTTP: http://proxy.example.com:8080
//! - HTTPS: https://proxy.example.com:8443
//! - With authentication: socks5h://user:pass@127.0.0.1:1080

use slinger_mitm::{InterceptorFactory, MitmConfig, MitmProxy};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
  println!("=== Slinger MITM Proxy with Upstream Proxy ===\n");

  // Configure upstream proxy
  // Change this to your actual proxy address
  // Examples:
  // - For Tor: "socks5h://127.0.0.1:9050"
  // - For corporate proxy: "http://proxy.company.com:8080"
  // - For another SOCKS5 proxy: "socks5h://127.0.0.1:1080"
  //
  // Set to None to run without upstream proxy:
  // let upstream_proxy_url = None;
  let upstream_proxy_url = Some("http://127.0.0.1:8080");

  // Parse the proxy URL
  let proxy = match upstream_proxy_url {
    Some(url) => {
      let parsed = slinger::Proxy::parse(url)?;
      println!("✓ Configured upstream proxy: {}", url);
      Some(parsed)
    }
    None => {
      println!("ℹ Running without upstream proxy");
      None
    }
  };

  // Create MITM proxy configuration with upstream proxy
  let config = MitmConfig {
    ca_storage_path: std::path::PathBuf::from(".slinger-mitm"),
    enable_https_interception: true,
    enable_tcp_interception: false,
    max_connections: 1000,
    connection_timeout: 30,
    upstream_proxy: proxy,
  };

  let mitm_proxy = MitmProxy::new(config).await?;

  // Add a logging interceptor to see traffic
  let interceptor_handler = mitm_proxy.interceptor_handler();
  let mut handler = interceptor_handler.write().await;
  handler.add_interceptor(Arc::new(InterceptorFactory::logging()));
  drop(handler); // Release write lock

  // Start the proxy
  println!("\nStarting MITM proxy on 127.0.0.1:8080");
  println!("CA certificate: {}\n", mitm_proxy.ca_cert_path().display());
  println!("Traffic flow:");
  if let Some(proxy_url) = upstream_proxy_url {
    println!(
      "  Browser → MITM Proxy (127.0.0.1:8080) → Upstream Proxy ({}) → Internet\n",
      proxy_url
    );
  } else {
    println!("  Browser → MITM Proxy (127.0.0.1:8080) → Internet\n");
  }
  println!("To use this proxy:");
  println!("1. Configure your browser to use HTTP proxy: 127.0.0.1:8080");
  println!("2. Install the CA certificate in your browser/system");
  println!("3. Visit any HTTP/HTTPS website\n");

  mitm_proxy.start("127.0.0.1:2008").await?;

  Ok(())
}
