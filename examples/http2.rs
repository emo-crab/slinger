//! HTTP/2 example
//!
//! This example demonstrates HTTP/2 support with various stream types.
//! HTTP/2 can work with:
//! - Plain TCP connections (h2c - HTTP/2 over cleartext)
//! - TLS connections (with ALPN negotiation)
//!
//! Note: Most servers require TLS with ALPN to negotiate HTTP/2.
//! For testing h2c (HTTP/2 over cleartext), you need a server that supports it.

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
  #[cfg(all(feature = "http2", feature = "tls"))]
  {
    use slinger::ClientBuilder;
    // Example 2: HTTP/2 with standard TLS (rustls)
    println!("=== HTTP/2 with Rustls TLS ===");
    let client = ClientBuilder::default().enable_http2(true).build()?;
    // Note: Rustls doesn't support HTTP/2 ALPN by default in this configuration
    // This will likely fall back to HTTP/1.1
    let resp = client.get("https://httpbin.org/").send().await?;
    println!("Status: {}", resp.status_code());
    println!("Version: {:?}", resp.version());
    let body_len = resp.body().as_ref().map(|b| b.len()).unwrap_or(0);
    println!("Body length: {} bytes", body_len);
    println!();
  }
  Ok(())
}
