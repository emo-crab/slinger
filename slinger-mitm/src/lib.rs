//! MITM Proxy with Transparent Traffic Interception
//!
//! This crate provides a man-in-the-middle (MITM) proxy implementation similar to Burp Suite,
//! allowing transparent interception and modification of HTTP/HTTPS traffic.
//!
//! # Features
//!
//! - Automatic CA certificate generation
//! - Transparent HTTPS interception using rustls backend
//! - Traffic interception and modification interfaces
//! - Reuses slinger's Socket implementation
//!
//! # Example
//!
//! ```no_run
//! use slinger_mitm::{MitmProxy, MitmConfig};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let config = MitmConfig::default();
//!     let proxy = MitmProxy::new(config).await?;
//!     proxy.start("127.0.0.1:8080").await?;
//!     Ok(())
//! }
//! ```

mod ca;
mod error;
mod interceptor;
mod proxy;
mod server;
mod socks5;

pub use ca::{CertificateAuthority, CertificateManager};
pub use error::{Error, Result};
pub use interceptor::{Interceptor, InterceptorHandler, RequestInterceptor, ResponseInterceptor};
pub use proxy::{MitmConfig, MitmProxy};
pub use server::{ProxyServer, ProxyServerBuilder};
pub use socks5::{Socks5Server, TargetAddr};

#[cfg(test)]
mod tests {
  #[test]
  fn it_works() {
    let result = 2 + 2;
    assert_eq!(result, 4);
  }
}
