//! MITM Proxy configuration and main proxy implementation

use crate::ca::CertificateManager;
use crate::error::Result;
use crate::interceptor::InterceptorHandler;
use crate::server::ProxyServer;
use slinger::Proxy;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Configuration for MITM proxy
#[derive(Clone)]
pub struct MitmConfig {
  /// Path to store CA certificates
  pub ca_storage_path: PathBuf,
  /// Enable HTTPS interception
  pub enable_https_interception: bool,
  /// Maximum concurrent connections
  pub max_connections: usize,
  /// Connection timeout in seconds
  pub connection_timeout: u64,
  /// Optional upstream proxy (supports HTTP, HTTPS, SOCKS5, SOCKS5h)
  /// Example: "<socks5h://127.0.0.1:1080>" or "<http://proxy.example.com:8080>"
  pub upstream_proxy: Option<Proxy>,
}

impl Default for MitmConfig {
  fn default() -> Self {
    Self {
      ca_storage_path: PathBuf::from(".slinger-mitm"),
      enable_https_interception: true,
      max_connections: 1000,
      connection_timeout: 30,
      upstream_proxy: None,
    }
  }
}

/// MITM Proxy main struct
pub struct MitmProxy {
  config: MitmConfig,
  cert_manager: Arc<CertificateManager>,
  interceptor_handler: Arc<RwLock<InterceptorHandler>>,
}

impl MitmProxy {
  /// Create a new MITM proxy with the given configuration
  pub async fn new(config: MitmConfig) -> Result<Self> {
    let cert_manager = Arc::new(CertificateManager::new(&config.ca_storage_path).await?);
    let interceptor_handler = Arc::new(RwLock::new(InterceptorHandler::new()));

    Ok(Self {
      config,
      cert_manager,
      interceptor_handler,
    })
  }

  /// Create a new MITM proxy with default configuration
  pub async fn default() -> Result<Self> {
    Self::new(MitmConfig::default()).await
  }

  /// Get the CA certificate in PEM format
  ///
  /// This certificate should be installed in the client's trust store
  pub fn ca_cert_pem(&self) -> Result<String> {
    self.cert_manager.ca_cert_pem()
  }

  /// Get the CA certificate path
  pub fn ca_cert_path(&self) -> PathBuf {
    self.cert_manager.ca_cert_path()
  }

  /// Get a reference to the interceptor handler
  pub fn interceptor_handler(&self) -> Arc<RwLock<InterceptorHandler>> {
    self.interceptor_handler.clone()
  }

  /// Start the MITM proxy server on the given address
  pub async fn start(&self, addr: &str) -> Result<()> {
    let server = ProxyServer::new(
      self.config.clone(),
      self.cert_manager.clone(),
      self.interceptor_handler.clone(),
    )?;
    server.run(addr).await
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[tokio::test]
  async fn test_mitm_proxy_creation() {
    let config = MitmConfig {
      ca_storage_path: PathBuf::from("/tmp/test-mitm-ca"),
      ..Default::default()
    };

    let proxy = MitmProxy::new(config).await;
    assert!(proxy.is_ok());

    if let Ok(p) = proxy {
      let ca_pem = p.ca_cert_pem();
      assert!(ca_pem.is_ok());
    }
  }
}
