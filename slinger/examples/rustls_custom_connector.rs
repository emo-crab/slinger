//! Example demonstrating how to use rustls as a custom TLS connector
//!
//! This example shows that when the rustls feature is enabled, you can either:
//! 1. Use the default rustls implementation (automatic)
//! 2. Customize rustls settings and provide it as a custom connector
//!
//! To run this example:
//! ```bash
//! cargo run --example rustls_custom_connector --features rustls
//! ```

#[cfg(feature = "rustls")]
use slinger::tls::{rustls::RustlsTlsConnector, CustomTlsConnector};
#[cfg(feature = "rustls")]
use slinger::ConnectorBuilder;
#[cfg(feature = "rustls")]
use std::sync::Arc;

#[cfg(feature = "rustls")]
#[tokio::main]
async fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
  println!("Rustls Custom Connector Example");
  println!("================================\n");

  // Example 1: Using default rustls (automatic when rustls feature is enabled)
  println!("Example 1: Default rustls connector");
  println!("------------------------------------");
  let connector1 = ConnectorBuilder::default().build()?;
  println!("✓ Built connector with default rustls backend");

  // Test connection
  let socket1 = connector1
    .connect_with_uri(&http::Uri::from_static("https://www.rust-lang.org"))
    .await?;
  println!("✓ Successfully connected to rust-lang.org\n");
  drop(socket1);

  // Example 2: Creating a custom rustls connector with specific settings
  println!("Example 2: Custom rustls connector with specific settings");
  println!("----------------------------------------------------------");

  // Build a rustls connector with custom settings
  let custom_rustls = {
    use tokio_rustls::rustls;

    let mut root_cert_store = rustls::RootCertStore::empty();
    let certs = rustls_native_certs::load_native_certs().certs;
    for cert in certs {
      root_cert_store.add(cert)?;
    }

    let provider = rustls::crypto::CryptoProvider::get_default()
      .cloned()
      .unwrap_or_else(|| Arc::new(rustls::crypto::ring::default_provider()));

    let config = rustls::ClientConfig::builder_with_provider(provider)
      .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])?
      .with_root_certificates(root_cert_store)
      .with_no_client_auth();

    let rustls_connector = tokio_rustls::TlsConnector::from(Arc::new(config));

    // Wrap in RustlsTlsConnector
    Arc::new(RustlsTlsConnector::new(
      rustls_connector,
      Some(std::time::Duration::from_secs(30)),
    )) as Arc<dyn CustomTlsConnector>
  };

  // Use the custom rustls connector
  let connector2 = ConnectorBuilder::default()
    .custom_tls_connector(custom_rustls)
    .build()?;

  println!("✓ Built connector with custom rustls settings");

  // Test connection
  let socket2 = connector2
    .connect_with_uri(&http::Uri::from_static("https://www.rust-lang.org"))
    .await?;
  println!("✓ Successfully connected to rust-lang.org with custom rustls\n");
  drop(socket2);

  println!("Key points:");
  println!("1. When rustls feature is enabled, default connector uses RustlsTlsConnector");
  println!("2. You can create custom rustls settings and wrap them in RustlsTlsConnector");
  println!("3. RustlsTlsConnector implements CustomTlsConnector trait");
  println!("4. This provides a unified interface for all TLS implementations");
  println!("5. Users can easily switch between rustls, native-tls, or other TLS libraries");

  Ok(())
}

#[cfg(not(feature = "rustls"))]
fn main() {
  eprintln!("This example requires the 'rustls' feature.");
  eprintln!("Run with: cargo run --example rustls_custom_connector --features rustls");
}
