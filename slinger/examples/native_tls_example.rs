//! Example demonstrating how to implement native-tls support as a custom TLS connector
//!
//! This example shows how users can implement their own native-tls integration
//! using the unified CustomTlsConnector interface.
//!
//! To run this example:
//! ```bash
//! cargo run --example native_tls_example --features tls
//! ```
//!
//! Note: This example requires the `tls` feature.
//! The native-tls dependencies are available in dev-dependencies for examples.

#[cfg(feature = "tls")]
use slinger::tls::{CustomTlsConnector, CustomTlsStream, PeerCertificate};
#[cfg(feature = "tls")]
use slinger::{ConnectorBuilder, Result, Socket, StreamWrapper};
#[cfg(feature = "tls")]
use std::sync::Arc;
#[cfg(feature = "tls")]
use tokio::net::TcpStream;

#[cfg(feature = "tls")]
/// Wrapper for tokio-native-tls TlsStream that implements CustomTlsStream
/// Uses TlsStreamWrapper to automatically implement AsyncRead and AsyncWrite
struct NativeTlsStream {
  inner: tokio_native_tls::TlsStream<TcpStream>,
}

#[cfg(feature = "tls")]
impl NativeTlsStream {
  fn new(stream: tokio_native_tls::TlsStream<TcpStream>) -> Self {
    Self { inner: stream }
  }
}

#[cfg(feature = "tls")]
// Use the macro to implement AsyncRead and AsyncWrite by delegating to the inner TlsStreamWrapper
slinger::impl_tls_stream!(NativeTlsStream, inner);

#[cfg(feature = "tls")]
impl CustomTlsStream for NativeTlsStream {
  fn peer_certificate(&self) -> Option<Vec<PeerCertificate>> {
    let cert = self
      .inner
      .get_ref()
      .peer_certificate()
      .ok()??
      .to_der()
      .ok()?;

    Some(vec![PeerCertificate { inner: cert }])
  }

  fn alpn_protocol(&self) -> Option<Vec<u8>> {
    None
  }
}

#[cfg(feature = "tls")]
/// Native-TLS connector implementation
///
/// This demonstrates how to wrap tokio-native-tls to work with slinger's
/// CustomTlsConnector trait.
struct NativeTlsConnector {
  connector: tokio_native_tls::TlsConnector,
}

#[cfg(feature = "tls")]
impl NativeTlsConnector {
  fn new() -> std::result::Result<Self, Box<dyn std::error::Error>> {
    let mut builder = tokio_native_tls::native_tls::TlsConnector::builder();

    // Configure certificate verification
    builder.danger_accept_invalid_certs(false);
    builder.danger_accept_invalid_hostnames(false);

    // Optional: Configure TLS version
    builder.min_protocol_version(Some(tokio_native_tls::native_tls::Protocol::Tlsv12));

    // Optional: Add custom certificates
    // let cert = tokio_native_tls::native_tls::Certificate::from_pem(pem_bytes)?;
    // builder.add_root_certificate(cert);

    // Build the connector
    let connector = builder.build()?;

    Ok(Self {
      connector: tokio_native_tls::TlsConnector::from(connector),
    })
  }
}

#[cfg(feature = "tls")]
impl CustomTlsConnector for NativeTlsConnector {
  fn connect<'a>(
    &'a self,
    domain: &'a str,
    stream: Socket,
  ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Socket>> + Send + 'a>> {
    let connector = self.connector.clone();
    let domain = domain.to_string();

    Box::pin(async move {
      // Extract the TCP stream from the socket
      let tcp_stream = match stream.inner {
        StreamWrapper::Tcp(tcp) => tcp,
        _ => {
          return Err(slinger::Error::Other(
            "Expected plain TCP stream for TLS upgrade".to_string(),
          ));
        }
      };

      // Perform TLS handshake
      let tls_stream = connector
        .connect(&domain, tcp_stream)
        .await
        .map_err(|e| slinger::Error::Other(format!("native-tls handshake failed: {}", e)))?;

      // Wrap in NativeTlsStream which uses TlsStreamWrapper internally
      let custom_stream = NativeTlsStream::new(tls_stream);

      // Create a new socket with the TLS stream
      Ok(Socket::new(
        StreamWrapper::Custom(Box::new(custom_stream)),
        stream.read_timeout,
        stream.write_timeout,
      ))
    })
  }
}

#[cfg(feature = "tls")]
#[tokio::main]
async fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
  println!("Native-TLS Custom Connector Example");
  println!("====================================\n");

  // Create the native-tls connector
  let native_tls = Arc::new(NativeTlsConnector::new()?);
  println!("✓ Created native-tls connector");

  // Build a connector with the native-tls implementation
  let connector = ConnectorBuilder::default()
    .custom_tls_connector(native_tls)
    .build()?;

  println!("✓ Built connector with native-tls backend");

  // Test the connection
  println!("\nTesting connection to example.com...");
  let socket = connector
    .connect_with_uri(&http::Uri::from_static("https://example.com"))
    .await?;

  println!("✓ Successfully connected to example.com via HTTPS");

  // Try to get peer certificate
  if let Some(cert) = socket.inner.peer_certificate() {
    println!("✓ Retrieved peer certificate ({})", cert.len());
  } else {
    println!("✗ No peer certificate available");
  }

  println!("\nThis example demonstrates:");
  println!("1. Creating a custom TLS connector using native-tls");
  println!("2. Implementing the CustomTlsConnector trait");
  println!("3. Using impl_tls_stream! macro to avoid AsyncRead/AsyncWrite boilerplate");
  println!("4. Implementing only the CustomTlsStream trait for custom logic");
  println!("5. Using ConnectorBuilder to configure the connector");
  println!("6. Getting peer certificate information from the TLS connection");

  println!("\nKey implementation details:");
  println!("  - NativeTlsStream wraps TlsStreamWrapper<tokio_native_tls::TlsStream>");
  println!("  - impl_tls_stream! macro generates AsyncRead/AsyncWrite delegations");
  println!("  - No manual AsyncRead/AsyncWrite implementation needed");
  println!("  - Only CustomTlsStream trait needs custom implementation");
  println!("  - Clean and minimal code pattern");

  Ok(())
}

#[cfg(not(feature = "tls"))]
fn main() {
  eprintln!("This example requires the 'tls' feature.");
  eprintln!("Run with: cargo run --example native_tls_example --features tls");
}
