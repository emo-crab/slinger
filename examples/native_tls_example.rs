//! Example demonstrating how to implement native-tls support as a custom TLS connector
//!
//! This example shows how users can implement their own native-tls integration
//! when the built-in native-tls feature has been removed from the main library.
//!
//! To run this example:
//! ```bash
//! cargo run --example native_tls_example --features tls
//! ```
//!
//! Note: This example requires the `tls` feature without `rustls`.
//! The native-tls dependencies are available in dev-dependencies for examples.

#[cfg(all(feature = "tls", not(feature = "rustls")))]
use slinger::{
  ConnectorBuilder, CustomTlsConnector, CustomTlsStream, MaybeTlsStream, PeerCertificate, Result,
  Socket,
};
#[cfg(all(feature = "tls", not(feature = "rustls")))]
use std::pin::Pin;
#[cfg(all(feature = "tls", not(feature = "rustls")))]
use std::sync::Arc;
#[cfg(all(feature = "tls", not(feature = "rustls")))]
use std::task::{Context, Poll};
#[cfg(all(feature = "tls", not(feature = "rustls")))]
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
#[cfg(all(feature = "tls", not(feature = "rustls")))]
use tokio::net::TcpStream;

#[cfg(all(feature = "tls", not(feature = "rustls")))]
/// Wrapper for tokio-native-tls TlsStream that implements CustomTlsStream
#[derive(Debug)]
struct NativeTlsStream {
  inner: tokio_native_tls::TlsStream<TcpStream>,
}

#[cfg(all(feature = "tls", not(feature = "rustls")))]
impl NativeTlsStream {
  fn new(stream: tokio_native_tls::TlsStream<TcpStream>) -> Self {
    Self { inner: stream }
  }
}

#[cfg(all(feature = "tls", not(feature = "rustls")))]
impl CustomTlsStream for NativeTlsStream {
  fn peer_certificate(&self) -> Option<PeerCertificate> {
    self
      .inner
      .get_ref()
      .peer_certificate()
      .ok()
      .flatten()
      .and_then(|cert| cert.to_der().ok())
      .map(|der| PeerCertificate { inner: der })
  }
}

#[cfg(all(feature = "tls", not(feature = "rustls")))]
impl AsyncRead for NativeTlsStream {
  fn poll_read(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    buf: &mut ReadBuf<'_>,
  ) -> Poll<std::io::Result<()>> {
    Pin::new(&mut self.inner).poll_read(cx, buf)
  }
}

#[cfg(all(feature = "tls", not(feature = "rustls")))]
impl AsyncWrite for NativeTlsStream {
  fn poll_write(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    buf: &[u8],
  ) -> Poll<std::result::Result<usize, std::io::Error>> {
    Pin::new(&mut self.inner).poll_write(cx, buf)
  }

  fn poll_flush(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
  ) -> Poll<std::result::Result<(), std::io::Error>> {
    Pin::new(&mut self.inner).poll_flush(cx)
  }

  fn poll_shutdown(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
  ) -> Poll<std::result::Result<(), std::io::Error>> {
    Pin::new(&mut self.inner).poll_shutdown(cx)
  }
}

#[cfg(all(feature = "tls", not(feature = "rustls")))]
/// Native-TLS connector implementation
///
/// This demonstrates how to wrap tokio-native-tls to work with slinger's
/// CustomTlsConnector trait.
struct NativeTlsConnector {
  connector: tokio_native_tls::TlsConnector,
}

#[cfg(all(feature = "tls", not(feature = "rustls")))]
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

#[cfg(all(feature = "tls", not(feature = "rustls")))]
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
        MaybeTlsStream::Tcp(tcp) => tcp,
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

      // Wrap in our custom stream type
      let custom_stream = NativeTlsStream::new(tls_stream);

      // Create a new socket with the TLS stream
      Ok(Socket::new(
        MaybeTlsStream::Custom(Box::new(custom_stream)),
        stream.read_timeout,
        stream.write_timeout,
      ))
    })
  }
}

#[cfg(all(feature = "tls", not(feature = "rustls")))]
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
    println!("✓ Retrieved peer certificate ({} bytes)", cert.len());
  } else {
    println!("✗ No peer certificate available");
  }

  println!("\nThis example demonstrates:");
  println!("1. Creating a custom TLS connector using native-tls");
  println!("2. Implementing the CustomTlsConnector trait");
  println!("3. Implementing the CustomTlsStream trait for the TLS stream wrapper");
  println!("4. Using ConnectorBuilder to configure the connector");
  println!("5. Getting peer certificate information from the TLS connection");

  println!("\nKey implementation details:");
  println!("  - NativeTlsStream wraps tokio_native_tls::TlsStream");
  println!("  - Implements CustomTlsStream with AsyncRead/AsyncWrite");
  println!("  - Provides peer_certificate() to extract certificate info");
  println!("  - Provides get_ref() to access underlying TcpStream");

  Ok(())
}

#[cfg(not(all(feature = "tls", not(feature = "rustls"))))]
fn main() {
  eprintln!("This example requires the 'tls' feature without 'rustls'.");
  eprintln!("Run with: cargo run --example native_tls_example --features tls");
}
