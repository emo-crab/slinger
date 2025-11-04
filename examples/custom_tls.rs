//! Example demonstrating how to use a custom TLS connector
//!
//! This example shows how to implement your own TLS handshake logic
//! when the `tls` feature is enabled without a specific backend.
//!
//! To run this example, compile with:
//! ```bash
//! cargo run --example custom_tls --features tls
//! ```
//!
//! Note: This example requires the `tls` feature without `rustls`.
//! It demonstrates the API with a mock TLS implementation for educational purposes.

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
/// Mock TLS stream for demonstration purposes
///
/// In a real implementation, this would wrap an actual TLS stream from
/// a library like OpenSSL, BoringSSL, or another TLS implementation.
#[derive(Debug)]
struct MockTlsStream {
  inner: TcpStream,
  // In a real implementation, you would store TLS session state here
  mock_certificate: Vec<u8>,
}

#[cfg(all(feature = "tls", not(feature = "rustls")))]
impl MockTlsStream {
  fn new(stream: TcpStream) -> Self {
    // Create a mock certificate for demonstration
    let mock_certificate = b"This is a mock certificate".to_vec();
    Self {
      inner: stream,
      mock_certificate,
    }
  }
}

#[cfg(all(feature = "tls", not(feature = "rustls")))]
impl CustomTlsStream for MockTlsStream {
  fn peer_certificate(&self) -> Option<PeerCertificate> {
    // Return the mock certificate
    // In a real implementation, this would extract the actual peer certificate
    Some(PeerCertificate {
      inner: self.mock_certificate.clone(),
    })
  }
}

#[cfg(all(feature = "tls", not(feature = "rustls")))]
impl AsyncRead for MockTlsStream {
  fn poll_read(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    buf: &mut ReadBuf<'_>,
  ) -> Poll<std::io::Result<()>> {
    // In a real implementation, this would read encrypted data,
    // decrypt it, and place it in the buffer
    Pin::new(&mut self.inner).poll_read(cx, buf)
  }
}

#[cfg(all(feature = "tls", not(feature = "rustls")))]
impl AsyncWrite for MockTlsStream {
  fn poll_write(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    buf: &[u8],
  ) -> Poll<std::result::Result<usize, std::io::Error>> {
    // In a real implementation, this would encrypt the data
    // before writing it to the underlying stream
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
/// Example custom TLS connector implementation
///
/// In a real implementation, you would:
/// 1. Take the TCP socket from the provided Socket
/// 2. Perform TLS handshake using your preferred TLS library (openssl, boringssl, etc.)
/// 3. Wrap the resulting TLS stream in a type that implements CustomTlsStream
/// 4. Return it wrapped in a Socket
struct MyCustomTlsConnector;

#[cfg(all(feature = "tls", not(feature = "rustls")))]
impl CustomTlsConnector for MyCustomTlsConnector {
  fn connect<'a>(
    &'a self,
    domain: &'a str,
    stream: Socket,
  ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Socket>> + Send + 'a>> {
    Box::pin(async move {
      println!("Performing mock TLS handshake for domain: {}", domain);

      // Extract the TCP stream from the socket
      let tcp_stream = match stream.inner {
        MaybeTlsStream::Tcp(tcp) => tcp,
        _ => {
          return Err(slinger::Error::Other(
            "Expected plain TCP stream for TLS upgrade".to_string(),
          ));
        }
      };

      // In a real implementation, you would:
      // 1. Perform TLS handshake using your TLS library
      // 2. Verify the server's certificate
      // 3. Establish encrypted communication

      // Create our mock TLS stream
      let tls_stream = MockTlsStream::new(tcp_stream);

      println!("✓ Mock TLS handshake completed successfully");

      // Wrap in a Socket and return
      Ok(Socket::new(
        MaybeTlsStream::Custom(Box::new(tls_stream)),
        stream.read_timeout,
        stream.write_timeout,
      ))
    })
  }
}

#[cfg(all(feature = "tls", not(feature = "rustls")))]
#[tokio::main]
async fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
  println!("Custom TLS Connector Example");
  println!("============================\n");

  // Create a custom TLS connector
  let custom_connector = Arc::new(MyCustomTlsConnector);

  // Build a connector with the custom TLS implementation
  let _connector = ConnectorBuilder::default()
    .custom_tls_connector(custom_connector)
    .build()?;

  println!("✓ Successfully created connector with custom TLS backend");

  println!("\nThis example demonstrates:");
  println!("1. Implementing CustomTlsStream trait for a mock TLS stream");
  println!("2. Implementing CustomTlsConnector trait for custom TLS handshake");
  println!("3. Extracting the TCP stream from a Socket");
  println!("4. Wrapping the TLS stream back into a Socket");
  println!("5. Providing peer certificate information via peer_certificate()");
  println!("6. Providing access to underlying TcpStream via get_ref()");

  println!("\nIn a full implementation, you would:");
  println!("  - Use a real TLS library (openssl, boringssl, etc.)");
  println!("  - Perform actual cryptographic handshake");
  println!("  - Verify server certificates");
  println!("  - Encrypt/decrypt data in AsyncRead/AsyncWrite implementations");

  println!("\nExample libraries you could use:");
  println!("  - openssl: Use openssl-sys or tokio-openssl");
  println!("  - boring: Use boring (BoringSSL bindings)");
  println!("  - native-tls: See native_tls_example.rs");
  println!("  - Any other TLS library with async support");

  Ok(())
}

#[cfg(not(all(feature = "tls", not(feature = "rustls"))))]
fn main() {
  eprintln!("This example requires the 'tls' feature without 'rustls'.");
  eprintln!("Run with: cargo run --example custom_tls --features tls");
}
