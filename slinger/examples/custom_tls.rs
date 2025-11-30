//! Example demonstrating how to use a custom TLS connector
//!
//! This example shows how to implement your own TLS handshake logic
//! when the `tls` feature is enabled.
//!
//! To run this example, compile with:
//! ```bash
//! cargo run --example custom_tls --features tls
//! ```
//!
//! Note: This example demonstrates the API with a mock TLS implementation for educational purposes.

#[cfg(feature = "tls")]
use slinger::tls::CustomTlsStream;
#[cfg(feature = "tls")]
use slinger::tls::{CustomTlsConnector, PeerCertificate};
#[cfg(feature = "tls")]
use slinger::{ConnectorBuilder, Result, Socket, StreamWrapper};
#[cfg(feature = "tls")]
use std::sync::Arc;

#[cfg(feature = "tls")]
/// Mock TLS stream for demonstration purposes
///
/// In a real implementation, this would wrap an actual TLS stream from
/// a library like OpenSSL, BoringSSL, or another TLS implementation.
struct MockTlsStream {
  inner: tokio::net::TcpStream,
}
#[cfg(feature = "tls")]
impl CustomTlsStream for MockTlsStream {
  fn peer_certificate(&self) -> Option<Vec<PeerCertificate>> {
    None
  }

  fn alpn_protocol(&self) -> Option<Vec<u8>> {
    None
  }
}
#[cfg(feature = "tls")]
slinger::impl_tls_stream!(MockTlsStream, inner);
#[cfg(feature = "tls")]
/// Example custom TLS connector implementation
///
/// In a real implementation, you would:
/// 1. Take the TCP socket from the provided Socket
/// 2. Perform TLS handshake using your preferred TLS library (openssl, boringssl, etc.)
/// 3. Wrap the resulting TLS stream in a type that implements CustomTlsStream
/// 4. Return it wrapped in a Socket
struct MyCustomTlsConnector;
#[cfg(feature = "tls")]
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
        StreamWrapper::Tcp(tcp) => tcp,
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
      let mock = MockTlsStream { inner: tcp_stream };
      // let tls_stream = TlsStreamWrapper::new(mock);

      println!("✓ Mock TLS handshake completed successfully");

      // Wrap in a Socket and return
      Ok(Socket::new(
        StreamWrapper::Custom(Box::new(mock)),
        stream.read_timeout,
        stream.write_timeout,
      ))
    })
  }
}

#[cfg(feature = "tls")]
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

#[cfg(not(feature = "tls"))]
fn main() {
  eprintln!("This example requires the 'tls' feature.");
  eprintln!("Run with: cargo run --example custom_tls --features tls");
}
