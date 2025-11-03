//! HTTP/2 client implementation
//!
//! This module provides HTTP/2 support using the h2 library

use crate::socket::{MaybeTlsStream, Socket};
use crate::{Request, Response};
use bytes::Bytes;
use h2::client;
use http::Version;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};

/// Wrapper for MaybeTlsStream that allows h2 to work with any stream type
enum StreamWrapper {
  Tcp(tokio::net::TcpStream),
  #[cfg(feature = "rustls")]
  Tls(Box<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>),
  #[cfg(all(feature = "tls", not(feature = "rustls")))]
  Custom(Box<dyn crate::socket::CustomTlsStream>),
}

impl AsyncRead for StreamWrapper {
  fn poll_read(
    self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    buf: &mut tokio::io::ReadBuf<'_>,
  ) -> Poll<std::io::Result<()>> {
    match self.get_mut() {
      StreamWrapper::Tcp(stream) => Pin::new(stream).poll_read(cx, buf),
      #[cfg(feature = "rustls")]
      StreamWrapper::Tls(stream) => Pin::new(stream).poll_read(cx, buf),
      #[cfg(all(feature = "tls", not(feature = "rustls")))]
      StreamWrapper::Custom(stream) => Pin::new(stream).poll_read(cx, buf),
    }
  }
}

impl AsyncWrite for StreamWrapper {
  fn poll_write(
    self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    buf: &[u8],
  ) -> Poll<Result<usize, std::io::Error>> {
    match self.get_mut() {
      StreamWrapper::Tcp(stream) => Pin::new(stream).poll_write(cx, buf),
      #[cfg(feature = "rustls")]
      StreamWrapper::Tls(stream) => Pin::new(stream).poll_write(cx, buf),
      #[cfg(all(feature = "tls", not(feature = "rustls")))]
      StreamWrapper::Custom(stream) => Pin::new(stream).poll_write(cx, buf),
    }
  }

  fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
    match self.get_mut() {
      StreamWrapper::Tcp(stream) => Pin::new(stream).poll_flush(cx),
      #[cfg(feature = "rustls")]
      StreamWrapper::Tls(stream) => Pin::new(stream).poll_flush(cx),
      #[cfg(all(feature = "tls", not(feature = "rustls")))]
      StreamWrapper::Custom(stream) => Pin::new(stream).poll_flush(cx),
    }
  }

  fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
    match self.get_mut() {
      StreamWrapper::Tcp(stream) => Pin::new(stream).poll_shutdown(cx),
      #[cfg(feature = "rustls")]
      StreamWrapper::Tls(stream) => Pin::new(stream).poll_shutdown(cx),
      #[cfg(all(feature = "tls", not(feature = "rustls")))]
      StreamWrapper::Custom(stream) => Pin::new(stream).poll_shutdown(cx),
    }
  }
}

pub(crate) async fn send_h2_request(
  socket: Socket,
  request: &Request,
  _timeout: Option<Duration>,
) -> crate::Result<Response> {
  // Extract the stream from the socket
  let _read_timeout = socket.read_timeout;
  let _write_timeout = socket.write_timeout;

  let io = match socket.inner {
    MaybeTlsStream::Tcp(tcp_stream) => StreamWrapper::Tcp(tcp_stream),
    #[cfg(feature = "rustls")]
    MaybeTlsStream::Rustls(tls_stream) => StreamWrapper::Tls(tls_stream),
    #[cfg(all(feature = "tls", not(feature = "rustls")))]
    MaybeTlsStream::Custom(tls_stream) => StreamWrapper::Custom(tls_stream),
  };

  // Create an h2 client handshake
  let (client, h2_conn) = client::handshake(io)
    .await
    .map_err(|e| crate::errors::Error::Other(format!("HTTP/2 handshake failed: {}", e)))?;
  tokio::spawn(async {
    h2_conn.await.unwrap_or_default();
  });
  // Wait for the client to be ready and get it back
  let mut client = client
    .ready()
    .await
    .map_err(|e| crate::errors::Error::Other(format!("HTTP/2 client not ready: {}", e)))?;
  // Build the HTTP/2 request
  let mut h2_request = http::Request::builder()
    .method(request.method())
    .uri(request.uri())
    .version(Version::HTTP_2);
  // Add headers (skip certain HTTP/1.1 specific headers)
  for (key, value) in request.headers().iter() {
    // Skip HTTP/1.1 specific headers that shouldn't be in HTTP/2
    if key == http::header::CONNECTION
      || key == http::header::TRANSFER_ENCODING
      || key == http::header::UPGRADE
      || key.as_str().to_lowercase() == "keep-alive"
      || key.as_str().to_lowercase() == "proxy-connection"
    {
      continue;
    }
    h2_request = h2_request.header(key, value);
  }
  // Create the request body
  let body_bytes = request.body().map(|b| b.as_ref()).unwrap_or(&[]);
  let h2_request = h2_request
    .body(())
    .map_err(|e| crate::errors::Error::Other(format!("Failed to build HTTP/2 request: {}", e)))?;
  // Send the request
  let (response_future, mut send_stream) =
    client
      .send_request(h2_request, body_bytes.is_empty())
      .map_err(|e| crate::errors::Error::Other(format!("Failed to send HTTP/2 request: {}", e)))?;
  // Send the body if present
  if !body_bytes.is_empty() {
    send_stream
      .send_data(Bytes::copy_from_slice(body_bytes), true)
      .map_err(|e| crate::errors::Error::Other(format!("Failed to send HTTP/2 body: {}", e)))?;
  }
  // Wait for the response
  let h2_response = response_future.await.map_err(|e| {
    crate::errors::Error::Other(format!("Failed to receive HTTP/2 response: {}", e))
  })?;
  // Extract status and headers
  let status = h2_response.status();
  let headers = h2_response.headers().clone();
  let mut body_stream = h2_response.into_body();
  // Read the response body
  let mut body = Vec::new();
  while let Some(chunk_result) = body_stream.data().await {
    let chunk = chunk_result.map_err(|e| {
      crate::errors::Error::Other(format!("Failed to read HTTP/2 body chunk: {}", e))
    })?;
    body.extend_from_slice(&chunk);
    body_stream
      .flow_control()
      .release_capacity(chunk.len())
      .map_err(|e| crate::errors::Error::Other(format!("Failed to release flow control: {}", e)))?;
  }
  // Build a slinger Response
  let mut response_builder = http::Response::builder()
    .status(status)
    .version(Version::HTTP_2);
  for (key, value) in headers.iter() {
    response_builder = response_builder.header(key, value);
  }
  let http_response = response_builder
    .body(Bytes::from(body))
    .map_err(|e| crate::errors::Error::Other(format!("Failed to build response: {}", e)))?;
  let response: Response = http_response.into();
  Ok(response)
}
