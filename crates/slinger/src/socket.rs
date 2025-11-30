#[cfg(feature = "tls")]
use crate::tls::{CustomTlsStream, PeerCertificate};
use std::io::Error;
use std::ops::{Deref, DerefMut};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

/// Socket
pub struct Socket {
  /// The underlying stream (TCP, TLS, or custom TLS)
  pub inner: StreamWrapper,
  /// Read timeout for socket operations
  pub read_timeout: Option<Duration>,
  /// Write timeout for socket operations
  pub write_timeout: Option<Duration>,
}

impl Socket {
  /// Create a new Socket with the given stream and timeouts
  pub fn new(
    maybe_tls_stream: StreamWrapper,
    read_timeout: Option<Duration>,
    write_timeout: Option<Duration>,
  ) -> Self {
    Self {
      inner: maybe_tls_stream,
      read_timeout,
      write_timeout,
    }
  }
  #[cfg(feature = "http2")]
  pub(crate) fn is_http2_negotiated(&self) -> bool {
    self
      .http2_negotiated()
      .map(|alpn| alpn == b"h2")
      .unwrap_or(false)
  }
  #[cfg(feature = "http2")]
  pub(crate) fn http2_negotiated(&self) -> Option<Vec<u8>> {
    match &self.inner {
      StreamWrapper::Tcp(_) => None,
      #[cfg(feature = "tls")]
      StreamWrapper::Custom(c) => c.alpn_protocol(),
    }
  }
}

/// Wrapper for StreamWrapper that allows h2 to work with any stream type
pub enum StreamWrapper {
  /// TCP
  Tcp(tokio::net::TcpStream),
  #[cfg(feature = "tls")]
  /// Custom TLS implementation (when tls feature is enabled)
  Custom(Box<dyn CustomTlsStream>),
}
#[cfg(feature = "tls")]
impl CustomTlsStream for StreamWrapper {
  fn peer_certificate(&self) -> Option<Vec<PeerCertificate>> {
    match &self {
      StreamWrapper::Tcp(_) => None,
      #[cfg(feature = "tls")]
      StreamWrapper::Custom(stream) => stream.peer_certificate(),
    }
  }

  fn alpn_protocol(&self) -> Option<Vec<u8>> {
    match &self {
      StreamWrapper::Tcp(_) => None,
      #[cfg(feature = "tls")]
      StreamWrapper::Custom(stream) => stream.alpn_protocol(),
    }
  }
}

// 实现socket的读写
impl AsyncRead for Socket {
  fn poll_read(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    buf: &mut ReadBuf<'_>,
  ) -> Poll<std::io::Result<()>> {
    Pin::new(&mut self.inner).poll_read(cx, buf)
  }
}
impl AsyncWrite for Socket {
  fn poll_write(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    buf: &[u8],
  ) -> Poll<Result<usize, Error>> {
    Pin::new(&mut self.inner).poll_write(cx, buf)
  }

  fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
    Pin::new(&mut self.inner).poll_flush(cx)
  }

  fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
    Pin::new(&mut self.inner).poll_shutdown(cx)
  }
}
impl AsyncRead for StreamWrapper {
  fn poll_read(
    self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    buf: &mut ReadBuf<'_>,
  ) -> Poll<std::io::Result<()>> {
    match self.get_mut() {
      StreamWrapper::Tcp(stream) => Pin::new(stream).poll_read(cx, buf),
      #[cfg(feature = "tls")]
      StreamWrapper::Custom(stream) => Pin::new(stream).poll_read(cx, buf),
    }
  }
}
impl AsyncWrite for StreamWrapper {
  fn poll_write(
    self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    buf: &[u8],
  ) -> Poll<Result<usize, Error>> {
    match self.get_mut() {
      StreamWrapper::Tcp(stream) => Pin::new(stream).poll_write(cx, buf),
      #[cfg(feature = "tls")]
      StreamWrapper::Custom(stream) => Pin::new(stream).poll_write(cx, buf),
    }
  }

  fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
    match self.get_mut() {
      StreamWrapper::Tcp(stream) => Pin::new(stream).poll_flush(cx),
      #[cfg(feature = "tls")]
      StreamWrapper::Custom(stream) => Pin::new(stream).poll_flush(cx),
    }
  }
  fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
    match self.get_mut() {
      StreamWrapper::Tcp(stream) => Pin::new(stream).poll_shutdown(cx),
      #[cfg(feature = "tls")]
      StreamWrapper::Custom(stream) => Pin::new(stream).poll_shutdown(cx),
    }
  }
}
impl Socket {
  /// Reads all bytes until EOF in this source, appending them to buf.
  pub async fn read_to_string(&mut self, buf: &mut String) -> std::io::Result<usize> {
    match self.read_timeout {
      None => AsyncReadExt::read_to_string(&mut self.inner, buf).await,
      Some(t) => {
        tokio::time::timeout(t, AsyncReadExt::read_to_string(&mut self.inner, buf)).await?
      }
    }
  }
  /// Reads all bytes until EOF in this source, placing them into buf.
  pub async fn read_to_end(&mut self, buf: &mut Vec<u8>) -> std::io::Result<usize> {
    match self.read_timeout {
      None => AsyncReadExt::read_to_end(&mut self.inner, buf).await,
      Some(t) => tokio::time::timeout(t, AsyncReadExt::read_to_end(&mut self.inner, buf)).await?,
    }
  }
  /// Reads the exact number of bytes required to fill buf.
  pub async fn read_exact(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
    match self.read_timeout {
      None => AsyncReadExt::read_exact(&mut self.inner, buf).await,
      Some(t) => tokio::time::timeout(t, AsyncReadExt::read_exact(&mut self.inner, buf)).await?,
    }
  }
  /// Pulls some bytes from this source into the specified buffer, returning how many bytes were read.
  pub async fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
    match self.read_timeout {
      None => AsyncReadExt::read(&mut self.inner, buf).await,
      Some(t) => tokio::time::timeout(t, AsyncReadExt::read(&mut self.inner, buf)).await?,
    }
  }
}
impl Socket {
  /// Writes a buffer into this writer, returning how many bytes were
  pub async fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
    match self.write_timeout {
      None => AsyncWriteExt::write(&mut self.inner, buf).await,
      Some(t) => tokio::time::timeout(t, AsyncWriteExt::write(&mut self.inner, buf)).await?,
    }
  }
  /// Attempts to write an entire buffer into this writer.
  pub async fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()> {
    match self.write_timeout {
      None => AsyncWriteExt::write_all(&mut self.inner, buf).await,
      Some(t) => tokio::time::timeout(t, AsyncWriteExt::write_all(&mut self.inner, buf)).await?,
    }
  }
  /// Flushes this output stream, ensuring that all intermediately buffered
  /// contents reach their destination.
  pub async fn flush(&mut self) -> std::io::Result<()> {
    match self.write_timeout {
      None => AsyncWriteExt::flush(&mut self.inner).await,
      Some(t) => tokio::time::timeout(t, AsyncWriteExt::flush(&mut self.inner)).await?,
    }
  }
  /// Shuts down the output stream, ensuring that the value can be dropped
  /// cleanly.
  pub async fn shutdown(&mut self) -> std::io::Result<()> {
    match self.write_timeout {
      None => AsyncWriteExt::shutdown(&mut self.inner).await,
      Some(t) => tokio::time::timeout(t, AsyncWriteExt::shutdown(&mut self.inner)).await?,
    }
  }
}

// 直接暴露socket的全部外部接口
impl Deref for Socket {
  type Target = StreamWrapper;

  fn deref(&self) -> &Self::Target {
    &self.inner
  }
}

impl DerefMut for Socket {
  fn deref_mut(&mut self) -> &mut Self::Target {
    &mut self.inner
  }
}
