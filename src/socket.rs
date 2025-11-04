#[cfg(feature = "tls")]
use crate::tls::PeerCertificate;
use std::io::Error;
use std::ops::{Deref, DerefMut};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
#[cfg(feature = "rustls")]
use tokio_rustls::client::TlsStream as RustlsStream;

/// Socket
#[derive(Debug)]
pub struct Socket {
  /// The underlying stream (TCP, TLS, or custom TLS)
  pub inner: MaybeTlsStream,
  /// Read timeout for socket operations
  pub read_timeout: Option<Duration>,
  /// Write timeout for socket operations
  pub write_timeout: Option<Duration>,
}

impl Socket {
  /// Create a new Socket with the given stream and timeouts
  pub fn new(
    maybe_tls_stream: MaybeTlsStream,
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
      MaybeTlsStream::Tcp(_) => None,
      #[cfg(feature = "rustls")]
      MaybeTlsStream::Rustls(tls) => tls
        .get_ref()
        .1
        .alpn_protocol()
        .map(|protocol| protocol.to_vec()),
      #[cfg(all(feature = "tls", not(feature = "rustls")))]
      MaybeTlsStream::Custom(c) => c.alpn_protocol(),
    }
  }
}
/// Enum representing different types of streams (TCP, TLS with rustls, or custom TLS)
#[derive(Debug)]
pub enum MaybeTlsStream {
  /// TCP
  Tcp(TcpStream),
  #[cfg(feature = "rustls")]
  /// TLS with rustls
  Rustls(Box<RustlsStream<TcpStream>>),
  #[cfg(all(feature = "tls", not(feature = "rustls")))]
  /// Custom TLS implementation (when tls feature is enabled without rustls backend)
  Custom(Box<dyn CustomTlsStream>),
}

#[cfg(all(feature = "tls", not(feature = "rustls")))]
/// Trait for custom TLS stream implementations
pub trait CustomTlsStream:
  AsyncRead + AsyncWrite + Send + Sync + std::fmt::Debug + Unpin + 'static
{
  /// Get the peer certificate from the TLS connection, if available
  fn peer_certificate(&self) -> Option<PeerCertificate> {
    None
  }
  /// Get the alpn_protocol
  fn alpn_protocol(&self) -> Option<Vec<u8>> {
    None
  }
}

#[cfg(feature = "rustls")]
impl From<RustlsStream<TcpStream>> for MaybeTlsStream {
  fn from(stream: RustlsStream<TcpStream>) -> Self {
    MaybeTlsStream::Rustls(Box::new(stream))
  }
}

#[cfg(all(feature = "tls", not(feature = "rustls")))]
impl<T: CustomTlsStream> From<T> for MaybeTlsStream {
  fn from(stream: T) -> Self {
    MaybeTlsStream::Custom(Box::new(stream))
  }
}

impl MaybeTlsStream {
  #[cfg(feature = "tls")]
  /// get peer_certificate
  pub fn peer_certificate(&self) -> Option<PeerCertificate> {
    match &self {
      MaybeTlsStream::Tcp(_) => None,
      #[cfg(feature = "rustls")]
      MaybeTlsStream::Rustls(stream) => stream
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|certs| certs.first())
        .map(|x| PeerCertificate { inner: x.to_vec() }),
      #[cfg(all(feature = "tls", not(feature = "rustls")))]
      MaybeTlsStream::Custom(stream) => stream.peer_certificate(),
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
impl AsyncRead for MaybeTlsStream {
  fn poll_read(
    self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    buf: &mut ReadBuf<'_>,
  ) -> Poll<std::io::Result<()>> {
    match self.get_mut() {
      MaybeTlsStream::Tcp(stream) => Pin::new(stream).poll_read(cx, buf),
      #[cfg(feature = "rustls")]
      MaybeTlsStream::Rustls(stream) => Pin::new(stream).poll_read(cx, buf),
      #[cfg(all(feature = "tls", not(feature = "rustls")))]
      MaybeTlsStream::Custom(stream) => Pin::new(stream).poll_read(cx, buf),
    }
  }
}
impl AsyncWrite for MaybeTlsStream {
  fn poll_write(
    self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    buf: &[u8],
  ) -> Poll<Result<usize, Error>> {
    match self.get_mut() {
      MaybeTlsStream::Tcp(stream) => Pin::new(stream).poll_write(cx, buf),
      #[cfg(feature = "rustls")]
      MaybeTlsStream::Rustls(stream) => Pin::new(stream).poll_write(cx, buf),
      #[cfg(all(feature = "tls", not(feature = "rustls")))]
      MaybeTlsStream::Custom(stream) => Pin::new(stream).poll_write(cx, buf),
    }
  }

  fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
    match self.get_mut() {
      MaybeTlsStream::Tcp(stream) => Pin::new(stream).poll_flush(cx),
      #[cfg(feature = "rustls")]
      MaybeTlsStream::Rustls(stream) => Pin::new(stream).poll_flush(cx),
      #[cfg(all(feature = "tls", not(feature = "rustls")))]
      MaybeTlsStream::Custom(stream) => Pin::new(stream).poll_flush(cx),
    }
  }
  fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
    match self.get_mut() {
      MaybeTlsStream::Tcp(stream) => Pin::new(stream).poll_shutdown(cx),
      #[cfg(feature = "rustls")]
      MaybeTlsStream::Rustls(stream) => Pin::new(stream).poll_shutdown(cx),
      #[cfg(all(feature = "tls", not(feature = "rustls")))]
      MaybeTlsStream::Custom(stream) => Pin::new(stream).poll_shutdown(cx),
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
  type Target = MaybeTlsStream;

  fn deref(&self) -> &Self::Target {
    &self.inner
  }
}

impl DerefMut for Socket {
  fn deref_mut(&mut self) -> &mut Self::Target {
    &mut self.inner
  }
}
