#[cfg(feature = "tls")]
use crate::tls::PeerCertificate;
use std::io::Error;
use std::ops::{Deref, DerefMut};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
#[cfg(feature = "tls")]
use tokio_rustls::client::TlsStream;

/// Socket
#[derive(Debug)]
pub struct Socket {
  inner: MaybeTlsStream,
  read_timeout: Option<Duration>,
  write_timeout: Option<Duration>,
}
impl Socket {
  pub(crate) fn new(
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
  pub(crate) fn read_timeout(&self) -> Option<Duration> {
    self.read_timeout
  }
  pub(crate) fn write_timeout(&self) -> Option<Duration> {
    self.write_timeout
  }
  #[cfg(feature = "tls")]
  pub(crate) fn inner(self) -> MaybeTlsStream {
    self.inner
  }
}
#[derive(Debug)]
pub enum MaybeTlsStream {
  /// TCP
  Tcp(TcpStream),
  #[cfg(feature = "tls")]
  /// TLS
  Tls(TlsStream<TcpStream>),
}
impl MaybeTlsStream {
  #[cfg(feature = "tls")]
  /// get peer_certificate
  pub fn peer_certificate(&self) -> Option<PeerCertificate> {
    match &self {
      MaybeTlsStream::Tcp(_) => None,
      MaybeTlsStream::Tls(stream) => stream
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|certs| certs.first())
        .map(|x| PeerCertificate { inner: x.to_vec() }),
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
      #[cfg(feature = "tls")]
      MaybeTlsStream::Tls(stream) => Pin::new(stream).poll_read(cx, buf),
    }
  }
}
impl AsyncWrite for MaybeTlsStream {
  fn poll_write(
    self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    buf: &[u8],
  ) -> Poll<Result<usize, std::io::Error>> {
    match self.get_mut() {
      MaybeTlsStream::Tcp(stream) => Pin::new(stream).poll_write(cx, buf),
      #[cfg(feature = "tls")]
      MaybeTlsStream::Tls(stream) => Pin::new(stream).poll_write(cx, buf),
    }
  }

  fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
    match self.get_mut() {
      MaybeTlsStream::Tcp(stream) => Pin::new(stream).poll_flush(cx),
      #[cfg(feature = "tls")]
      MaybeTlsStream::Tls(stream) => Pin::new(stream).poll_flush(cx),
    }
  }
  fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
    match self.get_mut() {
      MaybeTlsStream::Tcp(stream) => Pin::new(stream).poll_shutdown(cx),
      #[cfg(feature = "tls")]
      MaybeTlsStream::Tls(stream) => Pin::new(stream).poll_shutdown(cx),
    }
  }
}
impl Socket {
  /// 自定义的 `read_exact` 方法
  pub async fn read_to_string(&mut self, buf: &mut String) -> std::io::Result<usize> {
    match self.read_timeout {
      None => AsyncReadExt::read_to_string(self.deref_mut(), buf).await,
      Some(t) => {
        tokio::time::timeout(t, AsyncReadExt::read_to_string(self.deref_mut(), buf)).await?
      }
    }
  }
  /// 自定义的 `read_exact` 方法
  pub async fn read_to_end(&mut self, buf: &mut Vec<u8>) -> std::io::Result<usize> {
    match self.read_timeout {
      None => AsyncReadExt::read_to_end(self.deref_mut(), buf).await,
      Some(t) => tokio::time::timeout(t, AsyncReadExt::read_to_end(self.deref_mut(), buf)).await?,
    }
  }
  /// 自定义的 `read_exact` 方法
  pub async fn read_exact(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
    println!("{:?}", self.read_timeout);
    match self.read_timeout {
      None => AsyncReadExt::read_exact(self.deref_mut(), buf).await,
      Some(t) => tokio::time::timeout(t, AsyncReadExt::read_exact(self.deref_mut(), buf)).await?,
    }
  }
  /// 自定义的 `read` 方法
  pub async fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
    match self.read_timeout {
      None => AsyncReadExt::read(self.deref_mut(), buf).await,
      Some(t) => tokio::time::timeout(t, AsyncReadExt::read(self.deref_mut(), buf)).await?,
    }
  }
}
impl Socket {
  /// 自定义的 `write_all` 方法
  pub async fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
    match self.write_timeout {
      None => AsyncWriteExt::write(self.deref_mut(), buf).await,
      Some(t) => tokio::time::timeout(t, AsyncWriteExt::write(self.deref_mut(), buf)).await?,
    }
  }
  /// 自定义的 `write_all` 方法
  pub async fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()> {
    match self.write_timeout {
      None => AsyncWriteExt::write_all(self.deref_mut(), buf).await,
      Some(t) => tokio::time::timeout(t, AsyncWriteExt::write_all(self.deref_mut(), buf)).await?,
    }
  }
  /// 自定义的 `write_all` 方法
  pub async fn flush(&mut self) -> std::io::Result<()> {
    match self.write_timeout {
      None => AsyncWriteExt::flush(self.deref_mut()).await,
      Some(t) => tokio::time::timeout(t, AsyncWriteExt::flush(self.deref_mut())).await?,
    }
  }
  /// 自定义的 `write_all` 方法
  pub async fn shutdown(&mut self) -> std::io::Result<()> {
    match self.write_timeout {
      None => AsyncWriteExt::shutdown(self.deref_mut()).await,
      Some(t) => tokio::time::timeout(t, AsyncWriteExt::shutdown(self.deref_mut())).await?,
    }
  }
}
// 直接暴露socket的全部外部接口
impl Deref for MaybeTlsStream {
  type Target = TcpStream;

  fn deref(&self) -> &Self::Target {
    match self {
      MaybeTlsStream::Tcp(s) => s,
      #[cfg(feature = "tls")]
      MaybeTlsStream::Tls(t) => t.get_ref().0,
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
