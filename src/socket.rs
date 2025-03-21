#[cfg(feature = "tls")]
use crate::tls::PeerCertificate;
use std::ops::Deref;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
#[cfg(feature = "tls")]
use tokio_rustls::client::TlsStream;

/// Socket
#[derive(Debug)]
pub enum Socket {
  /// TCP
  TCP(TcpStream),
  #[cfg(feature = "tls")]
  /// TLS
  TLS(TlsStream<TcpStream>),
}
impl Socket {
  #[cfg(feature = "tls")]
  /// get peer_certificate
  pub fn peer_certificate(&self) -> Option<PeerCertificate> {
    match &self {
      Socket::TCP(_) => None,
      Socket::TLS(stream) => stream
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
    self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    buf: &mut ReadBuf<'_>,
  ) -> Poll<std::io::Result<()>> {
    match self.get_mut() {
      Socket::TCP(stream) => Pin::new(stream).poll_read(cx, buf),
      #[cfg(feature = "tls")]
      Socket::TLS(stream) => Pin::new(stream).poll_read(cx, buf),
    }
  }
}
impl AsyncWrite for Socket {
  fn poll_write(
    self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    buf: &[u8],
  ) -> Poll<Result<usize, std::io::Error>> {
    match self.get_mut() {
      Socket::TCP(stream) => Pin::new(stream).poll_write(cx, buf),
      #[cfg(feature = "tls")]
      Socket::TLS(stream) => Pin::new(stream).poll_write(cx, buf),
    }
  }

  fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
    match self.get_mut() {
      Socket::TCP(stream) => Pin::new(stream).poll_flush(cx),
      #[cfg(feature = "tls")]
      Socket::TLS(stream) => Pin::new(stream).poll_flush(cx),
    }
  }
  fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
    match self.get_mut() {
      Socket::TCP(stream) => Pin::new(stream).poll_shutdown(cx),
      #[cfg(feature = "tls")]
      Socket::TLS(stream) => Pin::new(stream).poll_shutdown(cx),
    }
  }
}
impl Socket {
  // 自定义的 `read_exact` 方法
  pub(crate) async fn read_exact(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
    AsyncReadExt::read_exact(self, buf).await
  }
  // 自定义的 `read` 方法
  pub(crate) async fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
    AsyncReadExt::read(self, buf).await
  }
}
impl Socket {
  // 自定义的 `write_all` 方法
  pub(crate) async fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()> {
    AsyncWriteExt::write_all(self, buf).await
  }
  pub(crate) async fn flush(&mut self) -> std::io::Result<()> {
    AsyncWriteExt::flush(self).await
  }
  pub(crate) async fn shutdown(&mut self) -> std::io::Result<()> {
    AsyncWriteExt::shutdown(self).await
  }
}
// 直接暴露socket的全部外部接口
impl Deref for Socket {
  type Target = TcpStream;

  fn deref(&self) -> &Self::Target {
    match self {
      Socket::TCP(s) => s,
      #[cfg(feature = "tls")]
      Socket::TLS(t) => t.get_ref().0,
    }
  }
}
