#[cfg(feature = "tls")]
use native_tls::TlsStream;
#[cfg(feature = "tls")]
use openssl::x509::X509;
use socket2::Socket as RawSocket;
use std::fmt::Arguments;
use std::io;
use std::io::{IoSlice, IoSliceMut, Read, Write};
use std::ops::Deref;
/// Socket
#[derive(Debug)]
pub enum Socket {
  /// TCP
  TCP(RawSocket),
  #[cfg(feature = "tls")]
  /// TLS
  TLS(TlsStream<RawSocket>),
}

impl Socket {
  #[cfg(feature = "tls")]
  /// get peer_certificate
  pub fn peer_certificate(&self) -> Option<X509> {
    match &self {
      Socket::TCP(_) => None,
      Socket::TLS(stream) => {
        if let Ok(Some(peer_certificate)) = stream.peer_certificate() {
          if let Ok(x509) = X509::from_der(&peer_certificate.to_der().unwrap_or_default()) {
            return Some(x509);
          }
        };
        None
      }
    }
  }
}

// 实现socket的读写
impl Read for Socket {
  #[inline]
  fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
    match self {
      Socket::TCP(s) => s.read(buf),
      #[cfg(feature = "tls")]
      Socket::TLS(t) => t.read(buf),
    }
  }
  #[inline]
  fn read_vectored(&mut self, buf: &mut [IoSliceMut<'_>]) -> io::Result<usize> {
    match self {
      Socket::TCP(s) => s.read_vectored(buf),
      #[cfg(feature = "tls")]
      Socket::TLS(t) => t.read_vectored(buf),
    }
  }
  #[inline]
  fn read_to_end(&mut self, buf: &mut Vec<u8>) -> io::Result<usize> {
    match self {
      Socket::TCP(s) => s.read_to_end(buf),
      #[cfg(feature = "tls")]
      Socket::TLS(t) => t.read_to_end(buf),
    }
  }
  #[inline]
  fn read_to_string(&mut self, buf: &mut String) -> io::Result<usize> {
    match self {
      Socket::TCP(s) => s.read_to_string(buf),
      #[cfg(feature = "tls")]
      Socket::TLS(t) => t.read_to_string(buf),
    }
  }
  #[inline]
  fn read_exact(&mut self, buf: &mut [u8]) -> io::Result<()> {
    match self {
      Socket::TCP(s) => s.read_exact(buf),
      #[cfg(feature = "tls")]
      Socket::TLS(t) => t.read_exact(buf),
    }
  }
}

impl Write for Socket {
  #[inline]
  fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
    match self {
      Socket::TCP(s) => s.write(buf),
      #[cfg(feature = "tls")]
      Socket::TLS(t) => t.write(buf),
    }
  }
  #[inline]
  fn write_vectored(&mut self, buf: &[IoSlice<'_>]) -> io::Result<usize> {
    match self {
      Socket::TCP(s) => s.write_vectored(buf),
      #[cfg(feature = "tls")]
      Socket::TLS(t) => t.write_vectored(buf),
    }
  }
  #[inline]
  fn flush(&mut self) -> io::Result<()> {
    match self {
      Socket::TCP(s) => s.flush(),
      #[cfg(feature = "tls")]
      Socket::TLS(t) => t.flush(),
    }
  }
  #[inline]
  fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
    match self {
      Socket::TCP(s) => s.write_all(buf),
      #[cfg(feature = "tls")]
      Socket::TLS(t) => t.write_all(buf),
    }
  }
  #[inline]
  fn write_fmt(&mut self, fmt: Arguments<'_>) -> io::Result<()> {
    match self {
      Socket::TCP(s) => s.write_fmt(fmt),
      #[cfg(feature = "tls")]
      Socket::TLS(t) => t.write_fmt(fmt),
    }
  }
}

// 直接暴露socket的全部外部接口
impl Deref for Socket {
  type Target = RawSocket;

  fn deref(&self) -> &Self::Target {
    match self {
      Socket::TCP(s) => s,
      #[cfg(feature = "tls")]
      Socket::TLS(t) => t.get_ref(),
    }
  }
}
