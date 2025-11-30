//! Error types for MITM proxy

use std::io;
use thiserror::Error;

/// Result type for MITM operations
pub type Result<T> = std::result::Result<T, Error>;

/// Error types for MITM proxy operations
#[derive(Error, Debug)]
pub enum Error {
  /// IO error
  #[error("IO error: {0}")]
  Io(io::Error),

  /// Certificate error
  #[error("Certificate error: {0}")]
  CertificateError(String),

  /// TLS error
  #[error("TLS error: {0}")]
  TlsError(String),

  /// HTTP parsing error
  #[error("HTTP error: {0}")]
  HttpError(http::Error),

  /// Slinger client error
  #[error("Slinger error: {0}")]
  SlingerError(slinger::Error),

  /// Proxy error
  #[error("Proxy error: {0}")]
  ProxyError(String),

  /// Invalid request
  #[error("Invalid request: {0}")]
  InvalidRequest(String),

  /// Connection error
  #[error("Connection error: {0}")]
  ConnectionError(String),

  /// Other errors
  #[error("{0}")]
  Other(String),
}

impl Error {
  /// Create a certificate error and log it
  pub fn certificate_error(msg: impl Into<String>) -> Self {
    let error = Error::CertificateError(msg.into());
    tracing::error!("Certificate error: {}", error);
    error
  }

  /// Create a TLS error and log it
  pub fn tls_error(msg: impl Into<String>) -> Self {
    let error = Error::TlsError(msg.into());
    tracing::error!("TLS error: {}", error);
    error
  }

  /// Create a proxy error and log it
  pub fn proxy_error(msg: impl Into<String>) -> Self {
    let error = Error::ProxyError(msg.into());
    tracing::error!("Proxy error: {}", error);
    error
  }

  /// Create an invalid request error and log it
  pub fn invalid_request(msg: impl Into<String>) -> Self {
    let error = Error::InvalidRequest(msg.into());
    tracing::error!("Invalid request: {}", error);
    error
  }

  /// Create a connection error and log it
  pub fn connection_error(msg: impl Into<String>) -> Self {
    let error = Error::ConnectionError(msg.into());
    tracing::error!("Connection error: {}", error);
    error
  }

  /// Create an other error and log it
  pub fn other(msg: impl Into<String>) -> Self {
    let error = Error::Other(msg.into());
    tracing::error!("Other error: {}", error);
    error
  }
}

impl From<io::Error> for Error {
  fn from(value: io::Error) -> Self {
    let error = Error::Io(value);
    tracing::error!("IO error: {}", error);
    error
  }
}

impl From<http::Error> for Error {
  fn from(value: http::Error) -> Self {
    let error = Error::HttpError(value);
    tracing::error!("HTTP error: {}", error);
    error
  }
}

impl From<slinger::Error> for Error {
  fn from(value: slinger::Error) -> Self {
    let error = Error::SlingerError(value);
    tracing::error!("Slinger error: {}", error);
    error
  }
}
