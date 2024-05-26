use crate::{Request, Response};
use bytes::Bytes;
use socket2::SockAddr;
use std::net::SocketAddr;

#[derive(Clone, Debug)]
pub struct HttpInfo {
  remote_addr: SockAddr,
  local_addr: SockAddr,
}

impl HttpInfo {
  pub fn new(remote_addr: SockAddr, local_addr: SockAddr) -> Self {
    HttpInfo {
      remote_addr,
      local_addr,
    }
  }
  pub fn remote_addr(&self) -> Option<SocketAddr> {
    self.remote_addr.as_socket()
  }
  pub fn local_addr(&self) -> Option<SocketAddr> {
    self.local_addr.as_socket()
  }
}
/// HTTPRecord
#[derive(Debug, Default, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct HTTPRecord {
  /// request
  pub request: Request,
  #[cfg_attr(feature = "serde", serde(skip))]
  /// raw_request
  pub raw_request: Bytes,
  /// response
  pub response: Response,
  #[cfg_attr(feature = "serde", serde(skip))]
  /// raw_response
  pub raw_response: Bytes,
}

impl HTTPRecord {
  pub(crate) fn record_request(&mut self, irq: &Request) {
    self.raw_request = irq.to_raw();
    self.request = irq.clone();
  }
  pub(crate) fn record_response(&mut self, irp: &Response) {
    self.raw_response = irp.to_raw();
    self.response = irp.clone();
  }
}
