use crate::{Request, Response};
use bytes::Bytes;
use socket2::SockAddr;

/// http peer_addr and local_addr
#[derive(Clone, Debug)]
pub struct LocalPeerRecord {
  /// peer_addr
  pub remote_addr: SockAddr,
  /// local_addr
  pub local_addr: SockAddr,
}

/// redirect info
#[derive(Clone, Debug)]
pub struct RedirectRecord {
  /// should_redirect
  pub should_redirect: bool,
  /// the next redirect url
  pub next: Option<http::Uri>,
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
