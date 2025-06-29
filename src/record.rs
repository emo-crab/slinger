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
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct HTTPRecord {
  /// request
  #[cfg_attr(
    feature = "schema",
    schemars(
      title = "HTTP request",
      description = "Structured representation of the HTTP request",
      example = r#"{
            "method": "GET",
            "uri": "https://example.com/api",
            "headers": {"Accept": "application/json"}
        }"#
    )
  )]
  pub request: Request,
  /// raw_request
  #[cfg_attr(
    feature = "serde",
    serde(
      with = "crate::serde_schema::bytes_serde",
      skip_serializing_if = "Bytes::is_empty"
    )
  )]
  #[cfg_attr(
    feature = "schema",
    schemars(
      with = "Bytes",
      title = "raw request bytes",
      description = "Original raw bytes of the HTTP request for debugging purposes",
      example = "GET /api HTTP/1.1\r\nHost: example.com\r\nAccept: application/json\r\n\r\n"
    )
  )]
  pub raw_request: Bytes,
  /// response
  #[cfg_attr(
    feature = "schema",
    schemars(
      title = "HTTP response",
      description = "Structured representation of the HTTP response",
      example = r#"{
            "status_code": 200,
            "headers": {"Content-Type": "application/json"},
            "body": "{\"data\":\"value\"}"
        }"#
    )
  )]
  pub response: Response,
  /// raw_response
  #[cfg_attr(
    feature = "serde",
    serde(
      with = "crate::serde_schema::bytes_serde",
      skip_serializing_if = "Bytes::is_empty"
    )
  )]
  #[cfg_attr(
    feature = "schema",
    schemars(
      with = "Bytes",
      title = "raw response bytes",
      description = "Original raw bytes of the HTTP response for debugging purposes",
      example = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"data\":\"value\"}"
    )
  )]
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

/// command record
#[derive(Clone, Debug)]
pub struct CommandRecord {
  /// nc or curl command
  pub command: String,
}

impl From<&Request> for CommandRecord {
  fn from(value: &Request) -> Self {
    let uri = value.uri();
    let https = uri.scheme() == Some(&http::uri::Scheme::HTTPS);
    let host = uri.host().unwrap_or("127.0.0.1");
    let port = uri
      .port_u16()
      .unwrap_or(if https { 443 } else { 80 })
      .to_string();
    let raw = value.to_raw();
    let command = if let Some(_raw) = value.raw_request() {
      let lines = raw
        .split(|b| b == &0xA)
        .map(|line| line.strip_suffix(&[0xD]).unwrap_or(line))
        .map(|line| [line, &[0xD, 0xA]].concat());
      let mut command = String::from("printf");
      command.push(' ');
      for line in lines {
        command.push_str(&bash_escape(
          &Bytes::from(line.to_vec()).escape_ascii().to_string(),
        ));
        command.push_str("\\\r\n");
      }
      command.push('|');
      let mut nc_cmd = vec!["ncat"];
      if https {
        nc_cmd.push("--ssl")
      }
      nc_cmd.push(host);
      nc_cmd.push(&port);
      command.push_str(&nc_cmd.join(" "));
      CommandRecord { command }
    } else {
      let mut curl_cmd = vec!["curl"];
      curl_cmd.push("-X");
      curl_cmd.push(value.method().as_str());
      if https {
        curl_cmd.push("-k");
      }
      curl_cmd.push("--compressed\\\r\n");
      let mut command = curl_cmd.join(" ");
      for (k, v) in value.headers() {
        command.push_str(" -H ");
        let header = format!("{}: {}", k.as_str(), v.to_str().unwrap_or_default());
        command.push_str(&bash_escape(&header));
        command.push_str("\\\r\n");
      }
      if let Some(body) = value.body() {
        command.push_str(" -d ");
        command.push_str(&format!(
          "'{}'\\\r\n",
          Bytes::from(body.to_vec()).escape_ascii()
        ));
      }
      command.push(' ');
      command.push_str(&bash_escape(&uri.to_string()));
      CommandRecord { command }
    };
    command
  }
}

impl std::fmt::Display for CommandRecord {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    std::fmt::Display::fmt(&self.command, f)
  }
}

fn bash_escape(s: &str) -> String {
  format!("'{}'", s.replace('\'', "\\'"))
}
