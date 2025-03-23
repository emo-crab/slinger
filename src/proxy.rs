use crate::connector::Connector;
use crate::errors::{new_io_error, Error, ReplyError, Result};
use crate::response::ResponseBuilder;
use crate::socket::Socket;
use crate::{Request, Response};
use bytes::Bytes;
use http::uri::Authority;
use http::HeaderValue;
use percent_encoding::percent_decode;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, ToSocketAddrs};
use std::str::FromStr;

impl Proxy {
  fn http(uri: &http::Uri) -> Result<Self> {
    let (host, addr) = uri_to_host_addr(uri)?;
    Ok(Proxy::HTTP(HttpProxy {
      uri: uri.clone(),
      https: false,
      auth: None,
      addr,
      host,
    }))
  }

  fn https(uri: &http::Uri) -> Result<Self> {
    let (host, addr) = uri_to_host_addr(uri)?;
    Ok(Proxy::HTTP(HttpProxy {
      uri: uri.clone(),
      https: true,
      auth: None,
      addr,
      host: host.to_string(),
    }))
  }
  fn socks5(uri: &http::Uri) -> Result<Self> {
    let (host, addr) = uri_to_host_addr(uri)?;
    Ok(Proxy::Socket(Socket5Proxy::new(
      uri.clone(),
      host.to_string(),
      addr,
      false,
    )))
  }
  fn socks5h(uri: &http::Uri) -> Result<Self> {
    let (host, addr) = uri_to_host_addr(uri)?;
    Ok(Proxy::Socket(Socket5Proxy::new(
      uri.clone(),
      host.to_string(),
      addr,
      true,
    )))
  }
  fn with_basic_auth<T: Into<String>, U: Into<String>>(mut self, username: T, password: U) -> Self {
    self.set_basic_auth(username, password);
    self
  }

  fn set_basic_auth<T: Into<String>, U: Into<String>>(&mut self, username: T, password: U) {
    match *self {
      Proxy::HTTP(HttpProxy { ref mut auth, .. }) => {
        let header = encode_basic_auth(username.into(), Some(&password.into()));
        *auth = Some(header);
      }
      Proxy::Socket(ref mut s) => {
        s.set_auth(username.into(), password.into());
      }
    }
  }
  /// Convert Proxy to a URL
  pub fn uri(&self) -> http::Uri {
    match self {
      Proxy::HTTP(http) => http.uri.clone(),
      Proxy::Socket(socket) => socket.uri.clone(),
    }
  }
  /// Convert a URL into a proxy
  ///
  /// Supported schemes: HTTP, HTTPS, (SOCKS5, SOCKS5H).
  pub fn parse<U>(url: U) -> Result<Self>
  where
    http::Uri: TryFrom<U>,
    <http::Uri as TryFrom<U>>::Error: Into<http::Error>,
  {
    let url: http::Uri = TryFrom::try_from(url).map_err(Into::into)?;
    let mut scheme = match url.scheme_str() {
      Some("http") => Self::http(&url)?,
      Some("https") => Self::https(&url)?,
      Some("socks5") => Self::socks5(&url)?,
      Some("socks5h") => Self::socks5h(&url)?,
      _ => {
        return Err(new_io_error(
          std::io::ErrorKind::NotConnected,
          "unknown proxy scheme",
        ));
      }
    };

    if let Some((username, Some(password))) = get_auth_from_authority(url.authority()) {
      let decoded_username = percent_decode(username.as_bytes()).decode_utf8_lossy();
      let decoded_password = percent_decode(password.as_bytes()).decode_utf8_lossy();
      scheme = scheme.with_basic_auth(decoded_username, decoded_password);
    }
    Ok(scheme)
  }
  fn to_addr(&self) -> Result<SocketAddr> {
    match self.clone() {
      Proxy::HTTP(HttpProxy { addr, .. }) => Ok(addr),
      Proxy::Socket(s) => Ok(s.addr()),
    }
  }
  #[cfg(feature = "tls")]
  fn domain(&self) -> Result<&str> {
    match self {
      Proxy::HTTP(HttpProxy { host, .. }) => Ok(host.as_str()),
      Proxy::Socket(s) => Ok(s.host()),
    }
  }
}
fn uri_to_host_addr(uri: &http::Uri) -> Result<(String, SocketAddr)> {
  let host = uri.host().ok_or(new_io_error(
    std::io::ErrorKind::InvalidData,
    "url not host",
  ))?;
  let to_addr = || {
    let port = match uri.port_u16() {
      None => match uri.scheme_str() {
        Some("socks5") | Some("socks5h") => Some(1080),
        Some("http") => Some(80),
        Some("https") => Some(443),
        _ => None,
      },
      Some(p) => Some(p),
    }
    .ok_or(new_io_error(
      std::io::ErrorKind::InvalidData,
      "no port in url",
    ))?;
    (host, port).to_socket_addrs()?.next().ok_or(new_io_error(
      std::io::ErrorKind::InvalidData,
      "no addr in url",
    ))
  };
  Ok((host.to_string(), to_addr()?))
}
fn get_auth_from_authority(authority: Option<&Authority>) -> Option<(String, Option<String>)> {
  match authority {
    None => None,
    Some(authority) => {
      let mut full = authority.to_string();
      if full.contains('@') {
        if let Some(port) = authority.port() {
          if let Some(remove) = full.strip_suffix(&format!(":{}", port.as_str())) {
            full = remove.to_string();
          }
        }
        if let Some(remove) = full.strip_suffix(authority.host()) {
          full = remove.to_string();
        }
        let at = full.pop();
        if at.is_none() {
          return None;
        } else if let Some((username, password)) = full.split_once(':') {
          let password = if password.is_empty() {
            None
          } else {
            Some(password.to_string())
          };
          return Some((username.to_string(), password));
        }
      }
      None
    }
  }
}

pub fn encode_basic_auth<U, P>(username: U, password: Option<P>) -> HeaderValue
where
  U: std::fmt::Display,
  P: std::fmt::Display,
{
  use base64::prelude::BASE64_STANDARD;
  use base64::write::EncoderWriter;

  let mut buf = b"Basic ".to_vec();
  {
    let mut encoder = EncoderWriter::new(&mut buf, &BASE64_STANDARD);
    encoder
      .write_fmt(format_args!("{}", &username))
      .unwrap_or_default();
    if let Some(password) = password {
      encoder
        .write_fmt(format_args!("{}", &password))
        .unwrap_or_default();
    }
  }
  let mut header = HeaderValue::from_bytes(&buf).expect("base64 is always valid HeaderValue");
  header.set_sensitive(true);
  header
}

/// Configuration of a proxy that a `Client` should pass requests to.
///
/// A `Proxy` has a couple pieces to it:
///
/// - a URL of how to talk to the proxy
/// - rules on what `Client` requests should be directed to the proxy
///
/// For instance, let's look at `Proxy::http`:
///
/// ```rust
/// # fn run() -> Result<(), Box<dyn std::error::Error>> {
/// let proxy = slinger::Proxy::parse("https://secure.example")?;
/// # Ok(())
/// # }
/// ```
///
/// This proxy will intercept all HTTP requests, and make use of the proxy
/// at `https://secure.example`. A request to `http://hyper.rs` will talk
/// to your proxy. A request to `https://hyper.rs` will not.
///
/// Multiple `Proxy` rules can be configured for a `Client`. The `Client` will
/// check each `Proxy` in the order it was added. This could mean that a
/// `Proxy` added first with eager intercept rules, such as `Proxy::all`,
/// would prevent a `Proxy` later in the list from ever working, so take care.
///
/// By enabling the `"socks"` feature it is possible to use a socks proxy:
/// ```rust
/// # fn run() -> Result<(), Box<dyn std::error::Error>> {
/// let proxy = slinger::Proxy::parse("socks5://192.168.1.1:9000")?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, PartialEq)]
pub enum Proxy {
  /// HTTP or HTTPS
  HTTP(HttpProxy),
  /// SOCKS5
  Socket(Socket5Proxy),
}

/// A particular scheme used for proxying requests.
///
/// For example, HTTP
#[derive(Clone, Debug, PartialEq)]
pub struct HttpProxy {
  uri: http::Uri,
  https: bool,
  auth: Option<HeaderValue>,
  addr: SocketAddr,
  host: String,
}

impl HttpProxy {
  fn raw(&self, host_port: &str) -> Result<Bytes> {
    // 生成隧道报文
    let mut br = Request::builder()
      .version(http::version::Version::HTTP_11)
      .uri(http::Uri::builder().path_and_query(host_port).build()?)
      .method(http::method::Method::CONNECT)
      .header("Host", host_port)
      .header("Proxy-Connection", "Keep-Alive");
    if let Some(auth) = &self.auth {
      br = br.header("Proxy-Authorization", auth);
    }
    let br: Request = br.body(None)?.into();
    Ok(br.to_raw())
  }
  #[allow(clippy::unused_io_amount)]
  async fn read_resp(&self, proxy_socket: &mut Socket) -> Result<Response> {
    let mut buffer = [0; 128];
    proxy_socket.read(&mut buffer[..]).await?;
    let reader = tokio::io::BufReader::new(buffer.as_slice());
    let proxy_response = ResponseBuilder::new(reader, Default::default())
      .build()
      .await?;
    if proxy_response.status_code() != http::StatusCode::OK {
      return Err(new_io_error(
        std::io::ErrorKind::NotConnected,
        "not connect proxy",
      ));
    }
    Ok(proxy_response)
  }
}

/// A particular scheme used for proxying requests.
///
/// For example, SOCKS5
#[derive(Clone, Debug, PartialEq)]
pub struct ProxySocket {
  target: http::Uri,
  proxy: Option<Proxy>,
}

impl ProxySocket {
  /// new ProxySocket
  pub fn new(target: &http::Uri, proxy: &Option<Proxy>) -> Self {
    Self {
      target: target.clone(),
      proxy: proxy.clone(),
    }
  }
  /// Connects to a target server through a connector
  pub async fn conn_with_connector(self, connector: &Connector) -> Result<Socket> {
    let addr = self.get_conn_addr()?;
    let mut socket = connector.connect_with_addr(addr).await?;
    match &self.proxy {
      None => {
        let _target_host = self.target.host().ok_or(new_io_error(
          std::io::ErrorKind::InvalidData,
          "no host in url",
        ))?;
        #[cfg(feature = "tls")]
        if self.target.scheme() == Some(&http::uri::Scheme::HTTPS) {
          socket = connector.upgrade_to_tls(socket, _target_host).await?;
        }
        Ok(socket)
      }
      Some(proxy) => {
        let target_host = self.target.host().ok_or(new_io_error(
          std::io::ErrorKind::InvalidData,
          "no host in url",
        ))?;
        let port = match self.target.port() {
          Some(p) => p.as_u16(),
          None => {
            if self.target.scheme() == Some(&http::uri::Scheme::HTTPS) {
              443u16
            } else {
              80u16
            }
          }
        };
        match proxy {
          Proxy::HTTP(h) => {
            #[cfg(feature = "tls")]
            if h.https {
              socket = connector.upgrade_to_tls(socket, proxy.domain()?).await?;
            }
            socket
              .write_all(&h.raw(&format!("{}:{}", target_host, port))?)
              .await?;
            socket.flush().await?;
            h.read_resp(&mut socket).await?;
            #[cfg(feature = "tls")]
            if self.target.scheme() == Some(&http::uri::Scheme::HTTPS) {
              socket = connector.upgrade_to_tls(socket, target_host).await?;
            }
            Ok(socket)
          }
          Proxy::Socket(s) => {
            s.conn(&mut socket, &self.target).await?;
            Ok(socket)
          }
        }
      }
    }
  }
  fn get_conn_addr(&self) -> Result<SocketAddr> {
    // 获取连接地址，如果有代理先返回代理地址
    match &self.proxy {
      None => {
        let original_host = self.target.host().ok_or(new_io_error(
          std::io::ErrorKind::InvalidData,
          "no host in url",
        ))?;
        let port = default_port(&self.target).ok_or(new_io_error(
          std::io::ErrorKind::InvalidData,
          "no port in url",
        ))?;
        let target_addr = (original_host, port)
          .to_socket_addrs()?
          .next()
          .ok_or(new_io_error(
            std::io::ErrorKind::InvalidData,
            "no addr in url",
          ))?;
        Ok(target_addr)
      }
      Some(proxy) => {
        let proxy_addr = proxy.to_addr()?;
        Ok(proxy_addr)
      }
    }
  }
}

fn default_port(uri: &http::Uri) -> Option<u16> {
  match uri.port_u16() {
    Some(p) => Some(p),
    None => match uri.scheme_str() {
      Some("https") => Some(443u16),
      Some("http") => Some(80u16),
      Some("socks5") | Some("socks5h") => Some(1080u16),
      _ => None,
    },
  }
}

/// A SOCKS5 client.
///
/// For convenience, it can be dereferenced to its inner socket.
#[derive(Clone, Debug, PartialEq)]
pub struct Socket5Proxy {
  uri: http::Uri,
  host: String,
  addr: SocketAddr,
  auth: Option<AuthenticationMethod>,
  remote_dns: bool,
}

impl Socket5Proxy {
  fn new(uri: http::Uri, host: String, addr: SocketAddr, remote_dns: bool) -> Self {
    Socket5Proxy {
      uri,
      host,
      addr,
      auth: None,
      remote_dns,
    }
  }
  fn set_auth(&mut self, username: String, password: String) {
    self.auth = Some(AuthenticationMethod::Password { username, password });
  }
  #[cfg(feature = "tls")]
  pub(crate) fn host(&self) -> &str {
    &self.host
  }
  pub(crate) fn addr(&self) -> SocketAddr {
    self.addr
  }
  pub(crate) async fn conn(&self, socket: &mut Socket, target: &http::Uri) -> Result<()> {
    // 协商认证方式
    let method = self.version_methods(socket).await?;
    // 确认认证方式
    let auth_methods = self.which_method_accepted(socket, method).await?;
    // 认证身份
    self.use_password_auth(socket, auth_methods).await?;
    // 发送代理请求
    self
      .request_header(socket, target, Socks5Command::TCPConnect)
      .await?;
    // 连接目标服务器
    self.read_request_reply(socket).await?;
    Ok(())
  }
  /// 首先，客户端向服务器发送一条包含协议版本号和可选验证方法的消息：
  ///
  /// | 字段 | 描述 | 类型 | 长度 | 例值 |
  /// | --- | --- | --- | --- | --- |
  /// | VER | 协议版本号 | unsigned char | 1 | 0x05 |
  /// | NMETHODS | 客户端支持的方法数量决定 METHODS 的长度 | unsigned char | 1 | 1 - 255 |
  /// | METHODS | 客户端支持的方法列表一个字节对应一个方法 | unsigned char [] | 可变长度1-255 | 0x02 用户名密码验证 |
  ///
  async fn version_methods(&self, proxy_socket: &mut Socket) -> Result<&AuthenticationMethod> {
    let mut main_method = &AuthenticationMethod::None;
    let mut methods = vec![main_method];
    if let Some(method) = &self.auth {
      methods.push(method);
      main_method = method;
    }
    let mut packet = vec![consts::SOCKS5_VERSION, methods.len() as u8];
    let auth: Vec<u8> = methods.into_iter().map(|l| l.into()).collect::<Vec<_>>();
    packet.extend(auth);
    proxy_socket.write_all(&packet).await?;
    Ok(main_method)
  }
  // 身份认证
  /// 如果服务器返回的方法不为 0x00 ，则需要进入子协商阶段，即身份验证阶段。本文实现的客户端仅支持用户名密码的验证方式。客户端向服务端发送一条包含用户名和密码的消息：
  ///
  /// | 字段 | 描述 | 类型 | 长度 | 例值 |
  /// | --- | --- | --- | --- | --- |
  /// | VER | 协议版本号 | unsigned char | 1 | 0x05 |
  /// | ULEN | 用户名长度 | unsigned char | 1 |  |
  /// | UNAME | 用户名 | unsigned char [] | 可变长度1-255 |  |
  /// | PLEN | 密码长度 | unsigned char | 1 |  |
  /// | PASSWD | 密码 | unsigned char [] | 可变长度1-255 |  |
  ///
  ///服务器收到消息后返回验证结果：
  ///
  /// | 字段 | 描述 | 类型 | 长度 | 例值 |
  /// | --- | --- | --- | --- | --- |
  /// | VER | 协议版本号 | unsigned char | 1 | 0x05 |
  /// | STATUS | 验证结果 | unsigned char | 1 | 0x00 成功 |
  async fn use_password_auth(
    &self,
    proxy_socket: &mut Socket,
    method: AuthenticationMethod,
  ) -> Result<bool> {
    if let AuthenticationMethod::Password { username, password } = method {
      let user_bytes = username.as_bytes();
      let pass_bytes = password.as_bytes();

      let mut packet: Vec<u8> = vec![1, user_bytes.len() as u8];
      packet.extend(user_bytes);
      packet.push(pass_bytes.len() as u8);
      packet.extend(pass_bytes);

      proxy_socket.write_all(&packet).await?;
      let mut buf = [0u8, 2];
      proxy_socket.read_exact(&mut buf).await?;
      let [_version, is_success] = buf;
      if is_success != consts::SOCKS5_REPLY_SUCCEEDED {
        return Err(Error::Other(format!(
          "Authentication with username `{}`, rejected.",
          username
        )));
      }
      return Ok(is_success != 0);
    }
    Ok(true)
  }
  /// 服务器会在客户端支持的方法中选择一个，并返回消息：
  ///
  /// | 字段 | 描述 | 类型 | 长度 | 例值 |
  /// | --- | --- | --- | --- | --- |
  /// | VER | 协议版本号 | unsigned char | 1 | 0x05 |
  /// | METHOD | 服务端选择的可用方法 | unsigned char | 1 | 0x00 不需要身份验证0x02 用户名密码验证0xFF 无可接受的方法 |
  ///
  /// 身份验证方法（ METHOD ）的全部可选值如下：
  ///
  /// - **0x00 不需要身份验证（ NO AUTHENTICATION REQUIRED ）**
  /// - 0x01 [GSSAPI](https://en.wikipedia.org/wiki/Generic_Security_Services_Application_Program_Interface)
  /// - **0x02 用户名密码（ USERNAME/PASSWORD ）**
  /// - 0x03 至 0x7F 由 IANA 分配（ IANA ASSIGNED ）
  /// - 0x80 至 0xFE 为私人方法保留（ RESERVED FOR PRIVATE METHODS ）
  /// - **0xFF 无可接受的方法（ NO ACCEPTABLE METHODS ）**
  async fn which_method_accepted(
    &self,
    proxy_socket: &mut Socket,
    auth_method: &AuthenticationMethod,
  ) -> Result<AuthenticationMethod> {
    let mut buf = [0u8; 2];
    proxy_socket.read_exact(&mut buf).await?;
    let [version, method] = buf;
    if version != consts::SOCKS5_VERSION {
      return Err(new_io_error(
        std::io::ErrorKind::InvalidData,
        "unsupported SOCKS version",
      ));
    }
    match method {
      consts::SOCKS5_AUTH_METHOD_NONE => Ok(AuthenticationMethod::None),
      consts::SOCKS5_AUTH_METHOD_PASSWORD => Ok(auth_method.clone()),
      _ => {
        proxy_socket
          .write_all(&[
            consts::SOCKS5_VERSION,
            consts::SOCKS5_AUTH_METHOD_NOT_ACCEPTABLE,
          ])
          .await?;
        Err(Error::Other("no acceptable auth methods".to_string()))
      }
    }
  }
  /// 协商验证通过后，客户端向服务器发送代理请求消息：
  ///
  /// | 字段 | 描述 | 类型 | 长度 | 例值 |
  /// | --- | --- | --- | --- | --- |
  /// | VER | 协议版本号 | unsigned char | 1 | 0x05 |
  /// | CMD | 命令类型 | unsigned char | 1 | 0x01 CONNECT0x02 BIND0x03 UDP ASSOCIATE |
  /// | RSV | 保留字段 | unsigned char | 1 | 0x00 |
  /// | ATYP | 目标地址类型 | unsigned char | 1 | 0x01 IPv40x03 域名0x04 IPv6 |
  /// | DST.ADDR | 目标地址 | unsigned char [] | 可变长度4 (IPv4)16 (IPv6)域名另见下表 |  |
  /// | DST.PORT | 目标端口 | unsigned short | 2 |  |
  async fn request_header(
    &self,
    proxy_socket: &mut Socket,
    target: &http::Uri,
    cmd: Socks5Command,
  ) -> Result<TargetAddr> {
    let target = TargetAddr::from_uri(target, self.remote_dns)?;
    let (padding, packet) = target.to_be_bytes(cmd)?;
    proxy_socket.write_all(&packet[..padding]).await?;
    proxy_socket.flush().await?;
    Ok(target)
  }
  /// 服务器收到代理请求后会响应如下消息：
  ///
  /// | 字段 | 描述 | 类型 | 长度 | 例值 |
  /// | --- | --- | --- | --- | --- |
  /// | VER | 协议版本号 | unsigned char | 1 | 0x05 |
  /// | REP | 服务器应答 | unsigned char | 1 | 0x00 成功 |
  /// | RSV | 保留字段 | unsigned char | 1 | 0x00 |
  /// | ATYP | 目标地址类型 | unsigned char | 1 | 0x01 IPv40x04 IPv6 |
  /// | BND.ADDR | 绑定地址 | unsigned char [] | 可变长度4 (IPv4)16 (IPv6) |  |
  /// | BND.PORT | 绑定端口 | unsigned short | 2 |  |
  ///
  async fn read_request_reply(&self, proxy_socket: &mut Socket) -> Result<TargetAddr> {
    let mut buf = [0u8; 4];
    proxy_socket.read_exact(&mut buf).await?;
    let [version, reply, _rsv, address_type] = buf;
    if version != consts::SOCKS5_VERSION {
      return Err(Error::Other(format!("version {:?}", version)));
    }
    if reply != consts::SOCKS5_REPLY_SUCCEEDED {
      return Err(Error::ReplyError(ReplyError::from(reply))); // Convert reply received into correct error
    }
    let address = read_address(proxy_socket, address_type).await?;
    Ok(address)
  }
}

async fn read_port(proxy_socket: &mut Socket) -> Result<u16> {
  // Find port number
  let mut port = [0u8; 2];
  proxy_socket.read_exact(&mut port).await?;
  // Convert (u8 * 2) into u16
  let port = ((port[0] as u16) << 8) | port[1] as u16;
  Ok(port)
}

/// 如果 ATYP 字段值是 0x03，则 DST.ADDR 的格式为：
///
/// | 字段 | 描述 | 类型 | 长度 |
/// | --- | --- | --- | --- |
/// | DLEN | 域名长度 | unsigned char | 1 |
/// | DOMAIN | 域名 | unsigned char [] | 可变长度1-255 |
async fn read_address(proxy_socket: &mut Socket, addr_type: u8) -> Result<TargetAddr> {
  let addr = match addr_type {
    consts::SOCKS5_ADDR_TYPE_IPV4 => {
      let mut buf = [0u8; 4];
      proxy_socket.read_exact(&mut buf).await?;
      let [a, b, c, d] = buf;
      TargetAddr::IP(SocketAddr::V4(SocketAddrV4::new(
        Ipv4Addr::new(a, b, c, d),
        read_port(proxy_socket).await?,
      )))
    }
    consts::SOCKS5_ADDR_TYPE_IPV6 => {
      let mut buf = [0u8; 16];
      proxy_socket.read_exact(&mut buf).await?;
      TargetAddr::IP(SocketAddr::V6(SocketAddrV6::new(
        Ipv6Addr::from(buf),
        read_port(proxy_socket).await?,
        0,
        0,
      )))
    }
    consts::SOCKS5_ADDR_TYPE_DOMAIN_NAME => {
      let mut len = [0u8];
      proxy_socket.read_exact(&mut len).await?;
      let mut domain = vec![0u8; len[0] as usize];
      proxy_socket.read_exact(&mut domain).await?;
      TargetAddr::Domain(
        String::from_utf8_lossy(&domain).to_string(),
        read_port(proxy_socket).await?,
      )
    }
    _ => return Err(Error::Other("IncorrectAddressType".to_string())),
  };
  Ok(addr)
}

#[derive(Debug, PartialEq)]
enum Socks5Command {
  /// CONNECT 代理 TCP 流量
  TCPConnect,
  // /// BIND 代理开启监听端口，接收目标地址的连接
  // TCPBind,
  // /// UDP ASSOCIATE 代理 UDP 数据转发
  // UDPAssociate,
}

impl Socks5Command {
  #[inline]
  pub fn as_u8(&self) -> u8 {
    match self {
      Socks5Command::TCPConnect => consts::SOCKS5_CMD_TCP_CONNECT,
      // Socks5Command::TCPBind => consts::SOCKS5_CMD_TCP_BIND,
      // Socks5Command::UDPAssociate => consts::SOCKS5_CMD_UDP_ASSOCIATE,
    }
  }
}

// socket5 代理连接模块，连接完成后返回内部socket
#[derive(Debug, Clone, PartialEq)]
enum TargetAddr {
  // IPV4 IPV6
  IP(SocketAddr),
  // 域名
  Domain(String, u16),
}

#[derive(Debug, PartialEq, Clone)]
enum AuthenticationMethod {
  None,
  Password { username: String, password: String },
}

impl From<&AuthenticationMethod> for u8 {
  fn from(val: &AuthenticationMethod) -> Self {
    match val {
      AuthenticationMethod::None => consts::SOCKS5_AUTH_METHOD_NONE,
      AuthenticationMethod::Password { .. } => consts::SOCKS5_AUTH_METHOD_PASSWORD,
    }
  }
}

impl TargetAddr {
  pub fn from_uri(value: &http::Uri, remote_dns: bool) -> Result<Self> {
    let port = default_port(value).ok_or(new_io_error(
      std::io::ErrorKind::InvalidData,
      "not found port",
    ))?;
    let host = value.host().ok_or(new_io_error(
      std::io::ErrorKind::InvalidData,
      "not found host",
    ))?;
    if let Ok(ip) = IpAddr::from_str(host) {
      Ok(TargetAddr::IP(SocketAddr::new(ip, port)))
    } else {
      // 如果是使用远程DNS直接传域名过去让远程代理那边解析DNS，不是就本地解析到IP
      if !remote_dns {
        Ok(TargetAddr::IP(
          (host, port).to_socket_addrs()?.next().ok_or(new_io_error(
            std::io::ErrorKind::InvalidData,
            "url not addr",
          ))?,
        ))
      } else {
        Ok(TargetAddr::Domain(host.to_string(), port))
      }
    }
  }
  pub fn to_be_bytes(&self, cmd: Socks5Command) -> Result<(usize, Vec<u8>)> {
    let mut packet = [0u8; consts::MAX_ADDR_LEN + 3];
    let padding;
    packet[..3].copy_from_slice(&[consts::SOCKS5_VERSION, cmd.as_u8(), 0x00]);
    match self {
      TargetAddr::IP(SocketAddr::V4(addr)) => {
        padding = 10;

        packet[3] = 0x01;
        packet[4..8].copy_from_slice(&addr.ip().octets()); // ip
        packet[8..padding].copy_from_slice(&addr.port().to_be_bytes());
      }
      TargetAddr::IP(SocketAddr::V6(addr)) => {
        padding = 22;

        packet[3] = 0x04;
        packet[4..20].copy_from_slice(&addr.ip().octets()); // ip
        packet[20..padding].copy_from_slice(&addr.port().to_be_bytes());
      }
      TargetAddr::Domain(ref domain, port) => {
        if domain.len() > u8::MAX as usize {
          return Err(new_io_error(
            std::io::ErrorKind::InvalidData,
            "domain name too long",
          ));
        }
        padding = 5 + domain.len() + 2;
        packet[3] = 0x03; // Specify domain type
        packet[4] = domain.len() as u8; // domain length
        packet[5..(5 + domain.len())].copy_from_slice(domain.as_bytes()); // domain content
        packet[(5 + domain.len())..padding].copy_from_slice(&port.to_be_bytes());
      }
    }
    Ok((padding, packet.to_vec()))
  }
}

impl From<u8> for ReplyError {
  /// 服务器响应消息中的 REP 字段如果不为 0x00 ，则表示请求失败。不同值的具体含义如下：
  ///
  /// - 0x00 成功
  /// - 0x01 常规 SOCKS 服务器故障
  /// - 0x02 规则不允许的链接
  /// - 0x03 网络无法访问
  /// - 0x04 主机无法访问
  /// - 0x05 连接被拒绝
  /// - 0x06 TTL 过期
  /// - 0x07 不支持的命令
  /// - 0x08 不支持的地址类型
  ///
  fn from(value: u8) -> Self {
    match value {
      consts::SOCKS5_REPLY_SUCCEEDED => ReplyError::Succeeded,
      consts::SOCKS5_REPLY_GENERAL_FAILURE => ReplyError::GeneralFailure,
      consts::SOCKS5_REPLY_CONNECTION_NOT_ALLOWED => ReplyError::ConnectionNotAllowed,
      consts::SOCKS5_REPLY_NETWORK_UNREACHABLE => ReplyError::NetworkUnreachable,
      consts::SOCKS5_REPLY_HOST_UNREACHABLE => ReplyError::HostUnreachable,
      consts::SOCKS5_REPLY_CONNECTION_REFUSED => ReplyError::ConnectionRefused,
      consts::SOCKS5_REPLY_TTL_EXPIRED => ReplyError::TtlExpired,
      consts::SOCKS5_REPLY_COMMAND_NOT_SUPPORTED => ReplyError::CommandNotSupported,
      consts::SOCKS5_REPLY_ADDRESS_TYPE_NOT_SUPPORTED => ReplyError::AddressTypeNotSupported,
      _ => unreachable!("ReplyError code unsupported."),
    }
  }
}

#[rustfmt::skip]
pub mod consts {
  pub const MAX_ADDR_LEN: usize = 260;
  pub const SOCKS5_VERSION: u8 = 0x05;

  pub const SOCKS5_AUTH_METHOD_NONE: u8 = 0x00;
  // pub const SOCKS5_AUTH_METHOD_GSSAPI: u8 = 0x01;
  pub const SOCKS5_AUTH_METHOD_PASSWORD: u8 = 0x02;
  pub const SOCKS5_AUTH_METHOD_NOT_ACCEPTABLE: u8 = 0xff;

  pub const SOCKS5_CMD_TCP_CONNECT: u8 = 0x01;
  // pub const SOCKS5_CMD_TCP_BIND: u8 = 0x02;
  // pub const SOCKS5_CMD_UDP_ASSOCIATE: u8 = 0x03;

  pub const SOCKS5_ADDR_TYPE_IPV4: u8 = 0x01;
  pub const SOCKS5_ADDR_TYPE_DOMAIN_NAME: u8 = 0x03;
  pub const SOCKS5_ADDR_TYPE_IPV6: u8 = 0x04;

  pub const SOCKS5_REPLY_SUCCEEDED: u8 = 0x00;
  pub const SOCKS5_REPLY_GENERAL_FAILURE: u8 = 0x01;
  pub const SOCKS5_REPLY_CONNECTION_NOT_ALLOWED: u8 = 0x02;
  pub const SOCKS5_REPLY_NETWORK_UNREACHABLE: u8 = 0x03;
  pub const SOCKS5_REPLY_HOST_UNREACHABLE: u8 = 0x04;
  pub const SOCKS5_REPLY_CONNECTION_REFUSED: u8 = 0x05;
  pub const SOCKS5_REPLY_TTL_EXPIRED: u8 = 0x06;
  pub const SOCKS5_REPLY_COMMAND_NOT_SUPPORTED: u8 = 0x07;
  pub const SOCKS5_REPLY_ADDRESS_TYPE_NOT_SUPPORTED: u8 = 0x08;
}
