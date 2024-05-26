#[cfg(feature = "cookie")]
use crate::cookies;
use crate::errors::{new_io_error, Result};
use crate::proxy::Proxy;
use crate::record::{HTTPRecord, HttpInfo};
use crate::redirect::{remove_sensitive_headers, Action, Policy};
use crate::response::{ResponseBuilder, ResponseConfig};
use crate::socket::Socket;
use crate::{Connector, ConnectorBuilder, Request, RequestBuilder, Response};
use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method, StatusCode};
#[cfg(feature = "tls")]
use native_tls::{Certificate, Identity};
use std::collections::HashMap;
use std::io::{BufReader, Write};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
#[cfg(feature = "tls")]
use openssl::x509::X509;

/// A `Client` to make Requests with.
///
/// The Client has various configuration values to tweak, but the defaults
/// are set to what is usually the most commonly desired value. To configure a
/// `Client`, use `Client::builder()`.
///
/// The `Client` holds a connection pool internally, so it is advised that
/// you create one and **reuse** it.
///
/// # Examples
///
/// ```rust
/// use slinger::Client;
/// #
/// # fn run() -> Result<(), slinger::Error> {
/// let client = Client::new();
/// let resp = client.get("http://httpbin.org/").send()?;
/// #   Ok(())
/// # }
///
/// ```
#[derive(Clone, Debug)]
pub struct Client {
  inner: ClientRef,
}

impl Default for Client {
  fn default() -> Self {
    Self::new()
  }
}

impl Client {
  /// Constructs a new `Client`.
  ///
  /// # Panic
  ///
  /// This method panics if TLS backend cannot be initialized, or the resolver
  /// cannot load the system configuration.
  ///
  /// Use `Client::builder()` if you wish to handle the failure as an `Error`
  /// instead of panicking.
  ///
  /// See docs
  /// on [`slinger`][Client] for details.
  pub fn new() -> Client {
    ClientBuilder::new().build().expect("Client::new()")
  }
  /// Creates a `ClientBuilder` to configure a `Client`.
  ///
  /// This is the same as `ClientBuilder::new()`.
  pub fn builder() -> ClientBuilder {
    ClientBuilder::new()
  }
  /// Convenience method to make a `GET` request to a URL.
  ///
  /// # Errors
  ///
  /// This method fails whenever supplied `Uri` cannot be parsed.
  pub fn get<U>(&self, url: U) -> RequestBuilder
    where
      http::Uri: TryFrom<U>,
      <http::Uri as TryFrom<U>>::Error: Into<http::Error>,
  {
    self.request(Method::GET, url)
  }
  /// Convenience method to make a `POST` request to a URL.
  ///
  /// # Errors
  ///
  /// This method fails whenever supplied `Uri` cannot be parsed.
  pub fn post<U>(&self, url: U) -> RequestBuilder
    where
      http::Uri: TryFrom<U>,
      <http::Uri as TryFrom<U>>::Error: Into<http::Error>,
  {
    self.request(Method::POST, url)
  }
  /// Convenience method to make a `PUT` request to a URL.
  ///
  /// # Errors
  ///
  /// This method fails whenever supplied `Uri` cannot be parsed.
  pub fn put<U>(&self, url: U) -> RequestBuilder
    where
      http::Uri: TryFrom<U>,
      <http::Uri as TryFrom<U>>::Error: Into<http::Error>,
  {
    self.request(Method::PUT, url)
  }
  /// Convenience method to make a `PATCH` request to a URL.
  ///
  /// # Errors
  ///
  /// This method fails whenever supplied `Uri` cannot be parsed.
  pub fn patch<U>(&self, url: U) -> RequestBuilder
    where
      http::Uri: TryFrom<U>,
      <http::Uri as TryFrom<U>>::Error: Into<http::Error>,
  {
    self.request(Method::PATCH, url)
  }
  /// Convenience method to make a `DELETE` request to a URL.
  ///
  /// # Errors
  ///
  /// This method fails whenever supplied `Uri` cannot be parsed.
  pub fn delete<U>(&self, url: U) -> RequestBuilder
    where
      http::Uri: TryFrom<U>,
      <http::Uri as TryFrom<U>>::Error: Into<http::Error>,
  {
    self.request(Method::DELETE, url)
  }
  /// Convenience method to make a `HEAD` request to a URL.
  ///
  /// # Errors
  ///
  /// This method fails whenever supplied `Uri` cannot be parsed.
  pub fn head<U>(&self, url: U) -> RequestBuilder
    where
      http::Uri: TryFrom<U>,
      <http::Uri as TryFrom<U>>::Error: Into<http::Error>,
  {
    self.request(Method::HEAD, url)
  }
  /// Convenience method to make a `TRACE` request to a URL.
  ///
  /// # Errors
  ///
  /// This method fails whenever supplied `Uri` cannot be parsed.
  pub fn trace<U>(&self, url: U) -> RequestBuilder
    where
      http::Uri: TryFrom<U>,
      <http::Uri as TryFrom<U>>::Error: Into<http::Error>,
  {
    self.request(Method::TRACE, url)
  }
  /// Convenience method to make a `CONNECT` request to a URL.
  ///
  /// # Errors
  ///
  /// This method fails whenever supplied `Uri` cannot be parsed.
  pub fn connect<U>(&self, url: U) -> RequestBuilder
    where
      http::Uri: TryFrom<U>,
      <http::Uri as TryFrom<U>>::Error: Into<http::Error>,
  {
    self.request(Method::CONNECT, url)
  }
  /// Convenience method to make a `OPTIONS` request to a URL.
  ///
  /// # Errors
  ///
  /// This method fails whenever supplied `Uri` cannot be parsed.
  pub fn options<U>(&self, url: U) -> RequestBuilder
    where
      http::Uri: TryFrom<U>,
      <http::Uri as TryFrom<U>>::Error: Into<http::Error>,
  {
    self.request(Method::OPTIONS, url)
  }
  /// Start building a `Request` with the `Method` and `Uri`.
  ///
  /// Returns a `RequestBuilder`, which will allow setting headers and
  /// request body before sending.
  ///
  /// # Errors
  ///
  /// This method fails whenever supplied `Uri` cannot be parsed.
  pub fn request<U>(&self, method: Method, url: U) -> RequestBuilder
    where
      http::Uri: TryFrom<U>,
      <http::Uri as TryFrom<U>>::Error: Into<http::Error>,
  {
    RequestBuilder::new(
      self.clone(),
      http::request::Builder::new().method(method).uri(url),
    )
  }
  /// Start building a `Request` with the `Method` and `Uri`.
  ///
  /// Returns a `RequestBuilder`, which will allow setting headers and
  /// request body before sending.
  ///
  /// # Errors
  ///
  /// This method fails whenever supplied `Uri` cannot be parsed.
  pub fn raw<U, R>(&self, uri: U, raw: R, unsafe_raw: bool) -> RequestBuilder
    where
      Bytes: From<R>,
      http::Uri: TryFrom<U>,
      <http::Uri as TryFrom<U>>::Error: Into<http::Error>,
  {
    let mut builder = RequestBuilder::new(self.clone(), http::request::Builder::new().uri(uri));
    builder = builder.raw(raw, unsafe_raw);
    builder
  }
  /// Executes a `Request`.
  ///
  /// A `Request` can be built manually with `Request::new()` or obtained
  /// from a RequestBuilder with `RequestBuilder::build()`.
  ///
  /// You should prefer to use the `RequestBuilder` and
  /// `RequestBuilder::send()`.
  ///
  /// # Errors
  ///
  /// This method fails if there was an error while sending request,
  /// or redirect limit was exhausted.
  pub fn execute_request(&self, socket: &mut Socket, request: &Request) -> Result<Response> {
    let raw: Bytes = request.to_raw();
    #[cfg(feature = "tls")]
    let mut certificate:Option<X509> = None;
    #[cfg(feature = "tls")]
    {
      if let Some(x509) = socket.peer_certificate() {
        certificate = Some(x509);
      }
    }
    socket.write_all(&raw)?;
    socket.flush()?;
    let reader = BufReader::new(socket);
    let mut irp =
      ResponseBuilder::new(reader, ResponseConfig::new(request.is_unsafe(), None)).build()?;
    *irp.url_mut() = request.uri().clone();
    #[cfg(feature = "tls")]
    {
      if let Some(cert) = certificate {
        irp.extensions_mut().insert(cert);
      }
    }
    Ok(irp)
  }
  /// Executes a `Request`.
  ///
  /// A `Request` can be built manually with `Request::new()` or obtained
  /// from a RequestBuilder with `RequestBuilder::build()`.
  ///
  /// You should prefer to use the `RequestBuilder` and
  /// `RequestBuilder::send()`.
  ///
  /// # Errors
  ///
  /// This method fails if there was an error while sending request,
  /// or redirect limit was exhausted.
  pub fn execute<R: Into<Request>>(&self, request: R) -> Result<Response> {
    let mut records = vec![];
    let mut request = request.into();
    let mut cur_uri = request.uri().clone();
    let mut uris = vec![];
    let mut conn: HashMap<String, Socket> = HashMap::new();
    // 连接一次，同一个主机地址下复用socket连接
    let uniq_key = |u: &http::Uri| -> String {
      let scheme = u.scheme_str().unwrap_or_default();
      let host = u.host().unwrap_or_default();
      let port = u.port_u16().unwrap_or_default();
      format!("{}{}{}", scheme, host, port)
    };
    loop {
      let mut record = HTTPRecord::default();
      // 设置cookie到请求头
      #[cfg(feature = "cookie")]
      {
        if let Some(cookie_store) = self.inner.cookie_store.as_ref() {
          if request.headers().get(http::header::COOKIE).is_none() {
            add_cookie_header(&mut request, &**cookie_store);
          }
        }
      }
      record.record_request(&request);
      let socket = conn
        .entry(uniq_key(&cur_uri))
        .or_insert(self.inner.connector.connect_with_uri(&cur_uri)?);
      let mut response = self.execute_request(socket, &request)?;
      if let (Ok(remote_addr), Ok(local_addr)) = (socket.peer_addr(), socket.local_addr()) {
        response
          .extensions_mut()
          .insert(HttpInfo::new(remote_addr, local_addr));
      };
      record.record_response(&response);
      records.push(record);
      // 原始请求不跳转
      if request.raw_request().is_some() {
        break;
      }
      // 保存请求头的cookie
      #[cfg(feature = "cookie")]
      {
        if let Some(ref cookie_store) = self.inner.cookie_store {
          let mut cookies =
            cookies::extract_response_cookie_headers(response.headers()).peekable();
          if cookies.peek().is_some() {
            cookie_store.set_cookies(&mut cookies, request.uri());
          }
        }
      }
      // 根据状态码判断是否应该跳转
      let should_redirect = match response.status_code() {
        StatusCode::MOVED_PERMANENTLY | StatusCode::FOUND | StatusCode::SEE_OTHER => {
          for header in &[
            http::header::TRANSFER_ENCODING,
            http::header::CONTENT_ENCODING,
            http::header::CONTENT_TYPE,
            http::header::CONTENT_LENGTH,
          ] {
            response.headers_mut().remove(header);
          }
          match request.method() {
            &Method::GET | &Method::HEAD => {}
            _ => {
              *request.method_mut() = Method::GET;
            }
          }
          true
        }
        StatusCode::TEMPORARY_REDIRECT | StatusCode::PERMANENT_REDIRECT => match response.body() {
          Some(body) => body.is_empty(),
          None => true,
        },
        _ => false,
      };
      // 如果要跳转，获取进入跳转策略流程
      if should_redirect {
        // 在请求头获取下一跳URL
        let loc = response
          .headers()
          .get(http::header::LOCATION)
          .and_then(|val| {
            let val = val.to_str().ok()?;
            if val.starts_with("https://") || val.starts_with("http://") {
              http::Uri::from_str(val).ok()
            } else {
              let path = PathBuf::from(cur_uri.path()).join(val);
              http::Uri::builder()
                .scheme(cur_uri.scheme_str().unwrap_or_default())
                .authority(cur_uri.authority()?.as_str())
                .path_and_query(path.to_string_lossy().as_ref())
                .build()
                .ok()
            }
          });
        // 清除来源
        if let Some(loc) = loc {
          if self.inner.referer {
            if let Some(referer) = make_referer(&loc, &cur_uri) {
              response
                .headers_mut()
                .insert(http::header::REFERER, referer);
            }
          }
          uris.push(cur_uri);
          // 生成策略
          let action =
            self
              .inner
              .redirect_policy
              .check(response.status_code(), &loc, uris.as_slice());
          match action {
            Action::Follow => {
              cur_uri = loc;
              *request.uri_mut() =
                http::Uri::from_str(&cur_uri.to_string()).map_err(http::Error::from)?;
              let mut headers = std::mem::replace(response.headers_mut(), HeaderMap::new());
              remove_sensitive_headers(&mut headers, &cur_uri, uris.as_slice());
              continue;
            }
            Action::Stop => {
              break;
            }
          }
        }
      }
      break;
    }
    for (_key, socket) in conn {
      socket.shutdown(std::net::Shutdown::Both)?;
    }
    let mut last_response = records
      .last()
      .ok_or(new_io_error(
        std::io::ErrorKind::NotFound,
        "not found record",
      ))?
      .response
      .clone();
    last_response.extensions_mut().insert(records);
    Ok(last_response)
  }
}

#[cfg(feature = "cookie")]
#[cfg_attr(docsrs, doc(cfg(feature = "cookies")))]
fn add_cookie_header(request: &mut Request, cookie_store: &dyn cookies::CookieStore) {
  if let Some(header) = cookie_store.cookies(request.uri()) {
    request.headers_mut().insert(http::header::COOKIE, header);
  }
}

fn make_referer(next: &http::Uri, previous: &http::Uri) -> Option<HeaderValue> {
  if next.scheme() == Some(&http::uri::Scheme::HTTP)
    && previous.scheme() == Some(&http::uri::Scheme::HTTPS)
  {
    return None;
  }
  let referer = previous.clone();
  let mut builder = http::uri::Uri::builder();
  if let Some(scheme) = referer.scheme_str() {
    builder = builder.scheme(scheme);
  }
  if let Some(host) = referer.host() {
    let mut host_port = host.to_string();
    if let Some(port) = referer.port() {
      host_port.push(':');
      host_port.push_str(port.as_str());
    };
    builder = builder.authority(host_port);
  };
  if let Some(path) = referer.path_and_query() {
    builder = builder.path_and_query(path.as_str());
  }
  HeaderValue::from_str(&builder.build().ok()?.to_string()).ok()
}

/// A `ClientBuilder` can be used to create a `Client` with  custom configuration.
///
/// # Example
///
/// ```
/// # fn run() -> Result<(), slinger::Error> {
/// use std::time::Duration;
///
/// let client = slinger::Client::builder()
///     .timeout(Duration::from_secs(10))
///     .build()?;
/// # Ok(())
/// # }
/// ```
#[must_use]
pub struct ClientBuilder {
  config: Config,
}

impl Default for ClientBuilder {
  fn default() -> Self {
    Self::new()
  }
}

impl ClientBuilder {
  /// Constructs a new `ClientBuilder`.
  ///
  /// This is the same as `Client::builder()`.
  pub fn new() -> ClientBuilder {
    let mut headers: HeaderMap<HeaderValue> = HeaderMap::with_capacity(2);
    headers.insert(http::header::ACCEPT, HeaderValue::from_static("*/*"));
    ClientBuilder {
      config: Config::default(),
    }
  }
  /// Returns a `Client` that uses this `ClientBuilder` configuration.
  ///
  /// # Errors
  ///
  /// This method fails if TLS backend cannot be initialized, or the resolver
  /// cannot load the system configuration.
  ///
  /// # Panics
  ///
  /// See docs on
  /// [`slinger::client`][Client] for details.
  pub fn build(self) -> Result<Client> {
    let config = self.config;
    let connector = ConnectorBuilder::default()
      .proxy(config.proxy)
      .nodelay(config.nodelay)
      .read_timeout(config.timeout)
      .connect_timeout(config.connect_timeout)
      .write_timeout(config.timeout)
      .build()?;
    Ok(Client {
      inner: ClientRef {
        #[cfg(feature = "cookie")]
        cookie_store: config.cookie_store,
        connector: Arc::new(connector),
        redirect_policy: config.redirect_policy,
        referer: config.referer,
      },
    })
  }
  // Higher-level options

  /// Sets the `User-Agent` header to be used by this client.
  ///
  /// # Example
  ///
  /// ```rust
  /// # fn doc() -> Result<(), slinger::Error> {
  /// // Name your user agent after your app?
  /// static APP_USER_AGENT: &str = concat!(
  ///     env!("CARGO_PKG_NAME"),
  ///     "/",
  ///     env!("CARGO_PKG_VERSION"),
  /// );
  ///
  /// let client = slinger::Client::builder()
  ///     .user_agent(APP_USER_AGENT)
  ///     .build()?;
  /// let res = client.get("https://www.rust-lang.org").send()?;
  /// # Ok(())
  /// # }
  /// ```
  pub fn user_agent<V>(mut self, value: V) -> ClientBuilder
    where
      V: Into<HeaderValue>,
  {
    self
      .config
      .headers
      .insert(http::header::USER_AGENT, value.into());
    self
  }
  /// Sets the default headers for every request.
  ///
  /// # Example
  ///
  /// ```rust
  /// use slinger::header;
  /// # fn build_client() -> Result<(), slinger::Error> {
  /// let mut headers = header::HeaderMap::new();
  /// headers.insert("X-MY-HEADER", header::HeaderValue::from_static("value"));
  /// headers.insert(header::AUTHORIZATION, header::HeaderValue::from_static("secret"));
  ///
  /// // Consider marking security-sensitive headers with `set_sensitive`.
  /// let mut auth_value = header::HeaderValue::from_static("secret");
  /// auth_value.set_sensitive(true);
  /// headers.insert(header::AUTHORIZATION, auth_value);
  ///
  /// // get a client builder
  /// let client = slinger::Client::builder()
  ///     .default_headers(headers)
  ///     .build()?;
  /// let res = client.get("https://www.rust-lang.org").send()?;
  /// # Ok(())
  /// # }
  /// ```
  pub fn default_headers(mut self, headers: HeaderMap) -> ClientBuilder {
    for (key, value) in headers.iter() {
      self.config.headers.insert(key, value.clone());
    }
    self
  }
  // Redirect options

  /// Set a `redirect::Policy` for this client.
  ///
  /// Default will follow redirects up to a maximum of 10.
  pub fn redirect(mut self, policy: Policy) -> ClientBuilder {
    self.config.redirect_policy = policy;
    self
  }
  /// Enable or disable automatic setting of the `Referer` header.
  ///
  /// Default is `true`.
  pub fn referer(mut self, enable: bool) -> ClientBuilder {
    self.config.referer = enable;
    self
  }
  // Proxy options

  /// Add a `Proxy` to the list of proxies the `Client` will use.
  ///
  /// # Note
  ///
  /// Adding a proxy will disable the automatic usage of the "system" proxy.
  pub fn proxy(mut self, proxy: Proxy) -> ClientBuilder {
    self.config.proxy = Some(proxy);
    self
  }
  // Timeout options

  /// Set a timeout for connect, read and write operations of a `Client`.
  ///
  /// Default is 30 seconds.
  ///
  /// Pass `None` to disable timeout.
  pub fn timeout(mut self, timeout: Duration) -> ClientBuilder {
    self.config.timeout = Some(timeout);
    self
  }
  /// Set a timeout for only the connect phase of a `Client`.
  ///
  /// Default is `None`.
  pub fn connect_timeout(mut self, timeout: Duration) -> ClientBuilder {
    self.config.connect_timeout = Some(timeout);
    self
  }
  // TCP options

  /// Set whether sockets have `TCP_NODELAY` enabled.
  ///
  /// Default is `true`.
  pub fn tcp_nodelay(mut self, enabled: bool) -> ClientBuilder {
    self.config.nodelay = enabled;
    self
  }
  #[cfg(feature = "tls")]
  // TLS options
  /// Add a custom root certificate.
  ///
  /// This allows connecting to a server that has a self-signed
  /// certificate for example. This **does not** replace the existing
  /// trusted store.
  ///
  /// # Example
  ///
  /// ```
  /// # use std::fs::File;
  /// # use std::io::Read;
  /// # fn build_client() -> Result<(), Box<dyn std::error::Error>> {
  /// // read a local binary DER encoded certificate
  /// let der = std::fs::read("my-cert.der")?;
  ///
  /// // create a certificate
  /// let cert = slinger::Certificate::from_der(&der)?;
  ///
  /// // get a client builder
  /// let client = slinger::Client::builder()
  ///     .add_root_certificate(cert)
  ///     .build()?;
  /// # drop(client);
  /// # Ok(())
  /// # }
  /// ```
  ///
  /// # Optional
  ///
  /// This requires the optional `default-tls`, `native-tls`, or `rustls-tls(-...)`
  /// feature to be enabled.
  pub fn add_root_certificate(mut self, cert: Certificate) -> ClientBuilder {
    self.config.root_certs.push(cert);
    self
  }
  #[cfg(feature = "tls")]
  /// Sets the identity to be used for client certificate authentication.
  ///
  /// # Optional
  ///
  /// This requires the optional `native-tls`
  pub fn identity(mut self, identity: Identity) -> ClientBuilder {
    self.config.identity = Some(identity);
    self
  }
  /// Controls the use of hostname verification.
  ///
  /// Defaults to `false`.
  ///
  /// # Warning
  ///
  /// You should think very carefully before you use this method. If
  /// hostname verification is not used, any valid certificate for any
  /// site will be trusted for use from any other. This introduces a
  /// significant vulnerability to man-in-the-middle attacks.
  ///
  /// # Optional
  ///
  /// This requires the optional `native-tls` feature to be enabled.
  pub fn danger_accept_invalid_hostnames(mut self, accept_invalid_hostname: bool) -> ClientBuilder {
    self.config.hostname_verification = !accept_invalid_hostname;
    self
  }
  /// Controls the use of certificate validation.
  ///
  /// Defaults to `false`.
  ///
  /// # Warning
  ///
  /// You should think very carefully before using this method. If
  /// invalid certificates are trusted, *any* certificate for *any* site
  /// will be trusted for use. This includes expired certificates. This
  /// introduces significant vulnerabilities, and should only be used
  /// as a last resort.
  pub fn danger_accept_invalid_certs(mut self, accept_invalid_certs: bool) -> ClientBuilder {
    self.config.certs_verification = !accept_invalid_certs;
    self
  }
  /// Controls the use of TLS server name indication.
  ///
  /// Defaults to `true`.
  pub fn tls_sni(mut self, tls_sni: bool) -> ClientBuilder {
    self.config.tls_sni = tls_sni;
    self
  }
  /// Enable a persistent cookie store for the client.
  ///
  /// Cookies received in responses will be preserved and included in
  /// additional requests.
  ///
  /// By default, no cookie store is used. Enabling the cookies
  /// # Optional
  ///
  /// This requires the optional `cookies` feature to be enabled.
  #[cfg(feature = "cookie")]
  #[cfg_attr(docsrs, doc(cfg(feature = "cookies")))]
  pub fn cookie_store(mut self, enable: bool) -> ClientBuilder {
    if enable {
      self.cookie_provider(Arc::new(cookies::Jar::default()))
    } else {
      self.config.cookie_store = None;
      self
    }
  }
  /// Set the persistent cookie store for the client.
  ///
  /// Cookies received in responses will be passed to this store, and
  /// additional requests will query this store for cookies.
  ///
  /// By default, no cookie store is used.
  ///
  /// # Optional
  ///
  /// This requires the optional `cookies` feature to be enabled.
  #[cfg(feature = "cookie")]
  #[cfg_attr(docsrs, doc(cfg(feature = "cookies")))]
  pub fn cookie_provider<C: cookies::CookieStore + 'static>(
    mut self,
    cookie_store: Arc<C>,
  ) -> ClientBuilder {
    self.config.cookie_store = Some(cookie_store as _);
    self
  }
}

struct Config {
  connect_timeout: Option<Duration>,
  headers: HeaderMap,
  referer: bool,
  proxy: Option<Proxy>,
  timeout: Option<Duration>,
  nodelay: bool,
  #[cfg(feature = "tls")]
  root_certs: Vec<Certificate>,
  #[cfg(feature = "tls")]
  identity: Option<Identity>,
  hostname_verification: bool,
  certs_verification: bool,
  tls_sni: bool,
  redirect_policy: Policy,
  #[cfg(feature = "cookie")]
  cookie_store: Option<Arc<dyn cookies::CookieStore>>,
}

impl Default for Config {
  fn default() -> Self {
    Self {
      connect_timeout: None,
      headers: Default::default(),
      referer: false,
      proxy: None,
      timeout: None,
      nodelay: false,
      #[cfg(feature = "tls")]
      root_certs: vec![],
      #[cfg(feature = "tls")]
      identity: None,
      hostname_verification: false,
      certs_verification: false,
      tls_sni: false,
      redirect_policy: Policy::Limit(10),
      #[cfg(feature = "cookie")]
      cookie_store: None,
    }
  }
}

#[derive(Clone, Debug)]
struct ClientRef {
  #[cfg(feature = "cookie")]
  cookie_store: Option<Arc<dyn cookies::CookieStore>>,
  connector: Arc<Connector>,
  redirect_policy: Policy,
  referer: bool,
}
