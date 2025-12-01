use std::collections::btree_map::Entry;
use std::collections::BTreeMap;
use std::fmt::{Debug, Formatter};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

#[cfg(feature = "cookie")]
use crate::cookies;
#[cfg(feature = "dns")]
use crate::dns::DnsResolver;
use crate::errors::{new_io_error, Result};
use crate::proxy::Proxy;
use crate::record::{HTTPRecord, RedirectRecord};
use crate::redirect::{remove_sensitive_headers, Action, Policy};
use crate::response::{ResponseBuilder, ResponseConfig};
use crate::socket::Socket;
#[cfg(feature = "tls")]
use crate::tls::{
  self, Certificate, CustomTlsConnector, CustomTlsStream, Identity, PeerCertificate,
};
use crate::{Connector, ConnectorBuilder, Request, RequestBuilder, Response};
use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method, StatusCode};

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
/// # async fn run() -> Result<(), slinger::Error> {
/// let client = Client::new();
/// let resp = client.get("http://httpbin.org/").send().await?;
/// #   Ok(())
/// # }
///
/// ```
#[derive(Clone)]
pub struct Client {
  inner: Arc<ClientRef>,
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
    ClientBuilder::default().build().expect("Client::new()")
  }
  /// Creates a `ClientBuilder` to configure a `Client`.
  ///
  /// This is the same as `ClientBuilder::default()`.
  pub fn builder() -> ClientBuilder {
    ClientBuilder::default()
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
  pub async fn execute_request(
    &self,
    socket_opt: Option<Socket>,
    request: &Request,
  ) -> Result<(Response, Option<Socket>)> {
    if let Some(mut socket) = socket_opt {
      #[cfg(feature = "http2")]
      {
        // Check if HTTP/2 was negotiated via ALPN
        if socket.is_http2_negotiated() {
          let response =
            crate::h2_client::send_h2_request(socket, request, self.inner.timeout).await?;
          return Ok((response, None));
        }
      }
      // HTTP/1.1 path (existing code)
      let raw: Bytes = request.to_raw();
      #[cfg(feature = "tls")]
      let mut peer_certificate: Option<Vec<PeerCertificate>> = None;
      #[cfg(feature = "tls")]
      {
        if let Some(pc) = socket.peer_certificate() {
          peer_certificate = Some(pc);
        }
      }
      socket.write_all(&raw).await?;
      socket.flush().await?;
      let reader = tokio::io::BufReader::new(socket);
      let (mut irp, socket) =
        ResponseBuilder::new(reader, ResponseConfig::new(request, self.inner.timeout))
          .build()
          .await?;
      *irp.url_mut() = request.uri().clone();
      #[cfg(feature = "tls")]
      {
        if let Some(cert) = peer_certificate {
          irp.extensions_mut().insert(cert);
        }
      }
      Ok((irp, Some(socket)))
    } else {
      Err(new_io_error(
        std::io::ErrorKind::NotConnected,
        "socket is None",
      ))
    }
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
  pub async fn execute<R: Into<Request>>(&self, request: R) -> Result<Response> {
    let mut records = vec![];
    let mut request = request.into();
    let mut cur_uri = request.uri().clone();
    let mut uris = vec![];
    let mut conn: BTreeMap<String, Option<Socket>> = BTreeMap::new();
    // 连接一次，同一个主机地址下复用socket连接
    let uniq_key = |u: &http::Uri| -> String {
      let scheme = u.scheme_str().unwrap_or_default();
      let host = u.host().unwrap_or_default();
      let port = u.port_u16().unwrap_or_default();
      format!("{}{}{}", scheme, host, port)
    };
    // 先默认尝试复用连接
    let mut keepalive = true;
    loop {
      let mut record = HTTPRecord::default();
      for (k, v) in self.inner.header.iter() {
        // 内置优先级低于用户配置的
        if request.headers().get(k).is_none() {
          request.headers_mut().insert(k, v.clone());
        }
      }
      // 设置cookie到请求头
      #[cfg(feature = "cookie")]
      {
        if let Some(cookie_store) = self.inner.cookie_store.as_ref() {
          if request.headers().get(http::header::COOKIE).is_none() {
            add_cookie_header(&mut request, &**cookie_store);
          }
        }
      }
      // 配置了keepalive和服务器支持复用才设置请求头
      if self.inner.keepalive && keepalive {
        request.headers_mut().insert(
          http::header::CONNECTION,
          HeaderValue::from_static("keep-alive"),
        );
      } else {
        request
          .headers_mut()
          .insert(http::header::CONNECTION, HeaderValue::from_static("close"));
      }
      record.record_request(&request);
      let key = uniq_key(&cur_uri);
      let socket = match conn.entry(key.clone()) {
        Entry::Occupied(mut entry) => {
          entry.get_mut().take() // take out the Option<Socket>
        }
        Entry::Vacant(entry) => {
          let new_socket = self.inner.connector.connect_with_uri(&cur_uri).await?;
          let slot = entry.insert(Some(new_socket));
          slot.take()
        }
      };
      let (mut response, socket) = self.execute_request(socket, &request).await?;
      response.extensions_mut().insert(request.clone());
      if let Some(cv) = response.headers().get(http::header::CONNECTION) {
        match cv.to_str().unwrap_or_default() {
          "keep-alive" => {
            if let Some(slot) = conn.get_mut(&key) {
              if let Some(socket) = socket {
                *slot = Some(socket);
              }
            }
            if !self.inner.keepalive {
              conn.remove(&key);
            } else {
              keepalive = true;
            }
          }
          _ => {
            conn.remove(&key);
            keepalive = false;
          }
        }
      } else {
        conn.remove(&key);
        keepalive = false;
      }
      // 原始请求不跳转
      if request.raw_request().is_some() {
        record.record_response(&response);
        records.push(record);
        break;
      }
      // 保存请求头的cookie
      #[cfg(feature = "cookie")]
      {
        if let Some(ref cookie_store) = self.inner.cookie_store {
          let mut cookies = cookies::extract_response_cookie_headers(response.headers()).peekable();
          if cookies.peek().is_some() {
            cookie_store.set_cookies(&mut cookies, request.uri());
          }
        }
      }
      // 根据状态码判断是否应该跳转,并清除一些请求头信息
      // Determine whether to redirect on the status code and clear request header
      let should_redirect = match response.status_code() {
        StatusCode::MOVED_PERMANENTLY | StatusCode::FOUND | StatusCode::SEE_OTHER => {
          for header in &[
            http::header::TRANSFER_ENCODING,
            http::header::CONTENT_ENCODING,
            http::header::CONTENT_TYPE,
            http::header::CONTENT_LENGTH,
          ] {
            request.headers_mut().remove(header);
          }
          match request.method() {
            &Method::GET | &Method::HEAD => {}
            _ => {
              *request.method_mut() = Method::GET;
            }
          }
          true
        }
        StatusCode::TEMPORARY_REDIRECT | StatusCode::PERMANENT_REDIRECT => true,
        _ => false,
      };
      let mut redirect_info = RedirectRecord {
        should_redirect,
        next: None,
      };
      // 如果要跳转，获取进入跳转策略流程
      // 生成策略
      uris.push(cur_uri.clone());
      let action = self.inner.redirect_policy.check(&response, &uris);
      match action {
        Action::Follow(loc) => {
          redirect_info.next = Some(loc.clone());
          // 添加referer
          if self.inner.referer {
            if let Some(referer) = make_referer(&loc, &cur_uri) {
              response
                .headers_mut()
                .insert(http::header::REFERER, referer);
            }
          }
          cur_uri = loc;
          *request.uri_mut() =
            http::Uri::from_str(&cur_uri.to_string()).map_err(http::Error::from)?;
          let mut headers = std::mem::replace(response.headers_mut(), HeaderMap::new());
          remove_sensitive_headers(&mut headers, &cur_uri, uris.as_slice());
          record.record_response(&response);
          records.push(record);
          continue;
        }
        Action::Stop(next) => {
          redirect_info.next = Some(next.clone());
        }
        Action::None => {}
      }
      response.extensions_mut().insert(redirect_info);
      record.record_response(&response);
      records.push(record);
      break;
    }
    for (_key, socket) in conn {
      if let Some(mut s) = socket {
        s.shutdown().await?;
      }
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
#[cfg_attr(docsrs, doc(cfg(feature = "cookie")))]
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
///     .timeout(Some(Duration::from_secs(10)))
///     .build()?;
/// # Ok(())
/// # }
/// ```
#[must_use]
#[derive(Clone, Debug, Default)]
pub struct ClientBuilder {
  config: Config,
}

impl ClientBuilder {
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
    let connector_builder = if let Some(custom_builder) = config.connector_builder {
      custom_builder
    } else {
      // Build default connector with config values
      let mut default_builder = ConnectorBuilder::default()
        .proxy(config.proxy)
        .keepalive(config.keepalive)
        .read_timeout(config.read_timeout)
        .connect_timeout(config.connect_timeout)
        .write_timeout(config.timeout);
      default_builder = default_builder.nodelay(config.nodelay);
      #[cfg(feature = "dns")]
      {
        if let Some(resolver) = config.dns_resolver {
          default_builder = default_builder.dns_resolver(resolver);
        }
      }
      #[cfg(feature = "tls")]
      {
        default_builder = default_builder
          .hostname_verification(config.hostname_verification)
          .certs_verification(config.certs_verification)
          .certificate(config.root_certs)
          .tls_sni(config.tls_sni)
          .min_tls_version(config.min_tls_version)
          .max_tls_version(config.max_tls_version);
        if let Some(identity) = config.identity {
          default_builder = default_builder.identity(identity);
        }
        if let Some(tls) = config.tls {
          default_builder = default_builder.custom_tls_connector(tls)
        }
      }
      #[cfg(feature = "http2")]
      {
        default_builder = default_builder.enable_http2(config.http2);
      }
      default_builder
    };
    let connector = connector_builder.build()?;
    Ok(Client {
      inner: Arc::new(ClientRef {
        keepalive: config.keepalive,
        timeout: config.timeout,
        #[cfg(feature = "cookie")]
        cookie_store: config.cookie_store,
        connector: Arc::new(connector),
        redirect_policy: config.redirect_policy,
        referer: config.referer,
        header: config.headers,
      }),
    })
  }
  // Higher-level options

  /// Sets the `User-Agent` header to be used by this client.
  ///
  /// # Example
  ///
  /// ```rust
  /// # use http::HeaderValue;
  /// async fn doc() -> Result<(), slinger::Error> {
  /// let ua = HeaderValue::from_static("XX_UA");
  /// let client = slinger::Client::builder()
  ///     .user_agent(ua)
  ///     .build()?;
  /// let res = client.get("https://www.rust-lang.org").send().await?;
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
  /// use slinger::http::header;
  /// # async fn build_client() -> Result<(), slinger::Error> {
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
  /// let res = client.get("https://www.rust-lang.org").send().await?;
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
  // DNS options

  /// Set a custom DNS resolver for hostname resolution.
  ///
  /// This allows you to use custom DNS servers instead of the system's default DNS.
  ///
  /// # Optional
  ///
  /// This requires the optional `dns` feature to be enabled.
  ///
  /// # Example
  ///
  /// ```ignore
  /// use slinger::{Client, dns::DnsResolver};
  ///
  /// # fn example() -> Result<(), slinger::Error> {
  /// let resolver = DnsResolver::new(vec![
  ///     "8.8.8.8:53".parse().unwrap(),
  /// ])?;
  ///
  /// let client = Client::builder()
  ///     .dns_resolver(resolver)
  ///     .build()?;
  /// # Ok(())
  /// # }
  /// ```
  #[cfg(feature = "dns")]
  #[cfg_attr(docsrs, doc(cfg(feature = "dns")))]
  pub fn dns_resolver(mut self, resolver: DnsResolver) -> ClientBuilder {
    self.config.dns_resolver = Some(resolver);
    self
  }
  // Timeout options

  /// Set a timeout for connect, read and write operations of a `Client`.
  ///
  /// Default is 30 seconds.
  ///
  /// Pass `None` to disable timeout.
  pub fn timeout(mut self, timeout: Option<Duration>) -> ClientBuilder {
    self.config.timeout = timeout;
    self
  }
  /// Set a timeout for only the connect phase of a `Client`.
  ///
  /// Default is 10 seconds.
  pub fn connect_timeout(mut self, timeout: Option<Duration>) -> ClientBuilder {
    self.config.connect_timeout = timeout;
    self
  }
  /// Set a timeout for only the read phase of a `Client`.
  ///
  /// Default is 30 seconds.
  pub fn read_timeout(mut self, timeout: Option<Duration>) -> ClientBuilder {
    self.config.read_timeout = timeout;
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
  // HTTP keepalive options

  ///
  /// Default is `false`.
  pub fn keepalive(mut self, keepalive: bool) -> ClientBuilder {
    self.config.keepalive = keepalive;
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
  /// let cert = slinger::tls::Certificate::from_der(&der)?;
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
  /// This requires the optional `tls`(-...)`
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
  /// This requires the optional `tls`
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
  /// This requires the optional `tls` feature to be enabled.
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
  ///
  #[cfg(feature = "tls")]
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
  /// This requires the optional `cookie` feature to be enabled.
  #[cfg(feature = "cookie")]
  #[cfg_attr(docsrs, doc(cfg(feature = "cookie")))]
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
  #[cfg_attr(docsrs, doc(cfg(feature = "cookie")))]
  pub fn cookie_provider<C: cookies::CookieStore + Send + Sync + 'static>(
    mut self,
    cookie_store: Arc<C>,
  ) -> ClientBuilder {
    self.config.cookie_store = Some(cookie_store as _);
    self
  }
  /// Set the minimum required TLS version for connections.
  ///
  /// By default, the `native_tls::Protocol` default is used.
  ///
  /// # Optional
  ///
  /// This requires the optional `tls`
  /// feature to be enabled.
  #[cfg(feature = "tls")]
  #[cfg_attr(docsrs, doc(cfg(feature = "tls")))]
  pub fn min_tls_version(mut self, version: Option<tls::Version>) -> ClientBuilder {
    self.config.min_tls_version = version;
    self
  }
  /// Set the maximum required TLS version for connections.
  ///
  /// By default, the `native_tls::Protocol` default is used.
  ///
  /// # Optional
  ///
  /// This requires the optional `tls`
  /// feature to be enabled.
  #[cfg(feature = "tls")]
  #[cfg_attr(docsrs, doc(cfg(feature = "tls")))]
  pub fn max_tls_version(mut self, version: Option<tls::Version>) -> ClientBuilder {
    self.config.max_tls_version = version;
    self
  }
  /// Controls the use of TLS server name indication.
  ///
  /// Defaults to `None`.
  ///
  #[cfg(feature = "tls")]
  pub fn tls(mut self, tls: Option<Arc<dyn CustomTlsConnector>>) -> ClientBuilder {
    self.config.tls = tls;
    self
  }
  #[cfg(feature = "http2")]
  /// Enable or disable HTTP/2 support.
  pub fn enable_http2(mut self, http2: bool) -> Self {
    self.config.http2 = http2;
    self
  }
  /// Set a custom `ConnectorBuilder` for the client.
  ///
  /// This allows you to fully customize the connector configuration.
  /// When a custom connector builder is provided, it will be used directly
  /// instead of the default one.
  ///
  /// # Important
  ///
  /// When using this method, ALL connector-related settings configured through
  /// `ClientBuilder` methods will be ignored, including:
  /// - `tcp_nodelay()`
  /// - `add_root_certificate()`
  /// - `identity()`
  /// - `danger_accept_invalid_hostnames()`
  /// - `danger_accept_invalid_certs()`
  /// - `tls_sni()`
  /// - `min_tls_version()` and `max_tls_version()`
  /// - `connect_timeout()`, `read_timeout()`, and `timeout()` for the connector
  /// - `proxy()` for the connector
  /// - `enable_http2()` for the connector
  ///
  /// You must configure all these settings directly on the `ConnectorBuilder` instead.
  /// Client-level settings like `keepalive()`, `cookie_store()`, `redirect()`, etc.
  /// will still be respected.
  ///
  /// # Example
  ///
  /// ```rust
  /// use slinger::{Client, ConnectorBuilder};
  /// use std::time::Duration;
  ///
  /// # fn doc() -> Result<(), slinger::Error> {
  /// let custom_connector = ConnectorBuilder::default()
  ///     .connect_timeout(Some(Duration::from_secs(5)))
  ///     .read_timeout(Some(Duration::from_secs(10)))
  ///     .nodelay(true);
  ///
  /// let client = Client::builder()
  ///     .connector_builder(custom_connector)
  ///     .build()?;
  /// # Ok(())
  /// # }
  /// ```
  pub fn connector_builder(mut self, connector_builder: ConnectorBuilder) -> ClientBuilder {
    self.config.connector_builder = Some(connector_builder);
    self
  }
}
#[derive(Clone)]
struct Config {
  #[cfg(feature = "http2")]
  http2: bool,
  timeout: Option<Duration>,
  connect_timeout: Option<Duration>,
  read_timeout: Option<Duration>,
  headers: HeaderMap,
  referer: bool,
  proxy: Option<Proxy>,
  nodelay: bool,
  keepalive: bool,
  #[cfg(feature = "dns")]
  dns_resolver: Option<DnsResolver>,
  #[cfg(feature = "tls")]
  root_certs: Vec<Certificate>,
  #[cfg(feature = "tls")]
  identity: Option<Identity>,
  hostname_verification: bool,
  certs_verification: bool,
  #[cfg(feature = "tls")]
  tls_sni: bool,
  #[cfg(feature = "tls")]
  min_tls_version: Option<tls::Version>,
  #[cfg(feature = "tls")]
  max_tls_version: Option<tls::Version>,
  #[cfg(feature = "tls")]
  tls: Option<Arc<dyn CustomTlsConnector>>,
  redirect_policy: Policy,
  #[cfg(feature = "cookie")]
  cookie_store: Option<Arc<dyn cookies::CookieStore + Send + Sync + 'static>>,
  connector_builder: Option<ConnectorBuilder>,
}

impl Debug for Config {
  fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
    f.debug_struct("Config")
      .field("connect_timeout", &self.connect_timeout)
      .field("headers", &self.headers)
      .field("referer", &self.referer)
      .field("proxy", &self.proxy)
      .field("timeout", &self.timeout)
      .field("nodelay", &self.nodelay)
      .field("keepalive", &self.keepalive)
      .field("hostname_verification", &self.hostname_verification)
      .field("certs_verification", &self.certs_verification)
      .field("redirect_policy", &self.redirect_policy)
      .finish()
  }
}
impl Default for Config {
  fn default() -> Self {
    Self {
      #[cfg(feature = "http2")]
      http2: false,
      timeout: Some(Duration::from_secs(30)),
      connect_timeout: Some(Duration::from_secs(10)),
      read_timeout: Some(Duration::from_secs(30)),
      headers: Default::default(),
      referer: false,
      proxy: None,
      nodelay: false,
      keepalive: false,
      #[cfg(feature = "dns")]
      dns_resolver: None,
      #[cfg(feature = "tls")]
      root_certs: vec![],
      #[cfg(feature = "tls")]
      identity: None,
      hostname_verification: false,
      certs_verification: false,
      #[cfg(feature = "tls")]
      tls_sni: true,
      #[cfg(feature = "tls")]
      min_tls_version: None,
      #[cfg(feature = "tls")]
      max_tls_version: None,
      #[cfg(feature = "tls")]
      tls: None,
      redirect_policy: Policy::Limit(10),
      #[cfg(feature = "cookie")]
      cookie_store: None,
      connector_builder: None,
    }
  }
}

#[derive(Clone)]
struct ClientRef {
  keepalive: bool,
  timeout: Option<Duration>,
  #[cfg(feature = "cookie")]
  cookie_store: Option<Arc<dyn cookies::CookieStore + Send + Sync + 'static>>,
  connector: Arc<Connector>,
  redirect_policy: Policy,
  referer: bool,
  header: HeaderMap,
}
