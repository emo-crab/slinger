use crate::body::Body;
use crate::record::CommandRecord;
use crate::response::parser_headers;
use crate::{Client, Error, Response, COLON_SPACE, CR_LF, SPACE};
use bytes::Bytes;
use http::Request as HttpRequest;
use http::{HeaderMap, HeaderName, HeaderValue, Method, Version};
use std::fmt::{Debug, Formatter};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, BufReader};

/// Unsafe specifies whether to use raw engine for sending Non RFC-Compliant requests.
#[derive(Debug, Default, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct RawRequest {
  unsafe_raw: bool,
  #[cfg_attr(feature = "serde", serde(with = "crate::serde_schema::bytes_serde"))]
  #[cfg_attr(feature = "schema", schemars(with = "Bytes"))]
  raw: Bytes,
}

/// A request which can be executed with `Client::execute()`.
#[derive(Default, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct Request {
  /// The target URI of the HTTP request
  #[cfg_attr(feature = "serde", serde(with = "http_serde::uri"))]
  #[cfg_attr(
    feature = "schema",
    schemars(
      with = "String",
      title = "request URI",
      description = "The target URI of the HTTP request including path and query parameters",
      example = "https://example.com/api/v1/resource?id=123"
    )
  )]
  pub uri: http::Uri,
  /// The HTTP version used for the request
  #[cfg_attr(feature = "serde", serde(with = "http_serde::version"))]
  #[cfg_attr(
    feature = "schema",
    schemars(
      with = "String",
      title = "HTTP version",
      description = "The protocol version of HTTP used for this request",
      example = "HTTP/1.1"
    )
  )]
  pub version: Version,
  /// The HTTP method indicating the desired action for the resource
  #[cfg_attr(feature = "serde", serde(with = "http_serde::method"))]
  #[cfg_attr(
    feature = "schema",
    schemars(
      schema_with = "crate::serde_schema::http_method_schema",
      title = "HTTP method",
      description = "The HTTP method indicating the desired action for the resource",
      example = &"GET",
    )
  )]
  pub method: Method,
  /// Collection of HTTP headers sent with the request
  #[cfg_attr(feature = "serde", serde(with = "http_serde::header_map"))]
  #[cfg_attr(
    feature = "schema",
    schemars(
      with = "std::collections::HashMap<String,String>",
      title = "HTTP headers",
      description = "Key-value pairs of HTTP headers included in the request",
      example = r#"&[("Content-Type", "application/json"), ("Authorization", "Bearer token")]"#
    )
  )]
  pub headers: HeaderMap<HeaderValue>,
  /// Optional body content sent with the request
  #[cfg_attr(
    feature = "schema",
    schemars(
      title = "request body",
      description = "Optional body content sent with the HTTP request",
      example = r#"&"{\"key\":\"value\"}""#
    )
  )]
  pub body: Option<Body>,
  /// Optional raw request representation for special cases
  #[cfg_attr(
    feature = "schema",
    schemars(
      title = "raw request",
      description = "Optional raw representation of the HTTP request for special handling cases",
    )
  )]
  pub raw_request: Option<RawRequest>,
}

impl Debug for Request {
  fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
    if let Some(raw) = &self.raw_request {
      f.debug_struct("RawRequest")
        .field("uri", &self.uri)
        .field("raw", &format_args!("{}", &raw.raw.escape_ascii()))
        .field("unsafe_raw", &raw.unsafe_raw)
        .finish()
    } else {
      f.debug_struct("Request")
        .field("uri", &self.uri)
        .field("version", &self.version)
        .field("method", &self.method)
        .field("headers", &self.headers)
        .field("body", &self.body)
        .finish()
    }
  }
}
impl<T> From<HttpRequest<T>> for Request
where
  T: Into<Body>,
{
  fn from(value: HttpRequest<T>) -> Self {
    let (parts, body) = value.into_parts();
    let body = body.into();
    Self {
      uri: parts.uri,
      version: parts.version,
      method: parts.method,
      headers: parts.headers,
      body: if body.is_empty() { None } else { Some(body) },
      raw_request: None,
    }
  }
}

impl From<&Request> for Bytes {
  fn from(value: &Request) -> Self {
    if let Some(raw) = &value.raw_request {
      return raw.raw.clone();
    }
    let mut http_requests = Vec::new();
    // 请求头
    http_requests.extend(value.method.as_str().as_bytes());
    http_requests.extend(SPACE);
    // 路径
    http_requests.extend(value.uri.path().as_bytes());
    if let Some(q) = value.uri.query() {
      http_requests.extend([63]);
      http_requests.extend(q.as_bytes());
    }
    http_requests.extend(SPACE);
    // 版本
    http_requests.extend(format!("{:?}", value.version).as_bytes());
    http_requests.extend(CR_LF);
    // 如果请求头里面没有主机头就先加主机头
    if value.headers.get(http::header::HOST).is_none() {
      http_requests.extend(http::header::HOST.as_str().as_bytes());
      http_requests.extend(COLON_SPACE);
      http_requests.extend(if let Some(s) = value.uri.authority() {
        s.as_str().as_bytes()
      } else {
        &[]
      });
      http_requests.extend(CR_LF);
    }
    // 添加请求头
    let mut headers = value.headers.clone();
    // 如果有body加入Content-Length请求头
    if let Some(b) = value.body() {
      if !b.is_empty() {
        headers
          .entry(http::header::CONTENT_LENGTH)
          .or_insert(HeaderValue::from(b.len()));
      }
    }
    for (k, v) in headers.iter() {
      http_requests.extend(k.as_str().as_bytes());
      http_requests.extend(COLON_SPACE);
      http_requests.extend(v.as_bytes());
      http_requests.extend(CR_LF);
    }
    http_requests.extend(CR_LF);
    // 添加body
    if let Some(b) = value.body() {
      if !b.is_empty() {
        http_requests.extend(b.as_ref());
      }
    }
    Bytes::from(http_requests)
  }
}

impl From<Request> for Bytes {
  fn from(value: Request) -> Self {
    Bytes::from(&value)
  }
}

impl Request {
  /// Build a `Request` from an HTTP start-line and buffered stream body.
  pub async fn from_http_reader<R>(reader: &mut BufReader<R>) -> crate::Result<Self>
  where
    R: AsyncRead + Unpin,
  {
    let mut request_line = String::new();
    let n = reader.read_line(&mut request_line).await?;
    if n == 0 {
      return Err(Error::invalid_request("Empty request".to_string()));
    }
    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 3 {
      return Err(Error::invalid_request("Invalid request line".to_string()));
    }
    let method = parts[0];
    let uri = parts[1];
    let version = Self::parse_http_version(parts[2])?;

    // Read headers line by line until the blank line that ends them.
    let mut headers_buf = Vec::new();
    loop {
      let mut line = String::new();
      reader.read_line(&mut line).await?;
      if line == "\r\n" || line == "\n" {
        break;
      }
      headers_buf.extend_from_slice(line.as_bytes());
    }

    let mut content_length: usize = 0;
    let mut parsed_headers: Vec<(String, String)> = Vec::new();
    for line in String::from_utf8_lossy(&headers_buf).lines() {
      if let Some(idx) = line.find(':') {
        let (name, value) = line.split_at(idx);
        let value = value[1..].trim();
        parsed_headers.push((name.trim().to_string(), value.to_string()));
        if name.trim().eq_ignore_ascii_case("content-length") {
          content_length = value.parse().unwrap_or(0);
        }
      }
    }

    let body = if content_length > 0 {
      let mut body_buf = vec![0u8; content_length];
      reader.read_exact(&mut body_buf).await?;
      Bytes::from(body_buf)
    } else {
      Bytes::new()
    };

    Self::from_http_parts(method, uri, version, parsed_headers, body)
  }

  fn parse_http_version(version: &str) -> crate::Result<Version> {
    match version {
      "HTTP/0.9" => Ok(Version::HTTP_09),
      "HTTP/1.0" => Ok(Version::HTTP_10),
      "HTTP/1.1" => Ok(Version::HTTP_11),
      "HTTP/2.0" | "HTTP/2" => Ok(Version::HTTP_2),
      "HTTP/3.0" | "HTTP/3" => Ok(Version::HTTP_3),
      _ => Err(Error::invalid_request(format!(
        "Unsupported HTTP version: {}",
        version
      ))),
    }
  }

  /// Build a `Request` from parsed HTTP components.
  pub fn from_http_parts<I, K, V, B>(
    method: &str,
    uri: &str,
    version: Version,
    headers: I,
    body: B,
  ) -> crate::Result<Self>
  where
    I: IntoIterator<Item = (K, V)>,
    K: AsRef<str>,
    V: AsRef<str>,
    B: Into<Body>,
  {
    let mut request_builder = http::Request::builder()
      .method(method)
      .uri(uri)
      .version(version);

    for (name, value) in headers {
      request_builder = request_builder.header(name.as_ref(), value.as_ref());
    }

    let http_request = request_builder.body(body.into())?;
    Ok(http_request.into())
  }

  /// Creates a new builder-style object to manufacture a `Request`
  ///
  /// This method returns an instance of `Builder` which can be used to
  /// create a `Request`.
  ///
  /// # Examples
  ///
  /// ```
  /// # use http::*;
  /// let request = Request::builder()
  ///     .method("GET")
  ///     .uri("https://www.rust-lang.org/")
  ///     .header("X-Custom-Foo", "Bar")
  ///     .body(())
  ///     .unwrap();
  /// ```
  pub fn builder() -> http::request::Builder {
    http::request::Builder::new()
  }

  /// This method return raw_request to create a `Request`
  /// # Examples
  ///
  /// ```
  /// # use slinger::{Request, RequestBuilder};
  /// let request: Request = Request::raw(http::Uri::from_static("http://httpbin.org"),"",true);
  /// assert!(request.raw_request().is_some());
  ///
  pub fn raw<U, R>(uri: U, raw: R, unsafe_raw: bool) -> Request
  where
    Bytes: From<R>,
    http::Uri: From<U>,
  {
    let raw = RawRequest {
      unsafe_raw,
      raw: raw.into(),
    };
    Request {
      uri: uri.into(),
      raw_request: Some(raw),
      ..Request::default()
    }
  }
}

impl Request {
  /// Set the HTTP method for this request.
  ///
  /// By default, this is `GET`.
  ///
  /// # Examples
  ///
  /// ```
  /// # use http::*;
  ///
  /// let req = Request::builder()
  ///     .method("POST")
  ///     .body(())
  ///     .unwrap();
  /// ```
  #[inline]
  pub fn method(&self) -> &Method {
    &self.method
  }
  /// Get the HTTP Method for this request.
  ///
  /// By default, this is `GET`. If builder has error, returns None.
  ///
  /// # Examples
  ///
  /// ```
  /// # use http::*;
  ///
  /// let mut req = Request::builder();
  /// assert_eq!(req.method_ref(),Some(&Method::GET));
  ///
  /// req = req.method("POST");
  /// assert_eq!(req.method_ref(),Some(&Method::POST));
  /// ```
  #[inline]
  pub fn method_mut(&mut self) -> &mut Method {
    &mut self.method
  }
  /// Set the URI for this request.
  ///
  /// By default, this is `/`.
  ///
  /// # Examples
  ///
  /// ```
  /// # use http::*;
  ///
  /// let req = Request::builder()
  ///     .uri("https://www.rust-lang.org/")
  ///     .body(())
  ///     .unwrap();
  /// ```
  #[inline]
  pub fn uri(&self) -> &http::Uri {
    &self.uri
  }
  /// Get the URI for this request
  ///
  /// By default, this is `/`.
  ///
  /// # Examples
  ///
  /// ```
  /// # use http::*;
  ///
  /// let mut req = Request::builder();
  /// assert_eq!(req.uri_ref().unwrap(), "/" );
  ///
  /// req = req.uri("https://www.rust-lang.org/");
  /// assert_eq!(req.uri_ref().unwrap(), "https://www.rust-lang.org/" );
  /// ```
  #[inline]
  pub fn uri_mut(&mut self) -> &mut http::Uri {
    &mut self.uri
  }
  /// Appends a header to this request builder.
  ///
  /// This function will append the provided key/value as a header to the
  /// internal `HeaderMap` being constructed. Essentially this is equivalent
  /// to calling `HeaderMap::append`.
  ///
  /// # Examples
  ///
  /// ```
  /// # use http::*;
  /// # use http::header::HeaderValue;
  ///
  /// let req = Request::builder()
  ///     .header("Accept", "text/html")
  ///     .header("X-Custom-Foo", "bar")
  ///     .body(())
  ///     .unwrap();
  /// ```
  #[inline]
  pub fn headers(&self) -> &HeaderMap {
    &self.headers
  }
  /// Get header on this request builder.
  /// when builder has error returns None
  ///
  /// # Example
  ///
  /// ```
  /// # use http::Request;
  /// let req = Request::builder()
  ///     .header("Accept", "text/html")
  ///     .header("X-Custom-Foo", "bar");
  /// let headers = req.headers_ref().unwrap();
  /// assert_eq!( headers["Accept"], "text/html" );
  /// assert_eq!( headers["X-Custom-Foo"], "bar" );
  /// ```
  #[inline]
  pub fn headers_mut(&mut self) -> &mut HeaderMap {
    &mut self.headers
  }
  /// "Consumes" this builder, using the provided `body` to return a
  /// constructed `Request`.
  ///
  /// # Errors
  ///
  /// This function may return an error if any previously configured argument
  /// failed to parse or get converted to the internal representation. For
  /// example if an invalid `head` was specified via `header("Foo",
  /// "Bar\r\n")` the error will be returned when this function is called
  /// rather than when `header` was called.
  ///
  /// # Examples
  ///
  /// ```
  /// # use http::*;
  ///
  /// let request = Request::builder()
  ///     .body(())
  ///     .unwrap();
  /// ```
  #[inline]
  pub fn body(&self) -> Option<&Body> {
    self.body.as_ref()
  }
  /// Returns the associated version.
  ///
  /// # Examples
  ///
  /// ```
  /// # use http::*;
  /// let request: Request<()> = Request::default();
  /// assert_eq!(request.version(), Version::HTTP_11);
  /// ```
  #[inline]
  pub fn version(&self) -> Version {
    self.version
  }
  /// Returns a mutable reference to the associated version.
  ///
  /// # Examples
  ///
  /// ```
  /// # use http::*;
  /// let mut request: Request<()> = Request::default();
  /// *request.version_mut() = Version::HTTP_2;
  /// assert_eq!(request.version(), Version::HTTP_2);
  /// ```
  #[inline]
  pub fn version_mut(&mut self) -> &mut Version {
    &mut self.version
  }
  /// Returns raw_request.
  ///
  /// # Examples
  ///
  /// ```
  /// # use slinger::Request;
  /// let request: Request = Request::raw(http::Uri::from_static("http://httpbin.org"),"",true);
  /// assert!(request.raw_request().is_some());
  /// ```
  #[inline]
  pub fn raw_request(&self) -> &Option<RawRequest> {
    &self.raw_request
  }

  #[inline]
  pub(crate) fn raw_request_mut(&mut self) -> &mut Option<RawRequest> {
    &mut self.raw_request
  }
  #[inline]
  pub(crate) fn is_unsafe(&self) -> bool {
    match &self.raw_request {
      None => false,
      Some(raw) => raw.unsafe_raw,
    }
  }
  /// Returns ncat or curl command to send request.
  ///
  /// # Examples
  ///
  /// ```
  /// #
  /// let req: slinger::Request = slinger::Request::builder()
  /// .uri("http://httpbin.org/get")
  /// .header("X", "X")
  /// .body(bytes::Bytes::from(b"\x7f\x45\x4c\x46\x01\x00\x02\x03".to_vec())).unwrap().into();
  /// println!("{}", req.get_command());
  /// ```
  #[inline]
  pub fn get_command(&self) -> String {
    CommandRecord::from(self).command
  }
}

/// A builder to construct the properties of a `Request`.
///
/// To construct a `RequestBuilder`, refer to the `Client` documentation.
// #[derive(Debug)]
#[must_use = "RequestBuilder does nothing until you 'send' it"]
pub struct RequestBuilder {
  client: Client,
  builder: http::request::Builder,
  body: Body,
  raw: Option<RawRequest>,
}

impl Default for RequestBuilder {
  fn default() -> Self {
    RequestBuilder {
      client: Default::default(),
      builder: http::request::Builder::new(),
      body: Default::default(),
      raw: None,
    }
  }
}

impl RequestBuilder {
  /// Constructs a new request.
  pub fn new(client: Client, builder: http::request::Builder) -> RequestBuilder {
    RequestBuilder {
      client,
      builder,
      body: Default::default(),
      raw: None,
    }
  }
  /// Set `uri` to this Request.
  pub fn uri<U: Into<http::Uri>>(mut self, uri: U) -> RequestBuilder {
    self.builder = self.builder.uri(uri);
    self
  }
  /// Add a `Header` to this Request.
  pub fn header<K, V>(mut self, key: K, value: V) -> RequestBuilder
  where
    HeaderName: TryFrom<K>,
    HeaderValue: TryFrom<V>,
    <HeaderName as TryFrom<K>>::Error: Into<http::Error>,
    <HeaderValue as TryFrom<V>>::Error: Into<http::Error>,
  {
    self.builder = self.builder.header(key, value);
    self
  }
  /// Add a `Header` from lines to this Request.
  pub fn header_line<L: Into<String>>(mut self, lines: L) -> RequestBuilder {
    for line in lines.into().lines() {
      if let Ok((Some(key), Some(value))) = parser_headers(line.as_bytes()) {
        self.builder = self.builder.header(key, value);
      };
    }
    self
  }
  /// Add a set of Headers to the existing ones on this Request.
  ///
  /// The headers will be merged in to any already set.
  pub fn headers(mut self, headers: HeaderMap) -> RequestBuilder {
    if let Some(header) = self.builder.headers_mut() {
      for (key, value) in headers {
        if let Some(key) = key {
          header.insert(key, value);
        }
      }
    }
    self
  }
  /// Set the request body.
  pub fn body<T: Into<Body>>(mut self, body: T) -> RequestBuilder {
    self.body = body.into();
    self
  }
  /// set raw request
  pub fn raw<R: Into<Bytes>>(mut self, raw: R, unsafe_raw: bool) -> RequestBuilder {
    self.raw = Some(RawRequest {
      unsafe_raw,
      raw: raw.into(),
    });
    self
  }
  /// Build a `Request`, which can be inspected, modified and executed with
  /// `Client::execute()`.
  pub fn build(self) -> crate::Result<Request> {
    let mut r: Request = self.builder.body(self.body)?.into();
    r.raw_request = self.raw;
    Ok(r)
  }
  /// Constructs the Request and sends it to the target URL, returning a
  /// future Response.
  ///
  /// # Errors
  ///
  /// This method fails if there was an error while sending request,
  /// redirect loop was detected or redirect limit was exhausted.
  ///
  /// # Example
  ///
  /// ```no_run
  /// # use slinger::Error;
  /// #
  /// # async fn run() -> Result<(), Error> {
  /// let response = slinger::Client::new()
  ///     .get("https://hyper.rs")
  ///     .send().await?;
  /// # Ok(())
  /// # }
  /// ```
  pub async fn send(self) -> crate::Result<Response> {
    let mut req: Request = self.builder.body(self.body)?.into();
    *req.raw_request_mut() = self.raw;
    self.client.execute(req).await
  }
}
