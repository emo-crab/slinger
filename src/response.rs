use crate::body::Body;
#[cfg(feature = "cookie")]
use crate::cookies;
use crate::errors::Result;
use crate::record::HttpInfo;
use crate::{Error, COLON_SPACE, CR_LF, SPACE};
use bytes::Bytes;
#[cfg(feature = "charset")]
use encoding_rs::{Encoding, UTF_8};
use flate2::read::MultiGzDecoder;
use http::Response as HttpResponse;
#[cfg(feature = "charset")]
use mime::Mime;
use std::io::{BufRead, BufReader, Read};

/// A Response to a submitted `Request`.
#[derive(Debug, Default, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Response {
  #[cfg_attr(feature = "serde", serde(with = "http_serde::version"))]
  version: http::Version,
  #[cfg_attr(feature = "serde", serde(with = "http_serde::uri"))]
  uri: http::Uri,
  #[cfg_attr(feature = "serde", serde(with = "http_serde::status_code"))]
  status_code: http::StatusCode,
  #[cfg_attr(feature = "serde", serde(with = "http_serde::header_map"))]
  headers: http::HeaderMap<http::HeaderValue>,
  #[cfg_attr(feature = "serde", serde(skip))]
  extensions: http::Extensions,
  body: Option<Body>,
}

impl PartialEq for Response {
  fn eq(&self, other: &Self) -> bool {
    self.version == other.version
      && self.status_code == other.status_code
      && self.headers == other.headers
      && self.body.eq(&self.body)
  }
}

impl<T> From<HttpResponse<T>> for Response
  where
    T: Into<Body>,
{
  fn from(value: HttpResponse<T>) -> Self {
    let (parts, body) = value.into_parts();
    let body = body.into();
    Self {
      version: parts.version,
      uri: Default::default(),
      status_code: parts.status,
      headers: parts.headers,
      extensions: parts.extensions,
      body: if body.is_empty() { None } else { Some(body) },
    }
  }
}

impl Response {
  pub(crate) fn to_raw(&self) -> Bytes {
    let mut http_response = Vec::new();
    http_response.extend(format!("{:?}", self.version).as_bytes());
    http_response.extend(SPACE);
    http_response.extend(format!("{}", self.status_code).as_bytes());
    http_response.extend(CR_LF);
    for (k, v) in self.headers.iter() {
      http_response.extend(k.as_str().as_bytes());
      http_response.extend(COLON_SPACE);
      http_response.extend(v.as_bytes());
      http_response.extend(CR_LF);
    }
    http_response.extend(CR_LF);
    // 添加body
    if let Some(b) = self.body() {
      if !b.is_empty() {
        http_response.extend(b.as_ref());
      }
    }
    Bytes::from(http_response)
  }
  /// An HTTP response builder
  ///
  /// This type can be used to construct an instance of `Response` through a
  /// builder-like pattern.
  pub fn builder() -> http::response::Builder {
    http::response::Builder::new()
  }
}

impl Response {
  /// Retrieve the cookies contained in the response.
  ///
  /// Note that invalid 'Set-Cookie' headers will be ignored.
  ///
  /// # Optional
  ///
  /// This requires the optional `cookies` feature to be enabled.
  #[cfg(feature = "cookie")]
  #[cfg_attr(docsrs, doc(cfg(feature = "cookies")))]
  pub fn cookies(&self) -> impl Iterator<Item=cookies::Cookie> {
    cookies::extract_response_cookies(&self.headers).filter_map(|x| x.ok())
  }

  /// 获取编码并且尝试解码
  #[cfg(feature = "charset")]
  pub fn text_with_charset(&self, default_encoding: &str) -> Result<String> {
    let body = if let Some(b) = self.body() {
      b
    } else {
      return Ok(String::new());
    };
    let content_type = self
      .headers
      .get(http::header::CONTENT_TYPE)
      .and_then(|value| value.to_str().ok())
      .and_then(|value| value.parse::<Mime>().ok());
    let header_encoding = content_type
      .as_ref()
      .and_then(|mime| mime.get_param("charset").map(|charset| charset.as_str()))
      .unwrap_or(default_encoding);
    let mut decode_text = String::new();
    for encoding_name in &[header_encoding, &default_encoding] {
      let encoding = Encoding::for_label(encoding_name.as_bytes()).unwrap_or(UTF_8);
      let (text, _, is_errors) = encoding.decode(body);
      if !is_errors {
        decode_text = text.to_string();
        break;
      }
    }
    Ok(decode_text)
  }
  /// Get the response text.
  ///
  /// This method decodes the response body with BOM sniffing
  /// and with malformed sequences replaced with the REPLACEMENT CHARACTER.
  /// Encoding is determined from the `charset` parameter of `Content-Type` header,
  /// and defaults to `utf-8` if not presented.
  ///
  /// # Note
  ///
  /// If the `charset` feature is disabled the method will only attempt to decode the
  /// response as UTF-8, regardless of the given `Content-Type`
  ///
  /// # Example
  ///
  /// ```rust
  /// # extern crate slinger;
  /// # fn run() -> Result<(), Box<dyn std::error::Error>> {
  /// let content = slinger::get("http://httpbin.org/range/26")?.text()?;
  /// # Ok(())
  /// # }
  /// ```

  pub fn text(&self) -> Result<String> {
    #[cfg(feature = "charset")]
    {
      let default_encoding = "utf-8";
      self.text_with_charset(default_encoding)
    }
    #[cfg(not(feature = "charset"))]
    Ok(String::from_utf8_lossy(&self.body().clone().unwrap_or_default()).to_string())
  }
  /// Get the `StatusCode` of this `Response`.
  ///
  /// # Examples
  ///
  /// Checking for general status class:
  ///
  /// ```rust
  /// # #[cfg(feature = "json")]
  /// # fn run() -> Result<(), Box<dyn std::error::Error>> {
  /// let resp = slinger::get("http://httpbin.org/get")?;
  /// if resp.status().is_success() {
  ///     println!("success!");
  /// } else if resp.status().is_server_error() {
  ///     println!("server error!");
  /// } else {
  ///     println!("Something else happened. Status: {:?}", resp.status());
  /// }
  /// # Ok(())
  /// # }
  /// ```
  ///
  /// Checking for specific status codes:
  ///
  /// ```rust
  /// use slinger::Client;
  /// use slinger::StatusCode;
  /// # fn run() -> Result<(), Box<dyn std::error::Error>> {
  /// let client = Client::new();
  ///
  /// let resp = client.post("http://httpbin.org/post")
  ///     .body("possibly too large")
  ///     .send()?;
  ///
  /// match resp.status() {
  ///     StatusCode::OK => println!("success!"),
  ///     StatusCode::PAYLOAD_TOO_LARGE => {
  ///         println!("Request payload is too large!");
  ///     }
  ///     s => println!("Received response status: {s:?}"),
  /// };
  /// # Ok(())
  /// # }
  /// ```
  #[inline]
  pub fn status_code(&self) -> http::StatusCode {
    self.status_code
  }
  /// Get the HTTP `Version` of this `Response`.
  #[inline]
  pub fn version(&self) -> http::Version {
    self.version
  }

  /// Get the `Headers` of this `Response`.
  ///
  /// # Example
  ///
  /// Saving an etag when caching a file:
  ///
  /// ```
  /// use slinger::Client;
  /// use slinger::header::ETAG;
  ///
  /// # fn run() -> Result<(), Box<dyn std::error::Error>> {
  /// let client = Client::new();
  ///
  /// let mut resp = client.get("http://httpbin.org/cache").send()?;
  /// if resp.status().is_success() {
  ///     if let Some(etag) = resp.headers().get(ETAG) {
  ///         std::fs::write("etag", etag.as_bytes());
  ///     }
  /// }
  /// # Ok(())
  /// # }
  /// ```
  #[inline]
  pub fn headers(&self) -> &http::HeaderMap {
    &self.headers
  }
  /// Get a mutable reference to the `Headers` of this `Response`.
  #[inline]
  pub fn headers_mut(&mut self) -> &mut http::HeaderMap {
    &mut self.headers
  }
  /// Get the content-length of the response, if it is known.
  ///
  /// Reasons it may not be known:
  ///
  /// - The server didn't send a `content-length` header.
  /// - The response is gzipped and automatically decoded (thus changing
  ///   the actual decoded length).
  pub fn content_length(&self) -> Option<u64> {
    self
      .headers
      .get(http::header::CONTENT_LENGTH)
      .and_then(|x| x.to_str().ok()?.parse().ok())
  }
  /// Get the final `http::Uri` of this `Response`.
  ///
  /// # Example
  ///
  /// ```rust
  /// # fn run() -> Result<(), Box<dyn std::error::Error>> {
  /// let resp = slinger::get("http://httpbin.org/redirect/1")?;
  /// assert_eq!(resp.uri().as_str(), "http://httpbin.org/get");
  /// # Ok(())
  /// # }
  /// ```
  #[inline]
  pub fn uri(&self) -> &http::Uri {
    &self.uri
  }
  #[inline]
  pub(crate) fn url_mut(&mut self) -> &mut http::Uri {
    &mut self.uri
  }
  /// Get the remote address used to get this `Response`.
  ///
  /// # Example
  ///
  /// ```rust
  /// # fn run() -> Result<(), Box<dyn std::error::Error>> {
  /// let resp = slinger::get("http://httpbin.org/redirect/1")?;
  /// println!("httpbin.org address: {:?}", resp.remote_addr());
  /// # Ok(())
  /// # }
  /// ```
  pub fn remote_addr(&self) -> Option<&HttpInfo> {
    self.extensions().get::<HttpInfo>()
  }
  /// Get the full response body as `Bytes`.
  ///
  /// # Example
  ///
  /// ```
  /// # fn run() -> Result<(), Box<dyn std::error::Error>> {
  /// let bytes = slinger::get("http://httpbin.org/ip")?.body()?;
  ///
  /// println!("bytes: {bytes:?}");
  /// # Ok(())
  /// # }
  /// ```
  pub fn body(&self) -> &Option<Body> {
    &self.body
  }
  /// private
  pub fn body_mut(&mut self) -> &mut Option<Body> {
    &mut self.body
  }
  /// Returns a reference to the associated extensions.
  pub fn extensions(&self) -> &http::Extensions {
    &self.extensions
  }
  /// Returns a mutable reference to the associated extensions.
  pub fn extensions_mut(&mut self) -> &mut http::Extensions {
    &mut self.extensions
  }
}

/// A builder to construct the properties of a `Response`.
///
/// To construct a `ResponseBuilder`, refer to the `Client` documentation.
#[derive(Debug)]
pub struct ResponseBuilder<T: Read> {
  builder: http::response::Builder,
  reader: BufReader<T>,
  config: ResponseConfig,
}

/// response config
#[derive(Debug, Default)]
pub struct ResponseConfig {
  unsafe_response: bool,
  max_read: Option<u64>,
}

impl ResponseConfig {
  /// new a response config
  pub fn new(unsafe_response: bool, max_read: Option<u64>) -> Self {
    ResponseConfig {
      unsafe_response,
      max_read,
    }
  }
}

impl<T: Read> ResponseBuilder<T> {
  /// Constructs a new response.
  pub fn new(reader: BufReader<T>, config: ResponseConfig) -> ResponseBuilder<T> {
    ResponseBuilder {
      builder: Default::default(),
      reader,
      config,
    }
  }
  fn parser_version(&mut self) -> Result<(http::Version, http::StatusCode)> {
    let mut buffer = String::new();
    self.reader.read_line(&mut buffer)?;
    let mut version = http::Version::default();
    let mut code = http::StatusCode::default();
    for (index, vc) in buffer.splitn(3, |c| c == ' ').enumerate() {
      match index {
        0 => {
          version = match vc {
            "HTTP/0.9" => http::Version::HTTP_09,
            "HTTP/1.0" => http::Version::HTTP_10,
            "HTTP/1.1" => http::Version::HTTP_11,
            "HTTP/2.0" => http::Version::HTTP_2,
            "HTTP/3.0" => http::Version::HTTP_3,
            _ => http::Version::default(),
          };
        }
        1 => {
          code = http::StatusCode::try_from(vc).unwrap_or_default();
        }
        _ => {}
      }
    }
    Ok((version, code))
  }
  fn read_headers(&mut self) -> http::HeaderMap {
    // 读取请求头
    let mut headers = http::HeaderMap::new();
    let mut header_line = Vec::new();
    while let Ok(length) = self.reader.read_until(b'\n', &mut header_line) {
      if length == 0 || header_line == b"\r\n" {
        break;
      }
      if let Ok((Some(k), Some(v))) = parser_headers(&header_line) {
        headers.insert(k, v);
      };
      header_line.clear();
    }
    headers
  }
  fn read_body(&mut self, header: &http::HeaderMap) -> Result<Vec<u8>> {
    let mut content_length: Option<u64> = header
      .get(http::header::CONTENT_LENGTH)
      .and_then(|x| x.to_str().ok()?.parse().ok());
    if self.config.unsafe_response {
      content_length = None;
    }
    let mut body = Vec::new();
    if let Some(te) = header.get(http::header::TRANSFER_ENCODING) {
      if te == "chunked" {
        body = self.read_chunked_body()?;
      }
    } else if let Some(mut cl) = content_length {
      // 如果有最大读取限制，取一个最小的长度
      if let Some(max_read) = self.config.max_read {
        cl = std::cmp::min(cl, max_read);
      }
      let mut buf = vec![0; cl as usize];
      self.reader.read_exact(&mut buf)?;
      body = buf;
    } else {
      self.reader.read_to_end(&mut body)?;
    }
    if let Some(ce) = header.get(http::header::CONTENT_ENCODING) {
      if ce == "gzip" {
        let mut gzip_body = Vec::new();
        let mut d = MultiGzDecoder::new(&body[..]);
        d.read_to_end(&mut gzip_body)?;
        body = gzip_body;
      }
    }
    Ok(body)
  }

  fn read_chunked_body(&mut self) -> Result<Vec<u8>> {
    let mut body: Vec<u8> = Vec::new();
    loop {
      let mut chunk: String = String::new();
      loop {
        let mut one_byte = vec![0; 1];
        self.reader.read_exact(&mut one_byte)?;
        if one_byte[0] != 10 && one_byte[0] != 13 {
          chunk.push(one_byte[0] as char);
          break;
        }
      }
      loop {
        let mut one_byte = vec![0; 1];
        self.reader.read_exact(&mut one_byte)?;
        if one_byte[0] == 10 || one_byte[0] == 13 {
          self.reader.read_exact(&mut one_byte)?;
          break;
        } else {
          chunk.push(one_byte[0] as char)
        }
      }
      if chunk == "0" || chunk.is_empty() {
        break;
      }
      let chunk = usize::from_str_radix(&chunk, 16)?;
      let mut chunk_of_bytes = vec![0; chunk];
      self.reader.read_exact(&mut chunk_of_bytes)?;
      body.append(&mut chunk_of_bytes);
    }
    Ok(body)
  }

  /// Build a `Response`, which can be inspected, modified and executed with
  /// `Client::execute()`.
  pub fn build(mut self) -> Result<Response> {
    let (v, c) = self.parser_version()?;
    self.builder = self.builder.version(v).status(c);
    let header = self.read_headers();
    // 读取body
    let body = self.read_body(&header)?;
    if let Some(h) = self.builder.headers_mut() {
      *h = header;
    }
    let resp = self.builder.body(body)?;
    Ok(resp.into())
  }
}

pub(crate) fn parser_headers(
  buffer: &[u8],
) -> Result<(Option<http::HeaderName>, Option<http::HeaderValue>)> {
  let mut k = None;
  let mut v = None;
  let buffer = buffer.strip_suffix(CR_LF).unwrap_or(buffer);
  for (index, h) in buffer.splitn(2, |s| s == &58).enumerate() {
    let h = h.strip_prefix(SPACE).unwrap_or(h);
    match index {
      0 => match http::HeaderName::from_bytes(h) {
        Ok(hk) => k = Some(hk),
        Err(err) => {
          return Err(Error::Http(http::Error::from(err)));
        }
      },
      1 => match http::HeaderValue::from_bytes(h) {
        Ok(hv) => v = Some(hv),
        Err(err) => {
          return Err(Error::Http(http::Error::from(err)));
        }
      },
      _ => {}
    }
  }
  Ok((k, v))
}
