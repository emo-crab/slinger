use std::fmt::Debug;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, BufReader};

use crate::body::Body;
#[cfg(feature = "cookie")]
use crate::cookies;
use crate::errors::{new_io_error, Error, Result};
use crate::record::{HTTPRecord, LocalPeerRecord, RedirectRecord};
#[cfg(feature = "tls")]
use crate::tls::PeerCertificate;
use crate::{Request, COLON_SPACE, CR_LF, SPACE};
use bytes::Bytes;
#[cfg(feature = "charset")]
use encoding_rs::{Encoding, UTF_8};
#[cfg(feature = "gzip")]
use flate2::read::MultiGzDecoder;
use http::{Method, Response as HttpResponse};
#[cfg(feature = "charset")]
use mime::Mime;
#[cfg(feature = "gzip")]
use std::io::Read;

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
  /// This requires the optional `cookie` feature to be enabled.
  #[cfg(feature = "cookie")]
  #[cfg_attr(docsrs, doc(cfg(feature = "cookie")))]
  pub fn cookies(&self) -> impl Iterator<Item = cookies::Cookie> {
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
    for encoding_name in &[header_encoding, default_encoding] {
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
  /// # async fn run() -> Result<(), Box<dyn std::error::Error>> {
  /// let content = slinger::get("http://httpbin.org/range/26").await?.text()?;
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
  /// use slinger::http::StatusCode;
  /// # async fn run() -> Result<(), Box<dyn std::error::Error>> {
  /// let client = Client::new();
  ///
  /// let resp = client.post("http://httpbin.org/post")
  ///     .body("possibly too large")
  ///     .send().await?;
  ///
  /// match resp.status_code() {
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
  /// use slinger::http::header::ETAG;
  ///
  /// # async fn run() -> Result<(), Box<dyn std::error::Error>> {
  /// let client = Client::new();
  ///
  /// let mut resp = client.get("http://httpbin.org/cache").send().await?;
  /// if resp.status_code().is_success() {
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
  /// # async fn run() -> Result<(), Box<dyn std::error::Error>> {
  /// let resp = slinger::get("http://httpbin.org/redirect/1").await?;
  /// assert_eq!(resp.uri().to_string().as_str(), "http://httpbin.org/get");
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
  /// Get the full response body as `Bytes`.
  ///
  /// # Example
  ///
  /// ```
  /// # async fn run() -> Result<(), Box<dyn std::error::Error>> {
  /// let resp = slinger::get("http://httpbin.org/ip").await?;
  /// let body = resp.body();
  /// println!("bytes: {body:?}");
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

/// 放一些响应中间过程记录，存起来方便获取
impl Response {
  /// Get the remote address used to get this `Response`.
  ///
  /// # Example
  ///
  /// ```rust
  /// # async fn run() -> Result<(), Box<dyn std::error::Error>> {
  /// let resp = slinger::get("http://httpbin.org/redirect/1").await?;
  /// println!("httpbin.org address: {:?}", resp.local_peer_record());
  /// # Ok(())
  /// # }
  /// ```
  pub fn local_peer_record(&self) -> Option<&LocalPeerRecord> {
    self.extensions().get::<LocalPeerRecord>()
  }
  /// Get the certificate to get this `Response`.
  ///
  /// # Example
  ///
  /// ```rust
  /// # async fn run() -> Result<(), Box<dyn std::error::Error>> {
  /// let resp = slinger::get("https://httpbin.org/").await?;
  /// println!("httpbin.org certificate: {:?}", resp.certificate());
  /// # Ok(())
  /// # }
  /// ```

  #[cfg(feature = "tls")]
  pub fn certificate(&self) -> Option<&PeerCertificate> {
    self.extensions().get::<PeerCertificate>()
  }
  /// Get the http record used to get this `Response`.
  ///
  /// # Example
  ///
  /// ```rust
  /// # async fn run() -> Result<(), Box<dyn std::error::Error>> {
  /// let resp = slinger::get("http://httpbin.org/redirect/1").await?;
  /// println!("httpbin.org http: {:?}", resp.http_record());
  /// # Ok(())
  /// # }
  /// ```
  pub fn http_record(&self) -> Option<&Vec<HTTPRecord>> {
    self.extensions().get::<Vec<HTTPRecord>>()
  }
  /// Get the request used to get this `Response`.
  ///
  /// # Example
  ///
  /// ```rust
  /// # async fn run() -> Result<(), Box<dyn std::error::Error>> {
  /// let resp = slinger::get("http://httpbin.org/redirect/1").await?;
  /// println!("httpbin.org request: {:?}", resp.request());
  /// # Ok(())
  /// # }
  /// ```
  pub fn request(&self) -> Option<&Request> {
    self.extensions().get::<Request>()
  }
  /// Get the redirect record used to get this `Response`.
  ///
  /// # Example
  ///
  /// ```rust
  /// # async fn run() -> Result<(), Box<dyn std::error::Error>> {
  /// let resp = slinger::get("http://httpbin.org/redirect-to?url=http://www.example.com/").await?;
  /// println!("httpbin.org redirect: {:?}", resp.redirect_record());
  /// # Ok(())
  /// # }
  /// ```
  pub fn redirect_record(&self) -> Option<&RedirectRecord> {
    self.extensions().get::<RedirectRecord>()
  }
}

/// A builder to construct the properties of a `Response`.
///
/// To construct a `ResponseBuilder`, refer to the `Client` documentation.
#[derive(Debug)]
pub struct ResponseBuilder<T: AsyncRead + AsyncReadExt> {
  builder: http::response::Builder,
  reader: BufReader<T>,
  config: ResponseConfig,
}

/// response config
#[derive(Debug, Default)]
pub struct ResponseConfig {
  method: Method,
  timeout: Option<Duration>,
  unsafe_response: bool,
  max_read: Option<u64>,
}

impl ResponseConfig {
  /// new a response config
  pub fn new(request: &Request, timeout: Option<Duration>) -> Self {
    let method = request.method().clone();
    let unsafe_response = request.is_unsafe();
    ResponseConfig {
      method,
      timeout,
      unsafe_response,
      max_read: None,
    }
  }
}

impl<T: AsyncRead + Unpin + Sized> ResponseBuilder<T> {
  /// Constructs a new response.
  pub fn new(reader: BufReader<T>, config: ResponseConfig) -> ResponseBuilder<T> {
    ResponseBuilder {
      builder: Default::default(),
      reader,
      config,
    }
  }
  async fn parser_version(&mut self) -> Result<(http::Version, http::StatusCode)> {
    let (mut vf, mut sf) = (false, false);
    let mut lines = Vec::new();
    if let Ok(_length) = self.reader.read_until(b'\n', &mut lines).await {
      let mut version = http::Version::default();
      let mut sc = http::StatusCode::default();
      for (index, vc) in lines.splitn(3, |b| b == &b' ').enumerate() {
        if vc.is_empty() {
          return Err(new_io_error(
            std::io::ErrorKind::InvalidData,
            "invalid http version and status_code data",
          ));
        }
        match index {
          0 => {
            version = match vc {
              b"HTTP/0.9" => http::Version::HTTP_09,
              b"HTTP/1.0" => http::Version::HTTP_10,
              b"HTTP/1.1" => http::Version::HTTP_11,
              b"HTTP/2.0" => http::Version::HTTP_2,
              b"HTTP/3.0" => http::Version::HTTP_3,
              _ => {
                return Err(new_io_error(
                  std::io::ErrorKind::InvalidData,
                  "invalid http version",
                ));
              }
            };
            vf = true;
          }
          1 => {
            sc = http::StatusCode::try_from(vc).map_err(|x| Error::Http(http::Error::from(x)))?;
            sf = true;
          }
          _ => {}
        }
      }
      if !(vf && sf) {
        return Err(new_io_error(
          std::io::ErrorKind::InvalidData,
          "invalid http version and status_code data",
        ));
      }
      Ok((version, sc))
    } else {
      Err(new_io_error(
        std::io::ErrorKind::InvalidData,
        "invalid http version and status_code data",
      ))
    }
  }
  async fn read_headers(&mut self) -> http::HeaderMap {
    // 读取请求头
    let mut headers = http::HeaderMap::new();
    let mut header_line = Vec::new();
    while let Ok(length) = self.reader.read_until(b'\n', &mut header_line).await {
      if length == 0 || header_line == b"\r\n" {
        break;
      }
      if let Ok((Some(k), Some(v))) = parser_headers(&header_line) {
        if headers.contains_key(&k) {
          headers.append(k, v);
        } else {
          headers.insert(k, v);
        }
      };
      header_line.clear();
    }
    headers
  }
  async fn read_body(&mut self, header: &http::HeaderMap) -> Result<Vec<u8>> {
    let mut body = Vec::new();
    if matches!(self.config.method, Method::HEAD) {
      return Ok(body);
    }
    let mut content_length: Option<u64> = header.get(http::header::CONTENT_LENGTH).and_then(|x| {
      x.to_str()
        .ok()?
        .parse()
        .ok()
        .and_then(|l| if l == 0 { None } else { Some(l) })
    });
    if self.config.unsafe_response {
      content_length = None;
    }
    if let Some(te) = header.get(http::header::TRANSFER_ENCODING) {
      if te == "chunked" {
        body = self.read_chunked_body().await?;
      }
    } else {
      let limits = content_length.map(|x| {
        if let Some(max) = self.config.max_read {
          std::cmp::min(x, max)
        } else {
          x
        }
      });
      let mut buffer = vec![0; 12]; // 定义一个缓冲区
      let mut total_bytes_read = 0;
      let timeout = self.config.timeout;
      loop {
        let size = if let Some(to) = timeout {
          match tokio::time::timeout(to, self.reader.read(&mut buffer)).await {
            Ok(size) => size,
            Err(_) => break,
          }
        } else {
          self.reader.read(&mut buffer).await
        };
        match size {
          Ok(0) => break,
          Ok(n) => {
            body.extend_from_slice(&buffer[..n]);
            total_bytes_read += n;
            // 当有读取到数据的时候重置计时器
          }
          Err(ref err) if err.kind() == std::io::ErrorKind::WouldBlock => {
            // 如果没有数据可读，但超时尚未到达，可以在这里等待或重试
            // 当已经有数据了或者触发超时就跳出循环，防止防火墙一直把会话挂着不释放
            if total_bytes_read > 0 {
              break;
            }
          }
          Err(_err) => break,
        }
        // 检查是否读取到了全部数据，如果是，则退出循环
        if let Some(limit) = limits {
          if total_bytes_read >= limit as usize {
            break;
          }
        }
      }
    }
    #[cfg(feature = "gzip")]
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

  async fn read_chunked_body(&mut self) -> Result<Vec<u8>> {
    let mut body: Vec<u8> = Vec::new();
    loop {
      let mut chunk: String = String::new();
      loop {
        let mut one_byte = vec![0; 1];
        self.reader.read_exact(&mut one_byte).await?;
        if one_byte[0] != 10 && one_byte[0] != 13 {
          chunk.push(one_byte[0] as char);
          break;
        }
      }
      loop {
        let mut one_byte = vec![0; 1];
        self.reader.read_exact(&mut one_byte).await?;
        if one_byte[0] == 10 || one_byte[0] == 13 {
          self.reader.read_exact(&mut one_byte).await?;
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
      self.reader.read_exact(&mut chunk_of_bytes).await?;
      body.append(&mut chunk_of_bytes);
    }
    Ok(body)
  }

  /// Build a `Response`, which can be inspected, modified and executed with
  /// `Client::execute()`.
  pub async fn build(mut self) -> Result<Response> {
    let (v, c) = self.parser_version().await?;
    self.builder = self.builder.version(v).status(c);
    let header = self.read_headers().await;
    // 读取body
    let body = self.read_body(&header).await?;
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
