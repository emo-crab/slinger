#![deny(missing_docs)]
#![cfg_attr(docsrs, feature(doc_cfg))]

//! # slinger (投石手)
//!
//! The `slinger` crate provides a convenient, low-level HTTP
//! [`Client`].
//!
//! It handles many of the things that most people just expect an HTTP client
//! to do for them.
//!
//! - Customizable [redirect policy](#redirect-policies)
//! - HTTP [Proxies](#proxies)
//! - Uses [TLS](#tls) by default
//! - Cookies
//!
//!
//! Additional learning resources include:
//!
//! - [Slinger Repository Examples](https://github.com/emo-crab/slinger/tree/master/examples)
//!
//! ## Making a GET request
//!
//! For a single request, you can use the [`get`] shortcut method.
//!
//! ```rust
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!   let body = slinger::get("https://httpbin.org/get")?
//!     .text()?;
//!   println!("body = {body:?}");
//!   Ok(())
//! }
//! ```
//!
//! **NOTE**: If you plan to perform multiple requests, it is best to create a
//! [`Client`] and reuse it, taking advantage of keep-alive connection
//! pooling.
//!
//! ## Making POST requests (or setting request bodies)
//!
//! There are several ways you can set the body of a request. The basic one is
//! by using the `body()` method of a [`RequestBuilder`]. This lets you set the
//! exact raw bytes of what the body should be. It accepts various types,
//! including `String` and `Vec<u8>`. If you wish to pass a custom
//! type, you can use the `slinger::Body` constructors.
//!
//! ```rust
//! # use slinger::Error;
//! #
//! # fn run() -> Result<(), Error> {
//! let client = slinger::Client::new();
//! let res = client.post("http://httpbin.org/post")
//!     .body("the exact body that is sent")
//!     .send()?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Redirect Policies
//!
//! By default, a `Client` will automatically handle HTTP redirects, having a
//! maximum redirect chain of 10 hops. To customize this behavior, a
//! [`redirect::Policy`][redirect] can be used with a `ClientBuilder`.
//!
//! ## Cookies
//!
//! The automatic storing and sending of session cookies can be enabled with
//! the [`cookie_store`][client::ClientBuilder::cookie_store] method on `ClientBuilder`.
//!
//! ## Proxies
//!```rust
//! fn run() -> std::result::Result<(), Box<dyn std::error::Error>> {
//!   let proxy = slinger::Proxy::parse("http://user:pass@127.0.0.1:1080").unwrap();
//!   // let proxy = slinger::Proxy::parse("socks5://user:pass@127.0.0.1:1080").unwrap();
//!   let client = slinger::ClientBuilder::new().proxy(proxy).build().unwrap();
//!   let resp = client.get("https://httpbin.org/get").send()?;
//!   println!("{:?}", resp);
//!   Ok(())
//! }
//!```
//! ## TLS
//!
//! A `Client` will use transport layer security (TLS) by default to connect to
//! HTTPS destinations.
//!
//! - Additional server certificates can be configured on a `ClientBuilder`
//!   with the [`native_tls::Certificate`] type.
//! - Client certificates can be added to a `ClientBuilder` with the
//!   [`native_tls::Identity`] type.
//! - Various parts of TLS can also be configured or even disabled on the
//!   `ClientBuilder`.
//!
//! ## Optional Features
//!
//! The following are a list of [Cargo features][cargo-features] that can be
//! enabled or disabled:
//!
//! - **charset**: Improved support for decoding text.
//! - **cookie**: Provides cookie session support.
//! - **tls**: Provides https support.
//! - **serde**: Provides serialization and deserialization support.
//! - **gzip**: Provides response body gzip decompression.
//!
mod body;
mod client;
mod connector;
#[cfg(feature = "cookie")]
mod cookies;
mod errors;
mod proxy;
/// record info
pub mod record;
/// Redirect Handling
pub mod redirect;
mod request;
mod response;
mod socket;

use bytes::Bytes;
pub use body::Body;
pub use client::{Client, ClientBuilder};
pub use connector::{Connector, ConnectorBuilder};
pub use errors::{Error, Result};
pub use http::header;
pub use http::uri;
pub use http::Method;
pub use http::{StatusCode, Version};
#[cfg(feature = "tls")]
pub use native_tls;
#[cfg(feature = "tls")]
pub use openssl;
pub use proxy::Proxy;
pub use request::{Request, RequestBuilder};
pub use response::{Response, ResponseBuilder, ResponseConfig};
pub use socket::Socket;

/// Shortcut method to quickly make a `GET` request.
///
/// See also the methods on the [`slinger::Response`](./struct.Response.html)
/// type.
///
/// **NOTE**: This function creates a new internal `Client` on each call,
/// and so should not be used if making many requests. Create a
/// [`Client`](./struct.Client.html) instead.
///
/// # Examples
///
/// ```rust
/// # fn run() -> Result<(), slinger::Error> {
/// let body = slinger::get("https://www.rust-lang.org")?
///     .text()?;
/// # Ok(())
/// # }
/// ```
///
pub fn get<U>(url: U) -> errors::Result<Response>
  where
    http::Uri: TryFrom<U>,
    <http::Uri as TryFrom<U>>::Error: Into<http::Error>,
{
  Client::builder().build()?.get(url).send()
}
/// Shortcut method to quickly make a `RAW` request.
///
/// See also the methods on the [`slinger::Response`](./struct.Response.html)
/// type.
///
/// **NOTE**: This function creates a new internal `Client` on each call,
/// and so should not be used if making many requests. Create a
/// [`Client`](./struct.Client.html) instead.
///
/// # Examples
///
/// ```rust
/// # fn run() -> Result<(), slinger::Error> {
/// let body = slinger::raw("http://httpbin.org",b"GET /robots HTTP/1.1\r\n\r\n",true)?
///     .text()?;
/// # Ok(())
/// # }
/// ```
///
pub fn raw<U, R>(uri: U, raw: R, unsafe_raw: bool) -> errors::Result<Response>
  where
    Bytes: From<R>,
    http::Uri: TryFrom<U>,
    <http::Uri as TryFrom<U>>::Error: Into<http::Error>,
{
  Client::builder().build()?.raw(uri, raw, unsafe_raw).send()
}

pub(crate) const CR_LF: &[u8] = &[13, 10];
pub(crate) const SPACE: &[u8] = &[32];
pub(crate) const COLON_SPACE: &[u8] = &[58, 32];

#[cfg(test)]
mod tests {
  #[test]
  fn it_works() {
    let result = 2 + 2;
    assert_eq!(result, 4);
  }
}
