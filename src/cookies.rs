use bytes::Bytes;
use http::header::SET_COOKIE;
use http::HeaderValue;
use std::collections::BTreeMap;
use std::fmt::Debug;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::RwLock;
use std::time::SystemTime;

type NameMap = BTreeMap<String, Cookie<'static>>;
type PathMap = BTreeMap<String, NameMap>;
type DomainMap = BTreeMap<String, PathMap>;

#[derive(Debug, Default)]
pub struct Jar(RwLock<CookieStores>);

#[derive(Debug, Clone, Default)]
pub struct CookieStores {
  cookies: DomainMap,
}

impl CookieStores {
  pub fn get_request_values(&self, url: &http::Uri) -> impl Iterator<Item = (&str, &str)> {
    self.matches(url).into_iter().map(|c| c.0.name_value())
  }
  pub fn insert(&mut self, cookie: Cookie<'static>, request_url: &http::Uri) {
    let domain = if let Some(domain) = request_url.host() {
      domain.to_string()
    } else {
      return;
    };
    let path = if let Some(path) = cookie.path() {
      path.to_string()
    } else {
      return;
    };
    self
      .cookies
      .entry(domain)
      .or_default()
      .entry(path)
      .or_default()
      .insert(cookie.name().to_owned(), cookie);
  }
  pub fn store_response_cookies<I: Iterator<Item = Cookie<'static>>>(
    &mut self,
    cookies: I,
    url: &http::Uri,
  ) {
    for cookie in cookies {
      self.insert(cookie, url);
    }
  }
  pub fn matches(&self, request_url: &http::Uri) -> Vec<&Cookie<'static>> {
    let cookies = self
      .cookies
      .iter()
      .filter(|&(d, _)| domain_match(d, request_url))
      .flat_map(|(_, dcs)| {
        dcs
          .iter()
          .filter(|&(p, _)| path_match(p, request_url))
          .flat_map(|(_, pcs)| pcs.values().filter(|c| c.matches(request_url)))
      });
    match (!is_http_scheme(request_url), !is_secure(request_url)) {
      (true, true) => cookies.filter(|c| !c.http_only() && !c.secure()).collect(),
      (true, false) => cookies.filter(|c| !c.http_only()).collect(),
      (false, true) => cookies.filter(|c| !c.secure()).collect(),
      (false, false) => cookies.collect(),
    }
  }
}

pub fn domain_match(domain: &str, request_url: &http::Uri) -> bool {
  request_url.host().unwrap_or_default() == domain
}

pub fn path_match(cookie_path: &str, request_url: &http::Uri) -> bool {
  let request_path = request_url.path();
  cookie_path == request_path
    || (request_path.starts_with(cookie_path)
      && (cookie_path.ends_with('/')
        || &request_path[cookie_path.len()..=cookie_path.len()] == "/"))
}

fn is_http_scheme(url: &http::Uri) -> bool {
  url.scheme() == Some(&http::uri::Scheme::HTTP)
}

fn is_secure(url: &http::Uri) -> bool {
  if url.scheme() == Some(&http::uri::Scheme::HTTPS) {
    return true;
  }
  if let Some(u) = url.host() {
    match IpAddr::from_str(u) {
      Ok(ip) => ip.is_loopback(),
      Err(_) => u == "localhost",
    }
  } else {
    false
  }
}

pub trait CookieStore: Debug {
  fn set_cookies(&self, cookie_headers: &mut dyn Iterator<Item = &HeaderValue>, url: &http::Uri);
  fn cookies(&self, url: &http::Uri) -> Option<HeaderValue>;
}

#[derive(Debug, Clone)]
pub struct Cookie<'a>(cookie::Cookie<'a>);

impl<'a> Cookie<'a> {
  fn parse(value: &'a HeaderValue) -> Result<Cookie<'a>, cookie::ParseError> {
    std::str::from_utf8(value.as_bytes())
      .map_err(cookie::ParseError::from)
      .and_then(cookie::Cookie::parse)
      .map(Cookie)
  }

  pub fn name(&self) -> &str {
    self.0.name()
  }

  pub fn value(&self) -> &str {
    self.0.value()
  }

  pub fn http_only(&self) -> bool {
    self.0.http_only().unwrap_or(false)
  }

  pub fn secure(&self) -> bool {
    self.0.secure().unwrap_or(false)
  }

  pub fn same_site_lax(&self) -> bool {
    self.0.same_site() == Some(cookie::SameSite::Lax)
  }

  pub fn same_site_strict(&self) -> bool {
    self.0.same_site() == Some(cookie::SameSite::Strict)
  }

  pub fn path(&self) -> Option<&str> {
    self.0.path()
  }

  pub fn domain(&self) -> Option<&str> {
    self.0.domain()
  }

  pub fn max_age(&self) -> Option<std::time::Duration> {
    self.0.max_age().map(|d| {
      d.try_into()
        .expect("time::Duration into std::time::Duration")
    })
  }
  pub fn expires(&self) -> Option<SystemTime> {
    match self.0.expires() {
      Some(cookie::Expiration::DateTime(offset)) => Some(SystemTime::from(offset)),
      None | Some(cookie::Expiration::Session) => None,
    }
  }
  pub fn matches(&self, request_url: &http::Uri) -> bool {
    (!self.0.secure().unwrap_or(false) || is_secure(request_url))
      && (!self.0.http_only().unwrap_or(false) || is_http_scheme(request_url))
  }
}

impl CookieStore for Jar {
  fn set_cookies(&self, cookie_headers: &mut dyn Iterator<Item = &HeaderValue>, url: &http::Uri) {
    let iter =
      cookie_headers.filter_map(|val| Cookie::parse(val).map(|c| Cookie(c.0.into_owned())).ok());
    if let Ok(mut w) = self.0.write() {
      w.store_response_cookies(iter, url);
    }
  }

  fn cookies(&self, url: &http::Uri) -> Option<HeaderValue> {
    let s = self
      .0
      .read()
      .ok()?
      .get_request_values(url)
      .map(|(name, value)| format!("{name}={value}"))
      .collect::<Vec<_>>()
      .join("; ");
    if s.is_empty() {
      return None;
    }
    HeaderValue::from_maybe_shared(Bytes::from(s)).ok()
  }
}

pub(crate) fn extract_response_cookie_headers(
  headers: &http::HeaderMap,
) -> impl Iterator<Item = &HeaderValue> {
  headers.get_all(SET_COOKIE).iter()
}

pub(crate) fn extract_response_cookies(
  headers: &http::HeaderMap,
) -> impl Iterator<Item = Result<Cookie, cookie::ParseError>> {
  headers.get_all(SET_COOKIE).iter().map(Cookie::parse)
}
