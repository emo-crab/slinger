use crate::Response;
use http::header::{AUTHORIZATION, COOKIE, PROXY_AUTHORIZATION, WWW_AUTHENTICATE};
use http::HeaderMap;
use std::path::PathBuf;
use std::str::FromStr;
/// A type that controls the policy on how to handle the following of redirects.
///
/// The default value will catch redirect loops, and has a maximum of 10
/// redirects it will follow in a chain before returning an error.
///
/// - `limited` can be used have the same as the default behavior, but adjust
///   the allowed maximum redirect hops in a chain.
/// - `none` can be used to disable all redirect behavior.
/// - `custom` can be used to create a customized policy.
#[derive(Clone, Debug, PartialEq)]
pub enum Policy {
  /// - `custom` can be used to create a customized policy. see [only_same_host].
  Custom(fn(Attempt) -> Action),
  /// - `limited` can be used have the same as the default behavior, but adjust
  Limit(usize),
  /// - `none` can be used to disable all redirect behavior.
  None,
}

/// A type that holds information on the current response and previous requests
/// in redirect chain.
#[derive(Clone, Debug, PartialEq)]
pub struct Attempt<'a> {
  response: &'a Response,
  previous: &'a [http::Uri],
}

/// An action to perform when a redirect status code is found.
#[derive(Clone, Debug, PartialEq)]
pub enum Action {
  /// Follow next url
  Follow(http::Uri),
  /// Stop
  Stop(http::Uri),
  /// None
  None,
}

impl Policy {
  /// Create a `Policy` with a maximum number of redirects.
  ///
  /// An `Error` will be returned if the max is reached.
  pub fn limited(max: usize) -> Self {
    Policy::Limit(max)
  }
  /// Create a `Policy` that does not follow any redirect.
  pub fn none() -> Self {
    Policy::None
  }
  /// Create a custom `Policy` using the passed function.
  ///
  /// # Note
  ///
  /// The default `Policy` handles a maximum loop
  /// chain, but the custom variant does not do that for you automatically.
  /// The custom policy should have some way of handling those.
  ///
  /// Information on the next request and previous requests can be found
  /// on the [`Attempt`] argument passed to the closure.
  ///
  /// Actions can be conveniently created from methods on the
  /// [`Attempt`].
  ///
  /// # Example
  ///
  /// ```rust
  /// # use slinger::{Error, redirect};
  /// #
  /// # fn run() -> Result<(), Error> {
  /// let custom = redirect::Policy::custom(|attempt| {
  ///     if attempt.previous().len() > 5 {
  ///         attempt.none()
  ///     } else if attempt.url().host() == Some("example.domain") {
  ///         // prevent redirects to 'example.domain'
  ///         attempt.none()
  ///     } else {
  ///         match attempt.default_redirect(){
  ///           Some(next)=> attempt.follow(next),
  ///           None => attempt.none()
  ///         }
  ///     }
  /// });
  /// let client = slinger::Client::builder()
  ///     .redirect(custom)
  ///     .build()?;
  /// # Ok(())
  /// # }
  /// ```
  ///
  /// [`Attempt`]: struct.Attempt.html
  pub fn custom(policy: fn(Attempt) -> Action) -> Self {
    Policy::Custom(policy)
  }
  // Redirect options

  /// Set a `RedirectPolicy` for this client.
  ///
  /// Default will follow redirects up to a maximum of 10.
  pub fn redirect(&self, attempt: Attempt) -> Action {
    match self {
      Policy::Custom(ref custom) => custom(attempt),
      Policy::Limit(max) => match attempt.default_redirect() {
        Some(next) => {
          if attempt.previous.len() >= *max {
            attempt.stop(next)
          } else {
            attempt.follow(next)
          }
        }
        None => attempt.none(),
      },
      Policy::None => attempt.none(),
    }
  }

  pub(crate) fn check(&self, response: &Response, previous: &[http::Uri]) -> Action {
    self.redirect(Attempt { response, previous })
  }
}

impl Default for Policy {
  fn default() -> Policy {
    Policy::limited(10)
  }
}

impl<'a> Attempt<'a> {
  /// Get the type of redirect.
  pub fn response(&self) -> &Response {
    self.response
  }
  /// Get the type of redirect.
  pub fn url(&self) -> &http::Uri {
    self.response.uri()
  }
  /// Get the list of previous URLs that have already been requested in this chain.
  pub fn previous(&self) -> &[http::Uri] {
    self.previous
  }
  /// Returns an action meaning slinger should follow the next URL.
  pub fn follow(self, next: http::Uri) -> Action {
    Action::Follow(next)
  }
  /// Returns an action meaning slinger should not follow the next URL.
  pub fn stop(self, next: http::Uri) -> Action {
    Action::Stop(next)
  }
  /// Returns an action meaning slinger should not follow the next URL.
  pub fn none(self) -> Action {
    Action::None
  }
  /// default get next redirect from response
  pub fn default_redirect(&self) -> Option<http::Uri> {
    // 在请求头获取下一跳URL
    let cur_uri = self.response.uri();
    let loc = self
      .response
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
    loc
  }
}

/// only_same_host
pub fn only_same_host(attempt: Attempt) -> Action {
  match attempt.default_redirect() {
    Some(next) => {
      let p = attempt.url();
      // 如果上一个链接的主机和当前主机一样可以跟随跳转
      if p.host() == next.host() {
        if attempt.previous.len() > 10_usize {
          // 前后同主机，但是超过最大跳转
          attempt.stop(next)
        } else {
          attempt.follow(next)
        }
      } else {
        // 前后主机不同，取消跳转
        attempt.stop(next)
      }
    }
    None => Action::None,
  }
}

pub(crate) fn remove_sensitive_headers(
  headers: &mut HeaderMap,
  next: &http::Uri,
  previous: &[http::Uri],
) {
  if let Some(previous) = previous.last() {
    let cross_host = next.host() != previous.host() || next.port_u16() != previous.port_u16();
    if cross_host {
      headers.remove(AUTHORIZATION);
      headers.remove(COOKIE);
      headers.remove("cookie2");
      headers.remove(PROXY_AUTHORIZATION);
      headers.remove(WWW_AUTHENTICATE);
    }
  }
}
