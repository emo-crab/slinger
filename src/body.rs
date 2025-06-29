use bytes::Bytes;
use std::fmt;
use std::fmt::Write;
use std::ops::{Deref, DerefMut};

/// A body.
#[derive(Clone, PartialEq)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct Body {
  pub(crate) inner: Bytes,
}

impl Deref for Body {
  type Target = Bytes;

  fn deref(&self) -> &Self::Target {
    &self.inner
  }
}

impl DerefMut for Body {
  fn deref_mut(&mut self) -> &mut Self::Target {
    &mut self.inner
  }
}

impl Default for Body {
  fn default() -> Self {
    Self {
      inner: Bytes::new(),
    }
  }
}

impl From<Bytes> for Body {
  #[inline]
  fn from(b: Bytes) -> Body {
    Body { inner: b }
  }
}

impl From<String> for Body {
  #[inline]
  fn from(s: String) -> Body {
    s.into_bytes().into()
  }
}

impl From<&'static str> for Body {
  #[inline]
  fn from(s: &'static str) -> Body {
    s.as_bytes().into()
  }
}

impl From<&'static [u8]> for Body {
  #[inline]
  fn from(s: &'static [u8]) -> Body {
    Body {
      inner: Bytes::from_static(s),
    }
  }
}

impl From<Vec<u8>> for Body {
  #[inline]
  fn from(v: Vec<u8>) -> Body {
    Body { inner: v.into() }
  }
}

impl From<&Option<String>> for Body {
  #[inline]
  fn from(v: &Option<String>) -> Body {
    match v {
      Some(vv) => Body {
        inner: Bytes::from(vv.clone()),
      },
      None => Body {
        inner: Bytes::new(),
      },
    }
  }
}

impl From<Option<Vec<u8>>> for Body {
  #[inline]
  fn from(v: Option<Vec<u8>>) -> Body {
    match v {
      Some(vv) => Body { inner: vv.into() },
      None => Body {
        inner: Bytes::new(),
      },
    }
  }
}

impl fmt::Debug for Body {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    match String::from_utf8(self.inner.to_vec()) {
      Ok(s) => fmt::Display::fmt(&s, f),
      Err(_err) => fmt::Display::fmt(
        &self
          .inner
          .as_ref()
          .iter()
          .fold(String::new(), |mut output, b| {
            let _ = write!(output, "\\x{b:02x}");
            output
          }),
        f,
      ),
    }
  }
}

impl fmt::Display for Body {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    match String::from_utf8(self.inner.to_vec()) {
      Ok(s) => fmt::Display::fmt(&s, f),
      Err(_err) => fmt::Display::fmt(
        &self
          .inner
          .as_ref()
          .iter()
          .fold(String::new(), |mut output, b| {
            let _ = write!(output, "\\x{b:02x}");
            output
          }),
        f,
      ),
    }
  }
}
