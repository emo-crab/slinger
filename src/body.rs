use std::fmt;
use std::ops::{Deref, DerefMut};

use bytes::Bytes;

/// A body.
#[derive(Clone, PartialEq)]
pub struct Body {
  inner: Bytes,
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
      Err(_err) => fmt::Debug::fmt(&self.inner, f),
    }
  }
}

impl fmt::Display for Body {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    match String::from_utf8(self.inner.to_vec()) {
      Ok(s) => fmt::Display::fmt(&s, f),
      Err(_err) => fmt::Debug::fmt(&self.inner, f),
    }
  }
}
#[cfg(feature = "serde")]
impl serde::Serialize for Body {
  fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
  where
    S: serde::Serializer,
  {
    serializer.serialize_bytes(&self.inner)
  }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Body {
  fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
  where
    D: serde::Deserializer<'de>,
  {
    let s = Vec::deserialize(deserializer)?;
    Ok(Body::from(s))
  }
}

#[cfg(feature = "serde")]
pub(crate) mod bytes_serde {
  use bytes::Bytes;
  use serde::{Deserializer, Serializer};

  pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
    s.serialize_bytes(v)
  }

  pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Bytes, D::Error> {
    let bytes: Vec<u8> = serde::Deserialize::deserialize(d)?;
    Ok(Bytes::from(bytes))
  }
}
