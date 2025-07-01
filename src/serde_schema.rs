use crate::Body;
impl serde::Serialize for Body {
  fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
  where
    S: serde::Serializer,
  {
    if serializer.is_human_readable() {
      serializer.serialize_str(&String::from_utf8_lossy(&self.inner))
    } else {
      serializer.serialize_bytes(&self.inner)
    }
  }
}

impl<'de> serde::Deserialize<'de> for Body {
  fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
  where
    D: serde::Deserializer<'de>,
  {
    // 支持从字符串或字节数组反序列化
    if deserializer.is_human_readable() {
      let s = String::deserialize(deserializer)?;
      Ok(Body::from(s))
    } else {
      let bytes: Vec<u8> = serde::Deserialize::deserialize(deserializer)?;
      Ok(Body::from(bytes))
    }
  }
}

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
#[cfg(feature = "schema")]
pub(crate) fn status_code_schema(_gen: &mut schemars::SchemaGenerator) -> schemars::Schema {
  schemars::json_schema!({
      "type": "integer",
      "format": "uint16",
      "minimum": 100,
      "maximum": 599,
      "title": "HTTP status code",
      "description": "Standard HTTP status code indicating response status",
      "examples": [200, 404, 500],
      "enum": [
          100, 101, 102, 103,
          200, 201, 202, 203, 204, 205, 206, 207, 208, 226,
          300, 301, 302, 303, 304, 305, 307, 308,
          400, 401, 402, 403, 404, 405, 406, 407, 408, 409,
          410, 411, 412, 413, 414, 415, 416, 417, 418, 421,
          422, 423, 424, 425, 426, 428, 429, 431, 451,
          500, 501, 502, 503, 504, 505, 506, 507, 508, 510, 511
      ]
  })
}
#[cfg(feature = "schema")]
pub(crate) fn http_method_schema(_gen: &mut schemars::SchemaGenerator) -> schemars::Schema {
  schemars::json_schema!({
      "type": "string",
      "enum": ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT", "TRACE"],
      "title": "HTTP method",
      "description": "The HTTP method indicating the desired action for the resource",
      "example": "GET"
  })
}
