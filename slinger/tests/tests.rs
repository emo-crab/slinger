#[cfg(test)]
mod tests {

  #[test]
  fn it_works() {}

  use slinger::{ResponseBuilder, ResponseConfig};
  use std::io::Cursor;
  use tokio::io::BufReader;

  /// Helper to create a simple HTTP response as bytes
  fn create_mock_response(status: u16, headers: &[(&str, &str)], body: &str) -> Vec<u8> {
    let mut response = format!("HTTP/1.1 {} OK\r\n", status);
    for (name, value) in headers {
      response.push_str(&format!("{}: {}\r\n", name, value));
    }
    response.push_str("\r\n");
    response.push_str(body);
    response.into_bytes()
  }

  /// Test that streaming response correctly parses headers without reading body
  #[tokio::test]
  async fn test_streaming_response_headers_only() {
    let body_content = "This is the body content";
    let response_bytes = create_mock_response(
      200,
      &[
        ("Content-Type", "text/plain"),
        ("Content-Length", &body_content.len().to_string()),
      ],
      body_content,
    );

    let cursor = Cursor::new(response_bytes);
    let reader = BufReader::new(cursor);
    let config = ResponseConfig::default();

    let builder = ResponseBuilder::new(reader, config);
    let streaming = builder.build_streaming().await.unwrap();

    // Verify headers are parsed
    assert_eq!(streaming.status_code(), http::StatusCode::OK);
    assert_eq!(streaming.version(), http::Version::HTTP_11);
    assert!(streaming.headers().contains_key("content-type"));
    assert!(streaming.headers().contains_key("content-length"));
    assert_eq!(
      streaming.content_length(),
      Some(body_content.len() as u64)
    );
  }

  /// Test that streaming response can read body incrementally
  #[tokio::test]
  async fn test_streaming_response_read_body() {
    let body_content = "Line 1\nLine 2\nLine 3\n";
    let response_bytes = create_mock_response(
      200,
      &[("Content-Length", &body_content.len().to_string())],
      body_content,
    );

    let cursor = Cursor::new(response_bytes);
    let reader = BufReader::new(cursor);
    let config = ResponseConfig::default();

    let builder = ResponseBuilder::new(reader, config);
    let mut streaming = builder.build_streaming().await.unwrap();

    // Read lines one by one
    let mut line = String::new();
    let n = streaming.read_line(&mut line).await.unwrap();
    assert!(n > 0);
    assert_eq!(line, "Line 1\n");

    line.clear();
    let n = streaming.read_line(&mut line).await.unwrap();
    assert!(n > 0);
    assert_eq!(line, "Line 2\n");
  }

  /// Test that streaming response can be converted to a regular response
  #[tokio::test]
  async fn test_streaming_response_finish() {
    let body_content = "Complete body";
    let response_bytes = create_mock_response(
      201,
      &[("Content-Length", &body_content.len().to_string())],
      body_content,
    );

    let cursor = Cursor::new(response_bytes);
    let reader = BufReader::new(cursor);
    let config = ResponseConfig::default();

    let builder = ResponseBuilder::new(reader, config);
    let streaming = builder.build_streaming().await.unwrap();

    // Convert to full response
    let (response, _socket) = streaming.finish().await.unwrap();

    assert_eq!(response.status_code(), http::StatusCode::CREATED);
    assert!(response.body().is_some());
    let body = response.body().as_ref().unwrap();
    assert_eq!(body.as_ref(), body_content.as_bytes());
  }

  /// Test that streaming response can read arbitrary chunks
  #[tokio::test]
  async fn test_streaming_response_read_chunks() {
    let body_content = "ABCDEFGHIJKLMNOP";
    let response_bytes = create_mock_response(
      200,
      &[("Content-Length", &body_content.len().to_string())],
      body_content,
    );

    let cursor = Cursor::new(response_bytes);
    let reader = BufReader::new(cursor);
    let config = ResponseConfig::default();

    let builder = ResponseBuilder::new(reader, config);
    let mut streaming = builder.build_streaming().await.unwrap();

    // Read in small chunks
    let mut buf = [0u8; 4];
    let n = streaming.read(&mut buf).await.unwrap();
    assert_eq!(n, 4);
    assert_eq!(&buf, b"ABCD");

    let n = streaming.read(&mut buf).await.unwrap();
    assert_eq!(n, 4);
    assert_eq!(&buf, b"EFGH");
  }

  /// Test AsyncRead implementation
  #[tokio::test]
  async fn test_streaming_response_async_read() {
    use tokio::io::AsyncReadExt;

    let body_content = "async read test";
    let response_bytes = create_mock_response(
      200,
      &[("Content-Length", &body_content.len().to_string())],
      body_content,
    );

    let cursor = Cursor::new(response_bytes);
    let reader = BufReader::new(cursor);
    let config = ResponseConfig::default();

    let builder = ResponseBuilder::new(reader, config);
    let mut streaming = builder.build_streaming().await.unwrap();

    // Use AsyncReadExt directly
    let mut buf = vec![0u8; 5];
    let n = AsyncReadExt::read(&mut streaming, &mut buf).await.unwrap();
    assert_eq!(n, 5);
    assert_eq!(&buf, b"async");
  }

  /// Test AsyncBufRead implementation
  #[tokio::test]
  async fn test_streaming_response_async_buf_read() {
    use tokio::io::AsyncBufReadExt;

    let body_content = "buffered\nreading\n";
    let response_bytes = create_mock_response(
      200,
      &[("Content-Length", &body_content.len().to_string())],
      body_content,
    );

    let cursor = Cursor::new(response_bytes);
    let reader = BufReader::new(cursor);
    let config = ResponseConfig::default();

    let builder = ResponseBuilder::new(reader, config);
    let mut streaming = builder.build_streaming().await.unwrap();

    // Use AsyncBufReadExt directly
    let mut line = String::new();
    let n = AsyncBufReadExt::read_line(&mut streaming, &mut line)
      .await
      .unwrap();
    assert!(n > 0);
    assert_eq!(line, "buffered\n");
  }

  /// Test that regular build() still works as expected
  #[tokio::test]
  async fn test_regular_build_still_works() {
    let body_content = "regular body";
    let response_bytes = create_mock_response(
      200,
      &[("Content-Length", &body_content.len().to_string())],
      body_content,
    );

    let cursor = Cursor::new(response_bytes);
    let reader = BufReader::new(cursor);
    let config = ResponseConfig::default();

    let builder = ResponseBuilder::new(reader, config);
    let (response, _socket) = builder.build().await.unwrap();

    assert_eq!(response.status_code(), http::StatusCode::OK);
    assert!(response.body().is_some());
    let body = response.body().as_ref().unwrap();
    assert_eq!(body.as_ref(), body_content.as_bytes());
  }
}
