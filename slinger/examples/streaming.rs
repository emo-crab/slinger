//! Example demonstrating the streaming response feature.
//!
//! This example shows how to use `ResponseBuilder::build_streaming()` to get
//! access to HTTP response headers without reading the body, and then stream
//! the body data incrementally.
//!
//! Run with:
//! ```bash
//! cargo run --example streaming
//! ```

use slinger::{ResponseBuilder, ResponseConfig};
use std::io::Cursor;
use tokio::io::BufReader;

/// Create a simple mock HTTP response for demonstration
fn create_mock_response() -> Vec<u8> {
  let body = "Line 1: Hello World\nLine 2: Streaming Response\nLine 3: End of data\n";
  let mut response = String::new();
  response.push_str("HTTP/1.1 200 OK\r\n");
  response.push_str("Content-Type: text/plain\r\n");
  response.push_str(&format!("Content-Length: {}\r\n", body.len()));
  response.push_str("\r\n");
  response.push_str(body);
  response.into_bytes()
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
  println!("Streaming Response Example");
  println!("==========================\n");

  // Create a mock HTTP response
  let response_bytes = create_mock_response();
  let cursor = Cursor::new(response_bytes);
  let reader = BufReader::new(cursor);
  let config = ResponseConfig::default();

  // Use build_streaming() to get a StreamingResponse
  // This parses headers without reading the body
  let builder = ResponseBuilder::new(reader, config);
  let mut streaming = builder.build_streaming().await?;

  // Access headers and status immediately - body not read yet!
  println!("Status Code: {}", streaming.status_code());
  println!("HTTP Version: {:?}", streaming.version());
  println!("Content-Length: {:?}", streaming.content_length());
  println!("\nHeaders:");
  for (name, value) in streaming.headers().iter() {
    println!("  {}: {:?}", name, value);
  }

  println!("\n--- Reading body line by line ---\n");

  // Read body line by line - streaming!
  let mut line_number = 0;
  let mut line = String::new();
  while streaming.read_line(&mut line).await? > 0 {
    line_number += 1;
    print!("Read line {}: {}", line_number, line);
    line.clear();
  }

  println!("\n--- Done reading {} lines ---", line_number);

  // Example 2: Converting streaming response to full response
  println!("\n\nExample 2: Converting to full Response");
  println!("=======================================\n");

  let response_bytes = create_mock_response();
  let cursor = Cursor::new(response_bytes);
  let reader = BufReader::new(cursor);
  let config = ResponseConfig::default();

  let builder = ResponseBuilder::new(reader, config);
  let streaming = builder.build_streaming().await?;

  // Check status before reading body
  if streaming.status_code().is_success() {
    println!("Status is success, reading full body...");
    let (response, _socket) = streaming.finish().await?;
    println!("Body: {:?}", response.body());
  } else {
    println!("Non-success status, skipping body read");
  }

  println!("\n✓ Example completed successfully");
  Ok(())
}
