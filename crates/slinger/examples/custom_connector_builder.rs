//! Example demonstrating how to use a custom ConnectorBuilder with ClientBuilder
//!
//! This example shows how to customize the connector configuration by providing
//! a custom ConnectorBuilder instead of using the default one.

use slinger::{Client, ConnectorBuilder};
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
  println!("Custom ConnectorBuilder Example");
  println!("================================\n");

  // Create a custom ConnectorBuilder with specific settings
  let custom_connector = ConnectorBuilder::default()
    .connect_timeout(Some(Duration::from_secs(5)))
    .read_timeout(Some(Duration::from_secs(15)))
    .write_timeout(Some(Duration::from_secs(15)))
    .nodelay(true);

  println!("Creating client with custom connector builder...");

  // Build a client using the custom connector builder
  let _client = Client::builder()
    .connector_builder(custom_connector)
    .keepalive(true)
    .build()?;

  println!("✓ Client created successfully with custom connector configuration");

  println!("\nThis demonstrates:");
  println!("1. Creating a custom ConnectorBuilder with specific timeouts");
  println!("2. Using .connector_builder() to set the custom connector");
  println!("3. Building the client with both custom connector and client settings");

  println!("\nNote: When using a custom ConnectorBuilder, you have full control");
  println!("over the connector configuration, including timeouts, TCP settings,");
  println!("and TLS options (when the tls feature is enabled).");

  // For demonstration, we won't make an actual HTTP request
  // In a real scenario, you would use the client like this:
  // let response = client.get("http://httpbin.org/get").send().await?;
  // println!("Response status: {}", response.status_code());

  Ok(())
}
