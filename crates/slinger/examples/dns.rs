//! Example demonstrating custom DNS server resolution.
//!
//! This example shows how to use the `dns` feature to configure custom DNS servers
//! for hostname resolution.
//!
//! Run with:
//! ```
//! cargo run --example dns --features dns
//! ```

#[cfg(feature = "dns")]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
  use slinger::dns::DnsResolver;
  use slinger::Client;
  // Create a DNS resolver with Google's public DNS servers
  let resolver = DnsResolver::new(vec![
    "10.111.13.99:53".parse().unwrap(),
  ])?;

  // Create a client with the custom DNS resolver
  let client = Client::builder().dns_resolver(resolver).build()?;

  // Make a request - the hostname will be resolved using the custom DNS servers
  let resp = client.get("http://httpbin.org/get").send().await?;

  println!("Status: {}", resp.status_code());
  println!("Body: {}", resp.text()?);

  Ok(())
}
#[cfg(not(feature = "dns"))]
fn main() {
  println!("This example requires the 'dns' feature to be enabled.");
}
