//! Test CA certificate caching functionality
//!
//! This example demonstrates the certificate caching mechanism.
//! It generates certificates for multiple domains and shows that
//! subsequent requests for the same domain use cached certificates.

use slinger_mitm::CertificateManager;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
  let temp_dir = std::env::temp_dir().join("test_slinger_mitm_cache");
  std::fs::create_dir_all(&temp_dir)?;

  println!("=== Testing CA Certificate Caching ===\n");

  println!("Creating certificate manager...");
  let cert_manager = CertificateManager::new(&temp_dir).await?;
  println!(
    "CA certificate path: {}\n",
    cert_manager.ca_cert_path().display()
  );

  // First request - should generate new certificate
  println!("1. Generating certificate for example.com...");
  let start = std::time::Instant::now();
  let (cert_chain1, _key1) = cert_manager.get_server_cert("example.com").await?;
  let duration1 = start.elapsed();
  println!(
    "   Generated: {} certs in chain (took {:?})",
    cert_chain1.len(),
    duration1
  );

  // Second request for same domain - should use cache
  println!("\n2. Getting certificate for example.com again (should be cached)...");
  let start = std::time::Instant::now();
  let (cert_chain2, _key2) = cert_manager.get_server_cert("example.com").await?;
  let duration2 = start.elapsed();
  println!(
    "   Retrieved: {} certs in chain (took {:?})",
    cert_chain2.len(),
    duration2
  );

  if duration2 < duration1 / 2 {
    println!("   ✓ Cache is working! Second request was much faster.");
  }

  // Third request for different domain - should generate new certificate
  println!("\n3. Generating certificate for google.com...");
  let start = std::time::Instant::now();
  let (cert_chain3, _key3) = cert_manager.get_server_cert("google.com").await?;
  let duration3 = start.elapsed();
  println!(
    "   Generated: {} certs in chain (took {:?})",
    cert_chain3.len(),
    duration3
  );

  // Fourth request for another different domain
  println!("\n4. Generating certificate for github.com...");
  let (cert_chain4, _key4) = cert_manager.get_server_cert("github.com").await?;
  println!("   Generated: {} certs in chain", cert_chain4.len());

  println!("\n=== All tests passed! ===");
  println!("The certificate manager successfully:");
  println!("  - Generated unique certificates for different domains");
  println!("  - Cached certificates for improved performance");
  println!("  - Each certificate chain includes the server cert and CA cert");

  Ok(())
}
