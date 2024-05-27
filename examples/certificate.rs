fn main() -> Result<(), Box<dyn std::error::Error>> {
  #[cfg(feature = "tls")]
  {
    use openssl::x509::X509;
    use slinger::ClientBuilder;
    let client = ClientBuilder::new().build().unwrap();
    let resp = client.get("https://httpbin.org/get").send()?;
    let certificate = resp.extensions().get::<X509>().unwrap();
    println!("{:?}", certificate);
  }
  Ok(())
}
