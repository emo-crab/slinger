fn main() -> Result<(), Box<dyn std::error::Error>> {
  #[cfg(feature = "cookie")]
  {
    use slinger::{ClientBuilder, HTTPRecord};
    let client = ClientBuilder::new().cookie_store(true).build().unwrap();
    let resp = client
      .get("https://httpbin.org/cookies/set/key/value")
      .send()?;
    println!("{:?}", resp.text());
    let record = resp.extensions().get::<Vec<HTTPRecord>>().unwrap();
    println!("{:?}", record.len());
  }
  Ok(())
}
