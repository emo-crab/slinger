#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
  #[cfg(feature = "cookie")]
  {
    use slinger::ClientBuilder;
    let client = ClientBuilder::new().cookie_store(true).build().unwrap();
    let resp = client
      .get("https://httpbin.org/cookies/set/key/value")
      .send()
      .await?;
    println!("{:?}", resp.text());
    let record = resp.http_record().unwrap();
    println!("{:?}", record.len());
  }
  Ok(())
}
