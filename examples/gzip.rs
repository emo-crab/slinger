#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
  #[cfg(feature = "gzip")]
  {
    use slinger::ClientBuilder;
    let client = ClientBuilder::new().build().unwrap();
    let resp = client.get("http://httpbin.org/gzip").send().await?;
    println!("{:?}", resp.text());
  }
  Ok(())
}
