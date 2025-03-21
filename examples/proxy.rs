use slinger::ClientBuilder;

// set your proxy on BurpSuite
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
  let proxy = slinger::Proxy::parse("http://127.0.0.1:8080").unwrap();
  let client = ClientBuilder::new().proxy(proxy).build().unwrap();
  let resp = client.get("https://httpbin.org/get").send().await?;
  println!("{:?}", resp.text());
  Ok(())
}
