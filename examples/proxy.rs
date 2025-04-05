use slinger::ClientBuilder;

// set your proxy on BurpSuite
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
  let socks5_proxy = slinger::Proxy::parse("socks5://127.0.0.1:7897").unwrap();
  let client = ClientBuilder::new().proxy(socks5_proxy).build().unwrap();
  let resp = client.get("https://httpbin.org/get").send().await?;
  println!("{:?}", resp.text());
  let http_proxy = slinger::Proxy::parse("http://127.0.0.1:7897").unwrap();
  let client = ClientBuilder::new().proxy(http_proxy).build().unwrap();
  let resp = client.get("https://httpbin.org/get").send().await?;
  println!("{:?}", resp.text());
  Ok(())
}
