use http::HeaderValue;
use slinger::{ClientBuilder, Request};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
  let client = ClientBuilder::new()
    .user_agent(HeaderValue::from_static(
      "Mozilla/5.0 (X11; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0",
    ))
    .build()
    .unwrap();
  let resp = slinger::get("http://httpbin.org/get").await?;
  println!("{:?}", resp.body());
  let resp = client
    .post("http://httpbin.org/post")
    .body(b"test".to_vec())
    .send()
    .await?;
  println!("{:?}", resp.text());
  let req = Request::builder()
    .uri("http://httpbin.org/head")
    .method("HEAD")
    .header("pragma", "akamai-x-cache-on")
    .body(None)
    .unwrap();
  let resp = client.execute(req).await.unwrap();
  println!("{:?}", resp);
  Ok(())
}
