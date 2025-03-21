use slinger::{ClientBuilder, Request};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
  let client = ClientBuilder::new().build().unwrap();
  let resp = client
    .post("https://httpbin.org/post")
    .header("XX", "XX")
    .header_line("X: X")
    .body(b"data".as_slice())
    .send()
    .await?;
  println!("{:?}", resp.text());
  let u = http::Uri::from_static("https://httpbin.org/post");
  let raw = Request::raw(u, "", true);
  println!("{:?}", raw);
  Ok(())
}
