use slinger::{ClientBuilder, Request};

fn main() -> Result<(), Box<dyn std::error::Error>> {
  let client = ClientBuilder::new().build().unwrap();
  let resp = slinger::get("http://httpbin.org/get")?;
  println!("{:?}", resp.body());
  let resp = client
    .post("http://httpbin.org/post")
    .body(b"test".to_vec())
    .send()?;
  println!("{:?}", resp.text());
  let req = Request::builder()
    .uri("http://httpbin.org/head")
    .method("HEAD")
    .header("pragma", "akamai-x-cache-on")
    .body(None)
    .unwrap();
  let resp = client.execute(req).unwrap();
  println!("{:?}", resp);
  Ok(())
}
