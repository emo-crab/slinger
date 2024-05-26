use slinger::ClientBuilder;

fn main() -> Result<(), Box<dyn std::error::Error>> {
  let client = ClientBuilder::new().build().unwrap();
  let resp = client.get("http://httpbin.org/get").send()?;
  println!("{:?}", resp.status_code());
  let resp = client
    .post("http://httpbin.org/post")
    .body(b"test".to_vec())
    .send()?;
  println!("{:?}", resp.text());
  Ok(())
}
