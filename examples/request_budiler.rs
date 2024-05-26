use slinger::ClientBuilder;

fn main() -> Result<(), Box<dyn std::error::Error>> {
  let client = ClientBuilder::new().build().unwrap();
  let resp = client
    .post("https://httpbin.org/post")
    .header("XX", "XX")
    .header_line("X: X")
    .body(b"data".as_slice())
    .send()?;
  println!("{:?}", resp.text());
  Ok(())
}
