use slinger::{ClientBuilder, HTTPRecord};

fn main() -> Result<(), Box<dyn std::error::Error>> {
  let client = ClientBuilder::new().build().unwrap();
  let resp = client
    .get("https://httpbin.org/redirect-to?url=https%3A%2F%2Fhttpbin.org%2Fget")
    .send()?;
  let record = resp.extensions().get::<Vec<HTTPRecord>>().unwrap();
  println!("{:?}", record.len());
  Ok(())
}
