use slinger::{ClientBuilder, HTTPRecord};

fn main() -> Result<(), Box<dyn std::error::Error>> {
  let redirect = slinger::redirect::Policy::Limit(3);
  let client = ClientBuilder::new().redirect(redirect).build().unwrap();
  let resp = client.get("https://httpbin.org/redirect/10").send()?;
  let record = resp.extensions().get::<Vec<HTTPRecord>>().unwrap();
  println!("{:?}", record.len());
  Ok(())
}
