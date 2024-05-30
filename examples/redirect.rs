use slinger::ClientBuilder;
use slinger::record::HTTPRecord;

fn main() -> Result<(), Box<dyn std::error::Error>> {
  limit(3).unwrap();
  only_same_host().unwrap();
  jump().unwrap();
  Ok(())
}

fn limit(max_redirect: usize) -> Result<(), Box<dyn std::error::Error>> {
  let redirect = slinger::redirect::Policy::Limit(max_redirect);
  let client = ClientBuilder::new().redirect(redirect).build().unwrap();
  let resp = client.get("http://httpbin.org/redirect/10").send()?;
  let record = resp.extensions().get::<Vec<HTTPRecord>>().unwrap();
  assert_eq!(record.len(), 3);
  Ok(())
}

fn jump() -> Result<(), Box<dyn std::error::Error>> {
  let client = ClientBuilder::new().build().unwrap();
  let resp = client.get("http://httpbin.org/redirect-to?url=http://www.example.com/").send()?;
  let record = resp.extensions().get::<Vec<HTTPRecord>>().unwrap();
  println!("{:?}", record);
  assert_eq!(record.len(), 2);
  Ok(())
}

fn only_same_host() -> Result<(), Box<dyn std::error::Error>> {
  let redirect = slinger::redirect::Policy::Custom(slinger::redirect::only_same_host);
  let client = ClientBuilder::new().redirect(redirect).build().unwrap();
  let resp = client.get("http://httpbin.org/redirect-to?url=http://www.example.com/").send()?;
  let record = resp.extensions().get::<Vec<HTTPRecord>>().unwrap();
  println!("{:?}", record);
  assert_eq!(record.len(), 1);
  let redirect_record = resp.redirect_record().unwrap();
  println!("{:?}", redirect_record);
  assert_eq!(redirect_record.next, Some(http::Uri::from_static("http://www.example.com/")));
  Ok(())
}