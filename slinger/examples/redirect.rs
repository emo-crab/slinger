use std::str::FromStr;

use slinger::record::HTTPRecord;
use slinger::ClientBuilder;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
  customize().await.unwrap();
  limit(3).await.unwrap();
  only_same_host().await.unwrap();
  jump().await.unwrap();
  Ok(())
}
fn custom(attempt: slinger::redirect::Attempt) -> slinger::redirect::Action {
  let s = attempt
    .response()
    .body()
    .as_ref()
    .unwrap()
    .to_string()
    .trim()
    .to_string();
  if s == *"slinger" {
    let u = http::Uri::from_str(format!("http://httpbin.org/get?{}=awesome", &s).trim()).unwrap();
    slinger::redirect::Action::Follow(u)
  } else {
    slinger::redirect::Action::None
  }
}

async fn customize() -> Result<(), Box<dyn std::error::Error>> {
  let redirect = slinger::redirect::Policy::Custom(custom);
  let client = ClientBuilder::default().redirect(redirect).build().unwrap();
  let resp = client
    .get("http://httpbin.org/base64/c2xpbmdlcgo%3D")
    .send()
    .await?;
  assert!(resp.text().unwrap_or_default().contains("slinger"));
  Ok(())
}
async fn limit(max_redirect: usize) -> Result<(), Box<dyn std::error::Error>> {
  let redirect = slinger::redirect::Policy::Limit(max_redirect);
  let client = ClientBuilder::default().redirect(redirect).build().unwrap();
  let resp = client.get("http://httpbin.org/redirect/10").send().await?;
  let record = resp.extensions().get::<Vec<HTTPRecord>>().unwrap();
  assert_eq!(record.len(), 3);
  Ok(())
}

async fn jump() -> Result<(), Box<dyn std::error::Error>> {
  let client = ClientBuilder::default().build().unwrap();
  let resp = client
    .get("http://httpbin.org/redirect-to?url=http://www.example.com/")
    .send()
    .await?;
  let record = resp.extensions().get::<Vec<HTTPRecord>>().unwrap();
  println!("{:?}", record);
  assert_eq!(record.len(), 2);
  Ok(())
}

async fn only_same_host() -> Result<(), Box<dyn std::error::Error>> {
  let redirect = slinger::redirect::Policy::Custom(slinger::redirect::only_same_host);
  let client = ClientBuilder::default().redirect(redirect).build().unwrap();
  let resp = client
    .get("http://httpbin.org/redirect-to?url=http://www.example.com/")
    .send()
    .await?;
  let record = resp.extensions().get::<Vec<HTTPRecord>>().unwrap();
  println!("{:?}", record);
  assert_eq!(record.len(), 1);
  let redirect_record = resp.redirect_record().unwrap();
  println!("{:?}", redirect_record);
  assert_eq!(
    redirect_record.next,
    Some(http::Uri::from_static("http://www.example.com/"))
  );
  Ok(())
}
