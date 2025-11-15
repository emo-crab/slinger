use slinger::ClientBuilder;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
  let client = ClientBuilder::default().build().unwrap();
  let resp = client
    .get("https://httpbin.org/redirect-to?url=https%3A%2F%2Fhttpbin.org%2Fget")
    .send()
    .await?;
  println!("{:?}", resp.request());
  let record = resp.http_record().unwrap();
  println!("{:?}", record.len());
  Ok(())
}
