#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
  #[cfg(feature = "schema")]
  {
    use schemars::_private::serde_json;
    use schemars::schema_for;
    use slinger::record::HTTPRecord;
    let schema = schema_for!(HTTPRecord);
    println!("{}", serde_json::to_string_pretty(&schema).unwrap());
  }
  #[cfg(feature = "serde")]
  {
    let response: slinger::Response = slinger::Response::builder()
      .version(slinger::http::Version::HTTP_10)
      .header("Content-Type", "text/ html")
      .body(slinger::Body::from("xxx"))
      .unwrap()
      .into();
    let json = serde_json::to_string_pretty(&response).unwrap();
    println!("{}", json);
    let resp: slinger::Response = serde_json::from_str(&json).unwrap();
    println!("{:?}", resp);
  }
  Ok(())
}
