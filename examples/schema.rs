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
  Ok(())
}
