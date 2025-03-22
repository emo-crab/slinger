use futures::stream::FuturesUnordered;
use futures::StreamExt;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
  use slinger::ClientBuilder;
  let client = ClientBuilder::new().build().unwrap();
  let mut worker = FuturesUnordered::new();
  let start = std::time::Instant::now();
  let t = vec![1, 2, 3, 4, 5, 6, 7, 8, 9];
  for n in t {
    worker.push(client.get(format!("http://httpbin.org/delay/{}", n)).send());
  }
  while let Some(resp) = worker.next().await {
    println!("{}", resp?.text()?);
  }
  println!("{:?}", std::time::Instant::now() - start);
  Ok(())
}
