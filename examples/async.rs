use futures::stream::FuturesUnordered;
use futures::StreamExt;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
  use slinger::ClientBuilder;
  let client = ClientBuilder::default().build().unwrap();
  let mut worker = FuturesUnordered::new();
  let start = std::time::Instant::now();
  let mut t = vec![1, 2, 3, 4, 5, 6, 7, 8, 9].into_iter();
  for _ in 0..5 {
    if let Some(n) = t.next() {
      worker.push(client.get(format!("http://httpbin.org/delay/{}", n)).send());
    }
  }
  while let Some(resp) = worker.next().await {
    println!("{}", resp?.text()?);
    if let Some(n) = t.next() {
      worker.push(client.get(format!("http://httpbin.org/delay/{}", n)).send());
    }
  }
  println!("{:?}", std::time::Instant::now() - start);
  Ok(())
}
