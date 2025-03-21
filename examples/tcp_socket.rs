use std::net::{IpAddr, Ipv4Addr, SocketAddr};

#[tokio::main]
async fn main() {
  ssh().await;
  redis().await;
}

async fn ssh() {
  let add = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 22);
  let mut socket = slinger::Connector::default()
    .connect_with_addr(add)
    .await
    .unwrap();
  socket.write_all(b"\r\n").await.unwrap();
  socket.flush().await.unwrap();
  let mut buf = [0u8; 1];
  let mut full = Vec::new();
  while let Ok(size) = socket.read(&mut buf).await {
    if size == 0 {
      break;
    }
    full.extend(buf);
  }
  println!("{:?}", String::from_utf8_lossy(&full));
  socket.shutdown().await.unwrap();
}

async fn redis() {
  let add = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 6379);
  let mut socket = slinger::Connector::default()
    .connect_with_addr(add)
    .await
    .unwrap();
  socket.write_all(b"*1\r\n$4\r\ninfo\r\n").await.unwrap();
  socket.flush().await.unwrap();
  let mut buf = [0u8; 1];
  let mut full = Vec::new();
  while let Ok(size) = socket.read(&mut buf).await {
    if size == 0 {
      break;
    }
    full.extend(buf);
  }
  println!("{:?}", String::from_utf8_lossy(&full));
  socket.shutdown().await.unwrap();
}
