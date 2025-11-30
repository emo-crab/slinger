use slinger::{Body, ConnectorBuilder};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

#[tokio::main]
async fn main() {
  rdp().await;
  ssh().await;
  redis().await;
}
async fn rdp() {
  let add = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 3389);
  let data =
    b"\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x0b\x00\x00\x00".to_vec();
  let connector = ConnectorBuilder::default()
    .read_timeout(Some(std::time::Duration::from_secs(3)))
    .build()
    .unwrap();
  let mut socket = connector.connect_with_addr(add).await.unwrap();
  socket.write_all(&data).await.unwrap_or_default();
  socket.flush().await.unwrap_or_default();
  let mut buf = [0u8; 1];
  let mut full = Vec::new();
  while let Ok(size) = socket.read(&mut buf).await {
    if size == 0 {
      break;
    }
    full.extend(buf);
  }
  println!("{:?}", Body::from(full));
}
async fn ssh() {
  let add = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 22);
  let connector = ConnectorBuilder::default()
    .read_timeout(Some(std::time::Duration::from_secs(3)))
    .build()
    .unwrap();
  let mut socket = connector.connect_with_addr(add).await.unwrap();
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
