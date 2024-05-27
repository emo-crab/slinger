use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr};
use std::time::Duration;

fn main() {
  let add = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 22);
  let timeout = Duration::new(3, 0);
  let mut socket = slinger::ConnectorBuilder::default()
    .connect_timeout(Some(timeout))
    .read_timeout(Some(timeout))
    .write_timeout(Some(timeout))
    .build()
    .unwrap()
    .connect_with_addr(add)
    .unwrap();
  socket.write_all(b"\r\n").unwrap();
  socket.flush().unwrap();
  let mut buf = [0u8; 1];
  let mut full = Vec::new();
  while let Ok(size) = socket.read(&mut buf) {
    if size == 0 {
      break;
    }
    full.extend(buf);
  }
  println!("{:?}", String::from_utf8_lossy(&full));
  socket.shutdown(Shutdown::Both).unwrap();
}
