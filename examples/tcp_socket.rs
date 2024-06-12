use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr};
use std::time::Duration;

fn main() {
  ssh();
  redis();
}

fn ssh() {
  let add = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 22);
  let timeout = Duration::new(3, 0);
  let mut socket = slinger::Connector::default()
    .connect_with_addr(add)
    .unwrap();
  socket.set_write_timeout(Some(timeout)).unwrap();
  socket.set_read_timeout(Some(timeout)).unwrap();
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

fn redis() {
  let add = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 6379);
  let timeout = Duration::new(3, 0);
  let mut socket = slinger::Connector::default()
    .connect_with_addr(add)
    .unwrap();
  socket.set_write_timeout(Some(timeout)).unwrap();
  socket.set_read_timeout(Some(timeout)).unwrap();
  socket.write_all(b"*1\r\n$4\r\ninfo\r\n").unwrap();
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
