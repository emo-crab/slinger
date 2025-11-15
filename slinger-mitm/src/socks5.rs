//! SOCKS5 server implementation for MITM proxy

use crate::error::{Error, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const SOCKS5_VERSION: u8 = 0x05;
const SOCKS5_NO_AUTHENTICATION: u8 = 0x00;
const SOCKS5_NO_ACCEPTABLE_METHODS: u8 = 0xFF;

const SOCKS5_CMD_CONNECT: u8 = 0x01;

const SOCKS5_ATYP_IPV4: u8 = 0x01;
const SOCKS5_ATYP_DOMAIN: u8 = 0x03;
const SOCKS5_ATYP_IPV6: u8 = 0x04;

const SOCKS5_REP_SUCCESS: u8 = 0x00;
const SOCKS5_REP_COMMAND_NOT_SUPPORTED: u8 = 0x07;
const SOCKS5_REP_ADDRESS_TYPE_NOT_SUPPORTED: u8 = 0x08;

/// SOCKS5 target address
#[derive(Debug, Clone)]
pub enum TargetAddr {
  /// IPv4 address
  Ipv4([u8; 4], u16),
  /// IPv6 address
  Ipv6([u8; 16], u16),
  /// Domain name
  Domain(String, u16),
}

impl TargetAddr {
  /// Get host and port as string
  pub fn to_host_port(&self) -> String {
    match self {
      TargetAddr::Ipv4(ip, port) => {
        format!("{}.{}.{}.{}:{}", ip[0], ip[1], ip[2], ip[3], port)
      }
      TargetAddr::Ipv6(ip, port) => {
        // Group bytes into 16-bit segments
        let segments: Vec<u16> = (0..8)
          .map(|i| u16::from_be_bytes([ip[i * 2], ip[i * 2 + 1]]))
          .collect();
        format!(
          "[{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}]:{}",
          segments[0],
          segments[1],
          segments[2],
          segments[3],
          segments[4],
          segments[5],
          segments[6],
          segments[7],
          port
        )
      }
      TargetAddr::Domain(domain, port) => format!("{}:{}", domain, port),
    }
  }

  /// Get host (without port)
  pub fn host(&self) -> String {
    match self {
      TargetAddr::Ipv4(ip, _) => format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]),
      TargetAddr::Ipv6(ip, _) => {
        // Group bytes into 16-bit segments
        let segments: Vec<u16> = (0..8)
          .map(|i| u16::from_be_bytes([ip[i * 2], ip[i * 2 + 1]]))
          .collect();
        format!(
          "{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
          segments[0],
          segments[1],
          segments[2],
          segments[3],
          segments[4],
          segments[5],
          segments[6],
          segments[7]
        )
      }
      TargetAddr::Domain(domain, _) => domain.clone(),
    }
  }

  /// Get port
  pub fn port(&self) -> u16 {
    match self {
      TargetAddr::Ipv4(_, port) | TargetAddr::Ipv6(_, port) | TargetAddr::Domain(_, port) => *port,
    }
  }
}

/// SOCKS5 server for MITM proxy
pub struct Socks5Server;

impl Socks5Server {
  /// Handle SOCKS5 client connection
  /// Returns the target address if successful
  pub async fn handle_handshake(stream: &mut TcpStream) -> Result<TargetAddr> {
    // Read version and methods
    let mut buf = [0u8; 2];
    stream.read_exact(&mut buf).await?;

    let version = buf[0];
    let nmethods = buf[1];

    if version != SOCKS5_VERSION {
      return Err(Error::proxy_error(format!(
        "Unsupported SOCKS version: {}",
        version
      )));
    }

    Self::handle_handshake_internal(stream, nmethods).await
  }

  /// Handle SOCKS5 client connection when version byte has already been read
  /// Returns the target address if successful
  pub async fn handle_handshake_with_version(stream: &mut TcpStream) -> Result<TargetAddr> {
    // Version byte (0x05) was already read, now read nmethods
    let mut buf = [0u8; 1];
    stream.read_exact(&mut buf).await?;
    let nmethods = buf[0];

    Self::handle_handshake_internal(stream, nmethods).await
  }

  /// Internal handshake processing after version check
  async fn handle_handshake_internal(stream: &mut TcpStream, nmethods: u8) -> Result<TargetAddr> {
    // Read methods
    let mut methods = vec![0u8; nmethods as usize];
    stream.read_exact(&mut methods).await?;

    // For now, we only support no authentication
    // Check if client supports no auth
    let selected_method = if methods.contains(&SOCKS5_NO_AUTHENTICATION) {
      SOCKS5_NO_AUTHENTICATION
    } else {
      SOCKS5_NO_ACCEPTABLE_METHODS
    };

    // Send method selection response
    let response = [SOCKS5_VERSION, selected_method];
    stream.write_all(&response).await?;

    if selected_method == SOCKS5_NO_ACCEPTABLE_METHODS {
      return Err(Error::proxy_error(
        "No acceptable authentication method".to_string(),
      ));
    }

    // Read connection request
    let mut buf = [0u8; 4];
    stream.read_exact(&mut buf).await?;

    let version = buf[0];
    let cmd = buf[1];
    // buf[2] is reserved
    let atyp = buf[3];

    if version != SOCKS5_VERSION {
      return Err(Error::proxy_error(format!(
        "Invalid SOCKS version in request: {}",
        version
      )));
    }

    // Only support CONNECT command
    if cmd != SOCKS5_CMD_CONNECT {
      Self::send_reply(stream, SOCKS5_REP_COMMAND_NOT_SUPPORTED).await?;
      return Err(Error::proxy_error(format!("Unsupported command: {}", cmd)));
    }

    // Read target address
    let target_addr = match atyp {
      SOCKS5_ATYP_IPV4 => {
        let mut addr = [0u8; 4];
        stream.read_exact(&mut addr).await?;
        let mut port_buf = [0u8; 2];
        stream.read_exact(&mut port_buf).await?;
        let port = u16::from_be_bytes(port_buf);
        TargetAddr::Ipv4(addr, port)
      }
      SOCKS5_ATYP_IPV6 => {
        let mut addr = [0u8; 16];
        stream.read_exact(&mut addr).await?;
        let mut port_buf = [0u8; 2];
        stream.read_exact(&mut port_buf).await?;
        let port = u16::from_be_bytes(port_buf);
        TargetAddr::Ipv6(addr, port)
      }
      SOCKS5_ATYP_DOMAIN => {
        let mut len_buf = [0u8; 1];
        stream.read_exact(&mut len_buf).await?;
        let len = len_buf[0] as usize;
        let mut domain = vec![0u8; len];
        stream.read_exact(&mut domain).await?;
        let mut port_buf = [0u8; 2];
        stream.read_exact(&mut port_buf).await?;
        let port = u16::from_be_bytes(port_buf);
        let domain_str = String::from_utf8(domain)
          .map_err(|_| Error::proxy_error("Invalid domain name".to_string()))?;
        TargetAddr::Domain(domain_str, port)
      }
      _ => {
        Self::send_reply(stream, SOCKS5_REP_ADDRESS_TYPE_NOT_SUPPORTED).await?;
        return Err(Error::proxy_error(format!(
          "Unsupported address type: {}",
          atyp
        )));
      }
    };

    // Send success reply
    Self::send_reply(stream, SOCKS5_REP_SUCCESS).await?;

    Ok(target_addr)
  }

  /// Send SOCKS5 reply
  async fn send_reply(stream: &mut TcpStream, reply_code: u8) -> Result<()> {
    // Reply format: [VER, REP, RSV, ATYP, BND.ADDR, BND.PORT]
    // We'll use a simple IPv4 address 0.0.0.0:0 as the bound address
    let response = [
      SOCKS5_VERSION,
      reply_code,
      0x00, // Reserved
      SOCKS5_ATYP_IPV4,
      0x00,
      0x00,
      0x00,
      0x00, // Bind address (0.0.0.0)
      0x00,
      0x00, // Bind port (0)
    ];
    stream.write_all(&response).await?;
    Ok(())
  }
}
