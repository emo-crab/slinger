//! DNS resolver module using hickory-dns for custom DNS server resolution.
//!
//! This module provides a DNS resolver that can be configured to use custom DNS servers
//! instead of the system's default DNS configuration.
//!
//! # Example
//!
//! ```rust,ignore
//! use slinger::dns::DnsResolver;
//! use std::net::SocketAddr;
//!
//! # async fn example() -> Result<(), slinger::Error> {
//! // Create a resolver with custom DNS servers
//! let resolver = DnsResolver::new(vec![
//!     "8.8.8.8:53".parse().unwrap(),
//!     "8.8.4.4:53".parse().unwrap(),
//! ])?;
//!
//! // Resolve a hostname
//! let addrs = resolver.resolve("example.com", 443).await?;
//! # Ok(())
//! # }
//! ```

use crate::errors::{new_io_error, Result};
use hickory_resolver::config::{NameServerConfig, NameServerConfigGroup, ResolverConfig};
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::proto::xfer::Protocol;
use hickory_resolver::TokioResolver;
use std::net::SocketAddr;
use std::sync::Arc;

/// A DNS resolver that can use custom DNS servers.
///
/// This resolver wraps hickory-dns's async resolver and provides a simple interface
/// for resolving hostnames to IP addresses using custom DNS servers.
#[derive(Clone)]
pub struct DnsResolver {
  inner: Arc<TokioResolver>,
}

impl DnsResolver {
  /// Creates a new DNS resolver with the specified DNS servers.
  ///
  /// # Arguments
  ///
  /// * `dns_servers` - A list of DNS server addresses (e.g., "8.8.8.8:53")
  ///
  /// # Example
  ///
  /// ```rust,ignore
  /// use slinger::dns::DnsResolver;
  /// use std::net::SocketAddr;
  ///
  /// # fn example() -> Result<(), slinger::Error> {
  /// let resolver = DnsResolver::new(vec![
  ///     "8.8.8.8:53".parse().unwrap(),
  /// ])?;
  /// # Ok(())
  /// # }
  /// ```
  pub fn new(dns_servers: Vec<SocketAddr>) -> Result<Self> {
    if dns_servers.is_empty() {
      return Err(new_io_error(
        std::io::ErrorKind::InvalidInput,
        "DNS servers list cannot be empty",
      ));
    }

    let name_servers: Vec<NameServerConfig> = dns_servers
      .into_iter()
      .map(|addr| NameServerConfig::new(addr, Protocol::Udp))
      .collect();

    let name_server_group = NameServerConfigGroup::from(name_servers);
    let config = ResolverConfig::from_parts(None, vec![], name_server_group);

    let resolver = TokioResolver::builder_with_config(config, TokioConnectionProvider::default())
      .build();

    Ok(Self {
      inner: Arc::new(resolver),
    })
  }

  /// Creates a DNS resolver using the system's default configuration.
  ///
  /// # Example
  ///
  /// ```rust,ignore
  /// use slinger::dns::DnsResolver;
  ///
  /// # fn example() -> Result<(), slinger::Error> {
  /// let resolver = DnsResolver::system()?;
  /// # Ok(())
  /// # }
  /// ```
  pub fn system() -> Result<Self> {
    let resolver = TokioResolver::builder_tokio()
      .map_err(|e| new_io_error(std::io::ErrorKind::Other, &e.to_string()))?
      .build();

    Ok(Self {
      inner: Arc::new(resolver),
    })
  }

  /// Resolves a hostname to a list of socket addresses.
  ///
  /// # Arguments
  ///
  /// * `host` - The hostname to resolve
  /// * `port` - The port number to use for the resulting socket addresses
  ///
  /// # Returns
  ///
  /// A vector of socket addresses, or an error if resolution fails.
  pub async fn resolve(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>> {
    let lookup = self
      .inner
      .lookup_ip(host)
      .await
      .map_err(|e| new_io_error(std::io::ErrorKind::Other, &e.to_string()))?;

    let addrs: Vec<SocketAddr> = lookup
      .iter()
      .map(|ip| SocketAddr::new(ip, port))
      .collect();

    if addrs.is_empty() {
      return Err(new_io_error(
        std::io::ErrorKind::NotFound,
        &format!("no addresses found for host: {}", host),
      ));
    }

    Ok(addrs)
  }

  /// Resolves a hostname to the first socket address.
  ///
  /// # Arguments
  ///
  /// * `host` - The hostname to resolve
  /// * `port` - The port number to use for the resulting socket address
  ///
  /// # Returns
  ///
  /// The first resolved socket address, or an error if resolution fails.
  pub async fn resolve_one(&self, host: &str, port: u16) -> Result<SocketAddr> {
    let addrs = self.resolve(host, port).await?;
    // Safe to unwrap because resolve() already checks for empty results
    addrs.first().copied().ok_or_else(|| {
      new_io_error(
        std::io::ErrorKind::NotFound,
        &format!("no addresses found for host: {}", host),
      )
    })
  }
}

impl std::fmt::Debug for DnsResolver {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_struct("DnsResolver").finish()
  }
}
