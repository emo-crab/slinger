//! Certificate Authority (CA) management for MITM proxy
//!
//! This module handles automatic generation and management of CA certificates
//! for intercepting HTTPS traffic.
//!

use crate::error::{Error, Result};
use moka::future::Cache;
use rand::Rng;
use rcgen::{
  BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, Issuer, KeyPair,
  KeyUsagePurpose, SanType,
};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use time::{Duration, OffsetDateTime};
use tokio::fs;
use tokio::io::AsyncWriteExt;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};

/// Certificate validity period in seconds (1 year)
const TTL_SECS: i64 = 365 * 24 * 60 * 60;
/// Cache time-to-live in seconds (6 months)
const CACHE_TTL: u64 = (TTL_SECS / 2) as u64;
/// Offset for not_before timestamp to handle clock skew (60 seconds)
const NOT_BEFORE_OFFSET: i64 = 60;

/// Certificate Authority for generating certificates
pub struct CertificateAuthority {
  /// Root CA issuer
  issuer: Issuer<'static, KeyPair>,
  /// Root CA certificate in DER format
  ca_cert_der: CertificateDer<'static>,
  /// Root CA private key
  #[allow(dead_code)]
  ca_key_der: PrivateKeyDer<'static>,
  /// Storage path for certificates
  storage_path: PathBuf,
}

impl CertificateAuthority {
  /// Create a new Certificate Authority
  ///
  /// If a CA already exists at the storage path, it will be loaded.
  /// Otherwise, a new CA will be generated.
  pub async fn new(storage_path: impl AsRef<Path>) -> Result<Self> {
    let storage_path = storage_path.as_ref().to_path_buf();

    // Create storage directory if it doesn't exist
    if !storage_path.exists() {
      fs::create_dir_all(&storage_path).await?;
    }

    let ca_cert_path = storage_path.join("ca_cert.pem");
    let ca_key_path = storage_path.join("ca_key.pem");

    // Check if CA already exists
    let (issuer, ca_cert_der, ca_key_der) = if ca_cert_path.exists() && ca_key_path.exists() {
      Self::load_ca(&ca_cert_path, &ca_key_path).await?
    } else {
      Self::generate_ca(&ca_cert_path, &ca_key_path).await?
    };

    Ok(Self {
      issuer,
      ca_cert_der,
      ca_key_der,
      storage_path,
    })
  }

  /// Load existing CA certificate and key
  async fn load_ca(
    cert_path: &Path,
    key_path: &Path,
  ) -> Result<(
    Issuer<'static, KeyPair>,
    CertificateDer<'static>,
    PrivateKeyDer<'static>,
  )> {
    let cert_pem = fs::read_to_string(cert_path).await?;
    let key_pem = fs::read_to_string(key_path).await?;

    let key_pair = KeyPair::from_pem(&key_pem)
      .map_err(|e| Error::certificate_error(format!("Failed to parse CA key: {}", e)))?;

    let issuer = Issuer::from_ca_cert_pem(&cert_pem, key_pair).map_err(|e| {
      Error::certificate_error(format!("Failed to create issuer from CA cert: {}", e))
    })?;

    // Parse PEM to DER for rustls
    let cert_der = rustls_pemfile::certs(&mut cert_pem.as_bytes())
      .next()
      .ok_or_else(|| Error::certificate_error("No certificate found in PEM"))?
      .map_err(|e| Error::certificate_error(format!("Failed to parse PEM: {}", e)))?;

    let key_der = PrivateKeyDer::try_from(issuer.key().serialize_der())
      .map_err(|_| Error::certificate_error("Failed to serialize CA key"))?;

    Ok((issuer, cert_der, key_der))
  }

  /// Generate a new CA certificate and key
  async fn generate_ca(
    cert_path: &Path,
    key_path: &Path,
  ) -> Result<(
    Issuer<'static, KeyPair>,
    CertificateDer<'static>,
    PrivateKeyDer<'static>,
  )> {
    let mut params = CertificateParams::default();

    // Set up distinguished name
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "Slinger MITM Proxy CA");
    dn.push(DnType::OrganizationName, "Emo-Crab");
    dn.push(DnType::CountryName, "CN");
    dn.push(DnType::LocalityName, "Internet");
    dn.push(DnType::StateOrProvinceName, "World");
    params.distinguished_name = dn;
    // Configure as CA
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];

    // Set validity period (10 years)
    let now = OffsetDateTime::now_utc();
    params.not_before = now;
    params.not_after = now + Duration::days(3650);

    let key_pair = KeyPair::generate()
      .map_err(|e| Error::certificate_error(format!("Failed to generate key pair: {}", e)))?;

    let cert = params
      .self_signed(&key_pair)
      .map_err(|e| Error::certificate_error(format!("Failed to generate CA: {}", e)))?;

    // Serialize and save
    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();

    let mut cert_file = fs::File::create(cert_path).await?;
    cert_file.write_all(cert_pem.as_bytes()).await?;

    let mut key_file = fs::File::create(key_path).await?;
    key_file.write_all(key_pem.as_bytes()).await?;

    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::try_from(key_pair.serialize_der())
      .map_err(|_| Error::certificate_error("Failed to serialize CA key DER"))?;

    // Create issuer from the certificate and key pair
    let issuer = Issuer::from_ca_cert_pem(&cert_pem, key_pair)
      .map_err(|e| Error::certificate_error(format!("Failed to create issuer: {}", e)))?;

    Ok((issuer, cert_der, key_der))
  }

  /// Generate a server certificate signed by this CA
  pub fn generate_server_cert(
    &self,
    domain: &str,
  ) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let mut params = CertificateParams::default();

    // Generate random serial number for uniqueness
    params.serial_number = Some(rand::thread_rng().gen::<u64>().into());

    // Set up distinguished name
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, domain);
    params.distinguished_name = dn;

    // Add subject alternative names
    // If domain parses as an IP literal, include both an IP SAN and a DNS SAN.
    // Some clients strictly check iPAddress in SAN for IP targets while others
    // may check dNSName; including both increases compatibility for local IPs.
    params.subject_alt_names = if let Ok(ip) = domain.parse::<IpAddr>() {
      let mut sans = Vec::new();
      sans.push(SanType::IpAddress(ip));
      // Also add a DNS SAN with the textual IP as fallback (if rcgen accepts it).
      if let Ok(dns_name) = domain.try_into() {
        sans.push(SanType::DnsName(dns_name));
      }
      sans
    } else {
      vec![SanType::DnsName(domain.try_into().map_err(|_| {
        Error::certificate_error(format!("Invalid domain name: {}", domain))
      })?)]
    };

    // Set validity period with clock skew handling
    let now = OffsetDateTime::now_utc();
    params.not_before = now - Duration::seconds(NOT_BEFORE_OFFSET);
    params.not_after = now + Duration::seconds(TTL_SECS);

    let key_pair = KeyPair::generate()
      .map_err(|e| Error::certificate_error(format!("Failed to generate key pair: {}", e)))?;

    let cert = params
      .signed_by(&key_pair, &self.issuer)
      .map_err(|e| Error::certificate_error(format!("Failed to sign server cert: {}", e)))?;

    let cert_der = CertificateDer::from(cert.der().to_vec());

    let key_der = PrivateKeyDer::try_from(key_pair.serialize_der())
      .map_err(|_| Error::certificate_error("Failed to serialize server key"))?;

    // Return chain: [server_cert, ca_cert]
    Ok((vec![cert_der, self.ca_cert_der.clone()], key_der))
  }

  /// Get CA certificate in PEM format for client installation
  pub fn ca_cert_pem(&self) -> Result<String> {
    // Read the saved certificate file
    let ca_cert_path = self.storage_path.join("ca_cert.pem");
    std::fs::read_to_string(&ca_cert_path)
      .map_err(|e| Error::certificate_error(format!("Failed to read CA cert: {}", e)))
  }

  /// Get CA certificate path
  pub fn ca_cert_path(&self) -> PathBuf {
    self.storage_path.join("ca_cert.pem")
  }
}

/// Manager for caching generated server certificates
pub struct CertificateManager {
  ca: CertificateAuthority,
  /// Cache for generated server certificates
  cert_cache: Cache<String, Arc<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)>>,
}

impl CertificateManager {
  /// Create a new certificate manager
  pub async fn new(storage_path: impl AsRef<Path>) -> Result<Self> {
    let ca = CertificateAuthority::new(storage_path).await?;

    // Create cache with TTL matching certificate validity
    let cert_cache = Cache::builder()
      .max_capacity(1000)
      .time_to_live(std::time::Duration::from_secs(CACHE_TTL))
      .build();

    Ok(Self { ca, cert_cache })
  }

  /// Get or generate a server certificate for the given domain
  pub async fn get_server_cert(
    &self,
    domain: &str,
  ) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    // If domain is an IP literal, avoid returning a potentially stale cached
    // certificate that might lack an iPAddress SAN; always generate a fresh
    // certificate containing the IP SAN. For hostnames, use the cache for
    // performance.
    if domain.parse::<std::net::IpAddr>().is_ok() {
      let (cert_chain, key) = self.ca.generate_server_cert(domain)?;
      // Cache the generated cert for future use
      let cached_cert = (cert_chain.clone(), key.clone_key());
      self
        .cert_cache
        .insert(domain.to_string(), Arc::new(cached_cert))
        .await;
      return Ok((cert_chain, key));
    }

    // Try to get from cache for non-IP hostnames
    if let Some(cached) = self.cert_cache.get(domain).await {
      // Clone the certificate chain and key from cache
      let (cert_chain, key) = cached.as_ref();
      return Ok((cert_chain.clone(), key.clone_key()));
    }

    // Generate new certificate
    let (cert_chain, key) = self.ca.generate_server_cert(domain)?;

    // Clone before caching since we need to return the original
    let cached_cert = (cert_chain.clone(), key.clone_key());

    // Store in cache
    self
      .cert_cache
      .insert(domain.to_string(), Arc::new(cached_cert))
      .await;

    Ok((cert_chain, key))
  }

  /// Get the CA certificate in PEM format
  pub fn ca_cert_pem(&self) -> Result<String> {
    self.ca.ca_cert_pem()
  }

  /// Get the CA certificate path
  pub fn ca_cert_path(&self) -> PathBuf {
    self.ca.ca_cert_path()
  }
}
