//! Integration tests for slinger-mitm

use slinger_mitm::{CertificateManager, MitmConfig, MitmProxy};

#[tokio::test]
async fn test_ca_generation() {
  let temp_dir = std::env::temp_dir().join("slinger-mitm-test-ca");

  // Clean up if exists
  if temp_dir.exists() {
    std::fs::remove_dir_all(&temp_dir).ok();
  }

  let manager = CertificateManager::new(&temp_dir).await;
  assert!(manager.is_ok(), "Failed to create certificate manager");

  let manager = manager.unwrap();

  // Verify CA cert PEM can be retrieved
  let ca_pem = manager.ca_cert_pem();
  assert!(ca_pem.is_ok(), "Failed to get CA certificate PEM");

  let pem_content = ca_pem.unwrap();
  assert!(
    pem_content.contains("BEGIN CERTIFICATE"),
    "Invalid PEM format"
  );
  assert!(
    pem_content.contains("END CERTIFICATE"),
    "Invalid PEM format"
  );

  // Verify CA cert file exists
  let ca_path = manager.ca_cert_path();
  assert!(ca_path.exists(), "CA certificate file not created");

  // Clean up
  std::fs::remove_dir_all(&temp_dir).ok();
}

#[tokio::test]
async fn test_server_cert_generation() {
  let temp_dir = std::env::temp_dir().join("slinger-mitm-test-server");

  // Clean up if exists
  if temp_dir.exists() {
    std::fs::remove_dir_all(&temp_dir).ok();
  }

  let manager = CertificateManager::new(&temp_dir).await;
  assert!(manager.is_ok(), "Failed to create certificate manager");

  let manager = manager.unwrap();

  // Generate server certificate
  let result = manager.get_server_cert("example.com").await;
  assert!(result.is_ok(), "Failed to generate server certificate");

  let (cert_chain, _key) = result.unwrap();
  assert!(!cert_chain.is_empty(), "Certificate chain is empty");
  assert_eq!(
    cert_chain.len(),
    2,
    "Expected 2 certificates in chain (server + CA)"
  );

  // Clean up
  std::fs::remove_dir_all(&temp_dir).ok();
}

#[tokio::test]
async fn test_server_cert_caching_and_tls_config() {
  use tokio_rustls::rustls::ServerConfig;

  let temp_dir = std::env::temp_dir().join("slinger-mitm-test-caching");

  // Clean up if exists
  if temp_dir.exists() {
    std::fs::remove_dir_all(&temp_dir).ok();
  }

  let manager = CertificateManager::new(&temp_dir).await;
  assert!(manager.is_ok(), "Failed to create certificate manager");

  let manager = manager.unwrap();

  // First request - generates and caches certificate
  let result1 = manager.get_server_cert("test.example.com").await;
  assert!(
    result1.is_ok(),
    "Failed to generate server certificate (first request)"
  );

  let (cert_chain1, key1) = result1.unwrap();

  // Verify TLS config can be created from first request
  let config1 = ServerConfig::builder()
    .with_no_client_auth()
    .with_single_cert(cert_chain1.clone(), key1);
  if let Err(e) = &config1 {
    eprintln!("Error creating TLS config from first request: {:?}", e);
  }
  assert!(
    config1.is_ok(),
    "Failed to create TLS config from first request: {:?}",
    config1.err()
  );

  // Second request - should retrieve from cache
  let result2 = manager.get_server_cert("test.example.com").await;
  assert!(
    result2.is_ok(),
    "Failed to get cached server certificate (second request)"
  );

  let (cert_chain2, key2) = result2.unwrap();

  // Verify TLS config can be created from cached certificate
  // This is where the KeyMismatch error would occur if caching is broken
  let config2 = ServerConfig::builder()
    .with_no_client_auth()
    .with_single_cert(cert_chain2.clone(), key2);
  assert!(
    config2.is_ok(),
    "Failed to create TLS config from cached certificate - KeyMismatch error!"
  );

  // Third request - verify cache still works
  let result3 = manager.get_server_cert("test.example.com").await;
  assert!(
    result3.is_ok(),
    "Failed to get cached server certificate (third request)"
  );

  let (cert_chain3, key3) = result3.unwrap();

  // Verify TLS config works on third request too
  let config3 = ServerConfig::builder()
    .with_no_client_auth()
    .with_single_cert(cert_chain3, key3);
  assert!(
    config3.is_ok(),
    "Failed to create TLS config from cached certificate (third request)"
  );

  // Clean up
  std::fs::remove_dir_all(&temp_dir).ok();
}

#[tokio::test]
async fn test_mitm_proxy_creation() {
  let config = MitmConfig {
    ca_storage_path: std::env::temp_dir().join("slinger-mitm-test-proxy"),
    enable_https_interception: true,
    enable_tcp_interception: false,
    max_connections: 100,
    connection_timeout: 10,
    upstream_proxy: None,
  };

  // Clean up if exists
  if config.ca_storage_path.exists() {
    std::fs::remove_dir_all(&config.ca_storage_path).ok();
  }

  let proxy = MitmProxy::new(config.clone()).await;
  assert!(proxy.is_ok(), "Failed to create MITM proxy");

  let proxy = proxy.unwrap();

  // Verify CA certificate is accessible
  let ca_pem = proxy.ca_cert_pem();
  assert!(ca_pem.is_ok(), "Failed to get CA certificate from proxy");

  // Verify CA path
  let ca_path = proxy.ca_cert_path();
  assert!(ca_path.exists(), "CA certificate file not found");

  // Clean up
  std::fs::remove_dir_all(&config.ca_storage_path).ok();
}

#[tokio::test]
async fn test_interceptor_handler() {
  use slinger_mitm::{Interceptor, InterceptorHandler, MitmRequest};
  use std::sync::Arc;

  let mut handler = InterceptorHandler::new();

  // Add interceptors
  handler.add_request_interceptor(Arc::new(Interceptor::logging()));
  handler.add_response_interceptor(Arc::new(Interceptor::logging()));

  // Test with a simple HTTP request
  use bytes::Bytes;

  let http_request = http::Request::builder()
    .method("GET")
    .uri("http://example.com")
    .body(Bytes::new())
    .unwrap();

  let request: slinger::Request = http_request.into();
  let mitm_request = MitmRequest::new("example.com:80", request);

  let result = handler.process_request(mitm_request).await;
  assert!(result.is_ok(), "Failed to process request through handler");
  assert!(
    result.unwrap().is_some(),
    "Request was blocked unexpectedly"
  );
}

#[tokio::test]
async fn test_mitm_proxy_with_upstream_proxy() {
  use slinger_mitm::MitmConfig;

  // Test proxy URL parsing
  let proxy_result = slinger::Proxy::parse("socks5h://127.0.0.1:1080");
  assert!(proxy_result.is_ok(), "Failed to parse socks5h proxy URL");

  let config = MitmConfig {
    ca_storage_path: std::env::temp_dir().join("slinger-mitm-test-with-proxy"),
    enable_https_interception: true,
    enable_tcp_interception: false,
    max_connections: 100,
    connection_timeout: 10,
    upstream_proxy: Some(proxy_result.unwrap()),
  };

  // Clean up if exists
  if config.ca_storage_path.exists() {
    std::fs::remove_dir_all(&config.ca_storage_path).ok();
  }

  let proxy = MitmProxy::new(config.clone()).await;
  assert!(
    proxy.is_ok(),
    "Failed to create MITM proxy with upstream proxy"
  );

  // Clean up
  std::fs::remove_dir_all(&config.ca_storage_path).ok();
}

#[tokio::test]
async fn test_various_proxy_types() {
  // Test different proxy types
  let test_cases = [
    ("socks5://127.0.0.1:1080", "socks5"),
    ("socks5h://127.0.0.1:1080", "socks5h"),
    ("http://127.0.0.1:8080", "http"),
    ("https://127.0.0.1:8443", "https"),
  ];

  for (idx, (proxy_url, proxy_type)) in test_cases.iter().enumerate() {
    let proxy_result = slinger::Proxy::parse(*proxy_url);
    assert!(
      proxy_result.is_ok(),
      "Failed to parse proxy URL: {}",
      proxy_url
    );

    let config = MitmConfig {
      ca_storage_path: std::env::temp_dir()
        .join(format!("slinger-mitm-test-{}-{}", proxy_type, idx)),
      upstream_proxy: Some(proxy_result.unwrap()),
      ..Default::default()
    };

    // Clean up if exists
    if config.ca_storage_path.exists() {
      std::fs::remove_dir_all(&config.ca_storage_path).ok();
    }

    let proxy = MitmProxy::new(config.clone()).await;
    assert!(
      proxy.is_ok(),
      "Failed to create MITM proxy with {} proxy",
      proxy_url
    );

    // Clean up
    std::fs::remove_dir_all(&config.ca_storage_path).ok();
  }
}

#[tokio::test]
async fn test_socks5_target_addr() {
  use slinger_mitm::TargetAddr;

  // Test IPv4 address
  let ipv4 = TargetAddr::Ipv4([192, 168, 1, 1], 8080);
  assert_eq!(ipv4.to_host_port(), "192.168.1.1:8080");
  assert_eq!(ipv4.host(), "192.168.1.1");
  assert_eq!(ipv4.port(), 8080);

  // Test IPv6 address (::1 = loopback)
  let ipv6 = TargetAddr::Ipv6([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], 443);
  assert_eq!(ipv6.to_host_port(), "[0:0:0:0:0:0:0:1]:443");
  assert_eq!(ipv6.host(), "0:0:0:0:0:0:0:1");
  assert_eq!(ipv6.port(), 443);

  // Test IPv6 with different values (2001:db8::1)
  let ipv6_2 = TargetAddr::Ipv6(
    [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
    80,
  );
  assert_eq!(ipv6_2.to_host_port(), "[2001:db8:0:0:0:0:0:1]:80");
  assert_eq!(ipv6_2.host(), "2001:db8:0:0:0:0:0:1");

  // Test domain address
  let domain = TargetAddr::Domain("example.com".to_string(), 443);
  assert_eq!(domain.to_host_port(), "example.com:443");
  assert_eq!(domain.host(), "example.com");
  assert_eq!(domain.port(), 443);
}

#[tokio::test]
async fn test_unified_interceptor_handler() {
  use bytes::Bytes;
  use slinger_mitm::{Interceptor, InterceptorHandler, MitmRequest, MitmResponse};
  use std::sync::Arc;

  let mut handler = InterceptorHandler::new();

  // Add interceptors (same interceptors handle both HTTP and TCP)
  handler.add_request_interceptor(Arc::new(Interceptor::logging()));
  handler.add_response_interceptor(Arc::new(Interceptor::logging()));

  // Verify interceptors are registered
  assert!(
    handler.has_interceptors(),
    "Interceptors should be registered"
  );

  // Test with a raw TCP request
  let request = MitmRequest::raw_tcp("example.com:443", Bytes::from("Hello, TCP!"));
  assert_eq!(request.destination(), "example.com:443");
  assert_eq!(request.body().map(|b| b.len()).unwrap_or(0), 11);

  let result = handler.process_request(request).await;
  assert!(
    result.is_ok(),
    "Failed to process TCP request through handler"
  );
  assert!(
    result.unwrap().is_some(),
    "TCP Request was blocked unexpectedly"
  );

  // Test with a raw TCP response
  let response = MitmResponse::raw_tcp("example.com:443", Bytes::from("Hello from server!"));
  assert_eq!(response.source(), "example.com:443");
  assert_eq!(response.body().map(|b| b.len()).unwrap_or(0), 18);

  let result = handler.process_response(response).await;
  assert!(
    result.is_ok(),
    "Failed to process TCP response through handler"
  );
  assert!(
    result.unwrap().is_some(),
    "TCP Response was blocked unexpectedly"
  );
}

#[tokio::test]
async fn test_mitm_request_with_source() {
  use bytes::Bytes;
  use slinger_mitm::MitmRequest;
  use std::net::{IpAddr, Ipv4Addr, SocketAddr};

  let source_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 12345);
  let request =
    MitmRequest::raw_tcp_with_source(source_addr, "target.com:80", Bytes::from("GET / HTTP/1.1"));

  assert_eq!(request.destination(), "target.com:80");
  assert!(request.source().is_some());
  assert_eq!(request.source().unwrap(), source_addr);
  assert_eq!(
    request.body().map(|b| b.as_ref()).unwrap_or(&[]),
    b"GET / HTTP/1.1"
  );
  assert!(request.timestamp() > 0);
}

#[tokio::test]
async fn test_mitm_response_body_modification() {
  use bytes::Bytes;
  use slinger_mitm::MitmResponse;

  let mut response = MitmResponse::raw_tcp("server.com:443", Bytes::from("original data"));
  assert_eq!(
    response.body().map(|b| b.as_ref()).unwrap_or(&[]),
    b"original data"
  );

  // Modify the body
  response.set_body(Bytes::from("modified data"));
  assert_eq!(
    response.body().map(|b| b.as_ref()).unwrap_or(&[]),
    b"modified data"
  );
  assert!(response.timestamp() > 0);
}

#[tokio::test]
async fn test_mitm_request_is_http() {
  use bytes::Bytes;
  use slinger_mitm::MitmRequest;

  // Raw TCP request should not be HTTP
  let tcp_request = MitmRequest::raw_tcp("example.com:443", Bytes::from("raw data"));
  assert!(!tcp_request.is_http(), "Raw TCP request should not be HTTP");

  // HTTP request should be detected
  let http_request = http::Request::builder()
    .method("GET")
    .uri("http://example.com/test")
    .body(Bytes::new())
    .unwrap();
  let request: slinger::Request = http_request.into();
  let mitm_request = MitmRequest::new("example.com:80", request);
  assert!(mitm_request.is_http(), "HTTP request should be detected");
}
