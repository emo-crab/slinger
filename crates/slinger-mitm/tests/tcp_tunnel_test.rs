//! Test TCP tunneling through MITM proxy

use slinger_mitm::{Interceptor, MitmConfig, MitmProxy, MitmRequest, MitmResponse, Result};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

struct PassthroughInterceptor;

#[async_trait::async_trait]
impl Interceptor for PassthroughInterceptor {
    async fn intercept_request(&self, request: MitmRequest) -> Result<Option<MitmRequest>> {
        Ok(Some(request))
    }
    async fn intercept_response(&self, response: MitmResponse) -> Result<Option<MitmResponse>> {
        Ok(Some(response))
    }
}

#[tokio::test]
async fn test_tcp_tunnel_with_interception() {
    // Start a mock server that sends "HELLO\n" immediately on connection
    let mock_server = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mock_addr = mock_server.local_addr().unwrap();
    
    tokio::spawn(async move {
        if let Ok((mut conn, _)) = mock_server.accept().await {
            conn.write_all(b"HELLO FROM SERVER\n").await.unwrap();
            // Keep connection open for a bit
            tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
        }
    });
    
    // Start MITM proxy with a passthrough interceptor
    let config = MitmConfig {
        ca_storage_path: std::path::PathBuf::from("/tmp/test-mitm-ca-tcp"),
        max_connections: 100,
        connection_timeout: 10,
        interceptor_timeout_secs: 5,
        upstream_proxy: None,
    };
    
    let proxy = MitmProxy::new(config).await.unwrap();
    {
        let handler = proxy.interceptor_handler();
        let mut h = handler.write().await;
        h.add_interceptor(Arc::new(PassthroughInterceptor));
    }
    
    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();
    drop(proxy_listener);
    
    let proxy_addr_str = proxy_addr.to_string();
    tokio::spawn(async move {
        proxy.start(&proxy_addr_str).await.unwrap();
    });
    
    // Small delay to ensure proxy is ready
    tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
    
    // Connect through proxy using HTTP CONNECT
    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    
    // Send CONNECT request
    let connect_req = format!("CONNECT {} HTTP/1.1\r\nHost: {}\r\n\r\n", mock_addr, mock_addr);
    client.write_all(connect_req.as_bytes()).await.unwrap();
    
    // Read the 200 response
    let mut response_buf = [0u8; 256];
    let n = client.read(&mut response_buf).await.unwrap();
    let response = String::from_utf8_lossy(&response_buf[..n]);
    assert!(response.contains("200"), "Expected 200 response, got: {}", response);
    
    // Now read data from the mock server through the tunnel
    let mut data_buf = [0u8; 256];
    match tokio::time::timeout(
        tokio::time::Duration::from_secs(3),
        client.read(&mut data_buf)
    ).await {
        Ok(Ok(n)) => {
            let received = String::from_utf8_lossy(&data_buf[..n]);
            println!("Got {} bytes: {:?}", n, received);
            assert!(received.contains("HELLO"), "Expected HELLO, got: {}", received);
        }
        Ok(Err(e)) => panic!("Error reading: {}", e),
        Err(_) => panic!("TIMEOUT! No data received from server through proxy. TCP tunneling is broken."),
    }
}

/// A minimal HTTP proxy that accepts CONNECT requests and forwards connections.
/// Used to test upstream proxy support.
async fn start_minimal_http_proxy() -> std::net::SocketAddr {
    use tokio::io::AsyncBufReadExt;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut client, _)) = listener.accept().await {
            tokio::spawn(async move {
                // Read CONNECT request line
                let mut buf_reader = tokio::io::BufReader::new(&mut client);
                let mut first_line = String::new();
                buf_reader.read_line(&mut first_line).await.ok();
                // Drain remaining headers until blank line
                loop {
                    let mut line = String::new();
                    let n = buf_reader.read_line(&mut line).await.unwrap_or(0);
                    if n == 0 || line == "\r\n" || line == "\n" {
                        break;
                    }
                }
                drop(buf_reader);

                // Parse target host:port from "CONNECT host:port HTTP/1.1"
                let parts: Vec<&str> = first_line.split_whitespace().collect();
                if parts.len() < 2 || parts[0] != "CONNECT" {
                    return;
                }
                let target = parts[1];

                // Connect to target
                let mut target_conn = match TcpStream::connect(target).await {
                    Ok(t) => t,
                    Err(_) => {
                        client.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await.ok();
                        return;
                    }
                };

                // Send 200 Connection Established
                client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await.ok();

                // Bidirectional copy
                let (mut cr, mut cw) = client.split();
                let (mut tr, mut tw) = target_conn.split();
                tokio::select! {
                    _ = tokio::io::copy(&mut cr, &mut tw) => {}
                    _ = tokio::io::copy(&mut tr, &mut cw) => {}
                }
            });
        }
    });
    addr
}

#[tokio::test]
async fn test_tcp_tunnel_through_upstream_http_proxy() {
    // Start the mock target server (sends data on connection)
    let mock_server = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mock_addr = mock_server.local_addr().unwrap();
    tokio::spawn(async move {
        if let Ok((mut conn, _)) = mock_server.accept().await {
            conn.write_all(b"DATA FROM TARGET\n").await.unwrap();
            tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
        }
    });

    // Start the upstream HTTP proxy
    let upstream_addr = start_minimal_http_proxy().await;
    let upstream_proxy_url = format!("http://{}", upstream_addr);
    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    // Configure MITM proxy to route through the upstream HTTP proxy
    let upstream_proxy = slinger::Proxy::parse(&upstream_proxy_url).unwrap();
    let config = MitmConfig {
        ca_storage_path: std::path::PathBuf::from("/tmp/test-mitm-ca-upstream"),
        max_connections: 100,
        connection_timeout: 10,
        interceptor_timeout_secs: 5,
        upstream_proxy: Some(upstream_proxy),
    };

    let proxy = MitmProxy::new(config).await.unwrap();

    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();
    drop(proxy_listener);

    let proxy_addr_str = proxy_addr.to_string();
    tokio::spawn(async move {
        proxy.start(&proxy_addr_str).await.ok();
    });

    tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;

    // Connect to MITM proxy and send HTTP CONNECT for the mock server
    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    let connect_req = format!("CONNECT {} HTTP/1.1\r\nHost: {}\r\n\r\n", mock_addr, mock_addr);
    client.write_all(connect_req.as_bytes()).await.unwrap();

    // Should get 200
    let mut buf = vec![0u8; 256];
    let n = tokio::time::timeout(tokio::time::Duration::from_secs(3), client.read(&mut buf))
        .await
        .expect("timeout reading 200")
        .expect("error reading 200");
    let response = String::from_utf8_lossy(&buf[..n]);
    assert!(response.contains("200"), "Expected 200, got: {:?}", response);

    // Should receive data from target via upstream proxy chain
    let mut data_buf = vec![0u8; 256];
    match tokio::time::timeout(tokio::time::Duration::from_secs(3), client.read(&mut data_buf)).await {
        Ok(Ok(0)) => panic!("Connection closed before receiving target data"),
        Ok(Ok(n)) => {
            let received = String::from_utf8_lossy(&data_buf[..n]);
            assert!(received.contains("DATA FROM TARGET"), "Got: {:?}", received);
        }
        Ok(Err(e)) => panic!("Error reading: {}", e),
        Err(_) => panic!("TIMEOUT! Data from target not received through upstream proxy chain"),
    }
}
