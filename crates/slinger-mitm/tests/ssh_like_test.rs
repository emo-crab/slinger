use slinger_mitm::{Interceptor, MitmConfig, MitmProxy, MitmRequest, MitmResponse, Result};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

struct PassthroughInterceptor;

#[async_trait::async_trait]
impl Interceptor for PassthroughInterceptor {
    async fn intercept_request(&self, request: MitmRequest) -> Result<Option<MitmRequest>> {
        eprintln!("[INTERCEPT] Request to: {} (is_http={})", request.destination(), request.is_http());
        Ok(Some(request))
    }
    async fn intercept_response(&self, response: MitmResponse) -> Result<Option<MitmResponse>> {
        eprintln!("[INTERCEPT] Response from: {} (is_http={})", response.source(), response.is_http());
        if let Some(body) = response.body() {
            eprintln!("[INTERCEPT] Body length: {} bytes", body.len());
        }
        Ok(Some(response))
    }
}

#[tokio::test]
async fn test_ssh_like_tcp_tunnel() {
    // Start a mock "SSH" server that IMMEDIATELY sends a banner on connection
    let mock_server = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mock_addr = mock_server.local_addr().unwrap();
    eprintln!("Mock SSH server on {}", mock_addr);

    tokio::spawn(async move {
        if let Ok((mut conn, _)) = mock_server.accept().await {
            eprintln!("[MOCK] Client connected, sending SSH banner immediately");
            conn.write_all(b"SSH-2.0-MockSSH_1.0\r\n").await.unwrap();
            conn.flush().await.unwrap();
            eprintln!("[MOCK] SSH banner sent");
            tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
        }
    });

    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    // Start MITM proxy WITH interceptors (triggers handle_tcp_tunnel_with_interception)
    let config = MitmConfig {
        ca_storage_path: std::path::PathBuf::from("/tmp/test-mitm-ca-ssh"),
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

    let proxy_listener_tmp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener_tmp.local_addr().unwrap();
    drop(proxy_listener_tmp);

    let proxy_addr_str = proxy_addr.to_string();
    tokio::spawn(async move {
        proxy.start(&proxy_addr_str).await.ok();
    });

    tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
    eprintln!("Proxy should be ready on {}", proxy_addr);

    let mut client = TcpStream::connect(proxy_addr).await.expect("Failed to connect to proxy");
    eprintln!("Connected to proxy");

    let connect_req = format!("CONNECT {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: test\r\n\r\n", mock_addr, mock_addr);
    client.write_all(connect_req.as_bytes()).await.unwrap();
    eprintln!("Sent CONNECT request");

    // Read the 200 response
    let mut buf = vec![0u8; 512];
    let n = tokio::time::timeout(
        tokio::time::Duration::from_secs(2),
        client.read(&mut buf)
    ).await.expect("Timeout reading 200 response").expect("Error reading 200 response");

    let response_str = String::from_utf8_lossy(&buf[..n]);
    eprintln!("Got response: {:?}", response_str);
    assert!(response_str.contains("200"), "Expected 200 response, got: {:?}", response_str);

    // Wait for SSH banner (server sends first - no client data needed)
    eprintln!("Waiting for SSH banner through tunnel (server-first protocol)...");
    let mut data_buf = vec![0u8; 256];
    match tokio::time::timeout(
        tokio::time::Duration::from_secs(5),
        client.read(&mut data_buf)
    ).await {
        Ok(Ok(0)) => panic!("Connection closed without sending SSH banner!"),
        Ok(Ok(n)) => {
            let banner = String::from_utf8_lossy(&data_buf[..n]);
            eprintln!("SUCCESS! Got {} bytes: {:?}", n, banner);
            assert!(banner.contains("SSH-2.0"), "Expected SSH banner, got: {:?}", banner);
        }
        Ok(Err(e)) => panic!("Error reading SSH banner: {}", e),
        Err(_) => panic!("TIMEOUT! No SSH banner received through proxy. TCP tunneling is BROKEN!"),
    }

    eprintln!("Test PASSED! SSH-like TCP tunneling through proxy works.");
}
