# Slinger MITM

A Man-in-the-Middle (MITM) proxy library with transparent HTTPS traffic interception using rustls backend, similar to Burp Suite.

## Features

- **Automatic CA Certificate Generation** - Automatically generates and manages root CA certificates
- **Transparent HTTPS Interception** - Intercepts HTTPS traffic using rustls backend  
- **Traffic Modification Interface** - Provides interfaces to intercept and modify HTTP/HTTPS requests and responses
- **Built on Slinger** - Reuses the robust Socket implementation from the slinger HTTP client
- **Multi-Protocol Support** - Supports both HTTP proxy and SOCKS5 protocols on the same port
- **Automatic Protocol Detection** - Automatically detects and handles HTTP or SOCKS5 connections
- **Minimal Dependencies** - Uses only essential libraries to keep the footprint small
- **High Performance** - Certificate caching and optimized certificate generation
- **Clock Skew Handling** - Built-in NOT_BEFORE_OFFSET to handle client clock differences
- **Unique Certificate Serial Numbers** - Each generated certificate has a unique random serial number

### CA Certificate Generation

The MITM proxy uses an advanced certificate generation approach inspired by [hudsucker](https://github.com/omjadas/hudsucker):

- **Issuer Pattern**: Uses rcgen 0.14's `Issuer` for clean separation between root CA and server certificates
- **Certificate Caching**: Generated server certificates are cached using moka for improved performance
- **Random Serial Numbers**: Each certificate gets a unique random serial number to avoid conflicts
- **Clock Skew Tolerance**: NOT_BEFORE_OFFSET of 60 seconds handles client clock differences
- **Long Validity**: CA certificates valid for 10 years, server certificates for 1 year

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
slinger-mitm = { path = "../slinger-mitm" }
tokio = { version = "1", features = ["full"] }
```

## Quick Start

### Basic Proxy

```rust
use slinger_mitm::{MitmConfig, MitmProxy, Interceptor};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create proxy with default configuration
    let config = MitmConfig::default();
    let proxy = MitmProxy::new(config).await?;

    // Add logging interceptor
    let interceptor_handler = proxy.interceptor_handler();
    let mut handler = interceptor_handler.write().await;
    handler.add_request_interceptor(Arc::new(Interceptor::logging()));
    handler.add_response_interceptor(Arc::new(Interceptor::logging()));
    drop(handler);

    // Start the proxy
    proxy.start("127.0.0.1:8080").await?;
    Ok(())
}
```

### Custom Interceptors

```rust
use async_trait::async_trait;
use bytes::Bytes;
use http::{Request, Response, HeaderValue};
use slinger_mitm::{RequestInterceptor, ResponseInterceptor, Result};

struct CustomInterceptor;

#[async_trait]
impl RequestInterceptor for CustomInterceptor {
    async fn intercept_request(&self, mut request: Request<Bytes>) -> Result<Option<Request<Bytes>>> {
        // Modify request headers
        request.headers_mut().insert(
            "X-Custom-Header",
            HeaderValue::from_static("value"),
        );
        Ok(Some(request))
    }
}

#[async_trait]
impl ResponseInterceptor for CustomInterceptor {
    async fn intercept_response(&self, mut response: Response<Bytes>) -> Result<Option<Response<Bytes>>> {
        // Modify response
        response.headers_mut().insert(
            "X-Modified",
            HeaderValue::from_static("true"),
        );
        Ok(Some(response))
    }
}
```

## Usage

### 1. Start the Proxy

Run your proxy application:

```bash
cargo run --example simple_proxy
```

### 2. Install CA Certificate

The proxy will automatically generate a CA certificate at `.slinger-mitm/ca_cert.pem`.

**For Firefox:**
1. Go to Settings → Privacy & Security → Certificates → View Certificates
2. Click "Import" and select the CA certificate
3. Trust it for identifying websites

**For Chrome/System:**
- **Linux:** Copy to `/usr/local/share/ca-certificates/` and run `sudo update-ca-certificates`
- **macOS:** Add to Keychain Access and trust it
- **Windows:** Double-click the certificate and install it to "Trusted Root Certification Authorities"

### 3. Configure Browser/Client Proxy

The MITM proxy supports both HTTP and SOCKS5 protocols:

**HTTP Proxy Mode:**
Set your browser to use HTTP proxy at `127.0.0.1:8080` (or whatever port you configured).

**SOCKS5 Proxy Mode:**
Set your browser/application to use SOCKS5 proxy at `127.0.0.1:8080`. The proxy automatically detects the protocol and handles both HTTP and SOCKS5 connections on the same port.

**Protocol Support:**
- HTTP proxy (CONNECT method for HTTPS)
- SOCKS5 protocol
- Automatic protocol detection based on connection handshake
- Support for non-HTTP protocols through SOCKS5 tunneling

## Configuration

```rust
use slinger_mitm::MitmConfig;
use std::path::PathBuf;

let config = MitmConfig {
    // Directory to store CA certificates
    ca_storage_path: PathBuf::from(".slinger-mitm"),
    
    // Enable HTTPS interception (requires CA cert installation)
    enable_https_interception: true,
    
    // Maximum concurrent connections
    max_connections: 1000,
    
    // Connection timeout in seconds
    connection_timeout: 30,
    
    // Optional upstream proxy (supports HTTP, HTTPS, SOCKS5, SOCKS5h)
    // Example: Some(slinger::Proxy::parse("socks5h://127.0.0.1:1080")?)
    upstream_proxy: None,
};
```

### Upstream Proxy Support

You can configure slinger-mitm to forward all traffic through an upstream proxy. This is useful for:
- Chaining with other proxies (like Tor, Burp Suite, or corporate proxies)
- Using remote DNS resolution with SOCKS5h
- Adding authentication to upstream proxies

```rust
use slinger_mitm::MitmConfig;

// Configure with SOCKS5h proxy (remote DNS resolution)
let proxy = slinger::Proxy::parse("socks5h://127.0.0.1:9050")?;
let config = MitmConfig {
    upstream_proxy: Some(proxy),
    ..Default::default()
};

// Supported proxy types:
// - HTTP: "http://proxy.example.com:8080"
// - HTTPS: "https://proxy.example.com:8443"
// - SOCKS5: "socks5://127.0.0.1:1080"
// - SOCKS5h: "socks5h://127.0.0.1:1080" (with remote DNS)
// - With auth: "socks5h://user:pass@127.0.0.1:1080"
```


## Architecture

```
Client → MITM Proxy → Target Server
           ↓
    Request Interceptor
           ↓
    Slinger HTTP Client
           ↓
    Response Interceptor
           ↓
        Client
```

The proxy works by:
1. Accepting client connections
2. For HTTPS: Generating on-the-fly certificates signed by the root CA
3. Establishing TLS connection with client using the generated certificate
4. Parsing the HTTP request
5. Running it through request interceptors
6. Forwarding to the target server using slinger client
7. Running the response through response interceptors
8. Sending the modified response back to the client

## Examples

See the `examples/` directory for more examples:

- `simple_proxy.rs` - Basic logging proxy
- `custom_interceptor.rs` - Custom request/response modification
- `proxy_chain.rs` - MITM proxy with upstream proxy support (SOCKS5h, HTTP, etc.)

Run an example:

```bash
cargo run --example simple_proxy
cargo run --example proxy_chain
```

## Security Note

WARNING: This is a MITM proxy tool designed for security testing and debugging. Only use it on networks and systems you have permission to test. Installing the CA certificate allows the proxy to decrypt all HTTPS traffic, so protect it accordingly.

## License

GPL-3.0-only

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
