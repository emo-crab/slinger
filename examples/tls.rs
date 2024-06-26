fn main() -> Result<(), Box<dyn std::error::Error>> {
  #[cfg(feature = "tls")]
  {
    use slinger::ClientBuilder;
    let urls = vec![
      "https://expired.badssl.com/",
      "https://wrong.host.badssl.com/",
      "https://self-signed.badssl.com/",
      "https://untrusted-root.badssl.com/",
      "https://revoked.badssl.com/",
      "https://pinning-test.badssl.com/",
      "https://no-common-name.badssl.com/",
      "https://no-subject.badssl.com/",
      "https://incomplete-chain.badssl.com/",
      "https://dh2048.badssl.com/",
      "https://dh-small-subgroup.badssl.com/",
      "https://static-rsa.badssl.com/",
    ];
    let key_urls = vec![
      "https://dh-composite.badssl.com/",
      "https://dh480.badssl.com/",
      "https://dh512.badssl.com/",
      "https://dh1024.badssl.com/",
    ];

    let client = ClientBuilder::new().build().unwrap();
    for url in urls {
      println!("{}", url);
      let resp = client.get(url).send()?;
      println!("{}", resp.text().unwrap_or_default());
      let certificate = resp.certificate().unwrap();
      println!("{:?}", certificate);
    }
    for url in key_urls {
      println!("{}", url);
      let resp = client.get(url).send();
      match resp {
        Ok(resp) => {
          println!("{}", resp.text().unwrap_or_default());
          let certificate = resp.certificate().unwrap();
          println!("{:?}", certificate);
        }
        Err(err) => {
          println!("{:?}", err)
        }
      }
    }
  }
  Ok(())
}
