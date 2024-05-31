use bytes::Bytes;
use slinger::record::CommandRecord;

/// ## ncat command
/// ```bash
/// #
/// printf 'GET /test1 HTTP/1.1\r\n'\
/// 'Host: 192.168.83.196:8081\r\n'\
/// 'Content-Length: 42\r\n'\
/// 'Transfer-Encoding: chunked\r\n'\
/// '\r\n'\
/// '0\r\n'\
/// '\r\n'\
/// 'GET /test1 HTTP/1.1\r\n'\
/// 'Host: 192.168.83.196:8081\r\n'\
/// 'X: GET http://192.168.83.1:8080/admin.jsp HTTP/1.0\r\n'\
/// '\r\n'\
/// '\r\n'\
/// |ncat 127.0.0.1 9015
/// #
/// ```
///
/// ## curl command
/// ```bash
/// #
/// curl -X GET --compressed\
///  -H 'x: X'\
///  -d '\x7fELF\x01\x00\x02\x03'\
///  'http://httpbin.org/get'
/// #
/// ```
const RAW: &str = "GET /test1 HTTP/1.1
Host: 192.168.83.196:8081
Content-Length: 42
Transfer-Encoding: chunked

0

GET /test1 HTTP/1.1
Host: 192.168.83.196:8081
X: GET http://192.168.83.1:8080/admin.jsp HTTP/1.0

";

fn main() {
  let req: slinger::Request = slinger::Request::builder()
    .uri("http://httpbin.org/get")
    .header("X", "X")
    .body(Bytes::from(b"\x7f\x45\x4c\x46\x01\x00\x02\x03".to_vec())).unwrap().into();
  println!("{}", req.get_command());
  let raw = RAW.replace('\n', "\r\n");
  let raw = [raw.as_bytes(), b"\x7f\x45\x4c\x46\x01\x00\x02\x03"].concat();
  let raw_req = slinger::RequestBuilder::default().raw(raw, true).build().unwrap();
  println!("{}", raw_req.get_command());
  // or from request
  println!("{}",CommandRecord::from(&req))
}