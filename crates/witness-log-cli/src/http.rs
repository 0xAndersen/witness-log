//! Minimal HTTP/1.1 server and client for `tlog-witness`, std only.
//!
//! Deliberately small: the witness protocol is two endpoints carrying
//! signed plain text, so a framework would add far more attack surface
//! and dependency weight than it removes. Everything an attacker sends is
//! bounded: header bytes, body bytes, per-read time, total request time,
//! and concurrent connections. Every response closes the connection, so
//! there is no keep-alive or pipelining state to get wrong.
//!
//! Transport security note: the protocol's integrity does not depend on
//! TLS -- checkpoints are signed by the log and cosignatures by the
//! witness, and the client verifies both, so an on-path attacker can
//! only withhold or delay. Public witnesses SHOULD still sit behind a
//! TLS-terminating proxy for privacy, and the built-in client speaks both
//! `http://` and `https://` (the `https` feature, on by default: rustls on
//! ring, Mozilla roots compiled in; `WITNESS_LOG_CA_FILE=<pem>` trusts
//! exactly the CA certificates in that file instead, for a private PKI).
//! The server side is plain HTTP only; TLS terminates in front of it.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Largest request/response head accepted.
pub const MAX_HEADER_BYTES: usize = 8 * 1024;
/// Largest body accepted. A checkpoint plus 63 proof lines is ~3 KiB.
pub const MAX_BODY_BYTES: usize = 64 * 1024;
/// Per-read/write socket timeout.
pub const IO_TIMEOUT: Duration = Duration::from_secs(5);
/// Total time a client gets to deliver one request (slowloris bound).
pub const REQUEST_DEADLINE: Duration = Duration::from_secs(10);

pub struct Request {
    pub method: String,
    pub path: String,
    pub body: Vec<u8>,
    pub peer: SocketAddr,
}

pub struct Response {
    pub status: u16,
    pub content_type: &'static str,
    pub body: Vec<u8>,
    /// Sent as `Retry-After` (seconds) on 429/503.
    pub retry_after: Option<u64>,
}

impl Response {
    pub fn text(status: u16, body: impl Into<String>) -> Self {
        Self {
            status,
            content_type: "text/plain; charset=utf-8",
            body: body.into().into_bytes(),
            retry_after: None,
        }
    }
    pub fn typed(status: u16, content_type: &'static str, body: impl Into<String>) -> Self {
        Self {
            status,
            content_type,
            body: body.into().into_bytes(),
            retry_after: None,
        }
    }
    pub fn json(status: u16, body: String) -> Self {
        Self::typed(status, "application/json", body)
    }
    pub fn retry_after(mut self, secs: u64) -> Self {
        self.retry_after = Some(secs);
        self
    }
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        409 => "Conflict",
        411 => "Length Required",
        413 => "Content Too Large",
        422 => "Unprocessable Content",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        503 => "Service Unavailable",
        505 => "HTTP Version Not Supported",
        _ => "Unknown",
    }
}

/// The address rate limits and connection caps are keyed on: the full
/// address for IPv4, the /64 for IPv6 (one IPv6 client routinely owns a
/// whole /64, so per-address limits would be trivially evaded).
pub fn client_key(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => {
                let mut o = v6.octets();
                for b in o.iter_mut().skip(8) {
                    *b = 0;
                }
                IpAddr::V6(std::net::Ipv6Addr::from(o))
            }
        },
    }
}

/// Per-read timeout that never runs past the request deadline, so the
/// slowloris bound really is REQUEST_DEADLINE (not deadline + IO_TIMEOUT).
fn bound_read(stream: &TcpStream, start: Instant) -> bool {
    let left = REQUEST_DEADLINE.saturating_sub(start.elapsed());
    if left.is_zero() {
        return false;
    }
    let _ = stream.set_read_timeout(Some(left.min(IO_TIMEOUT)));
    true
}

fn find_head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

fn timed_out(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    )
}

/// Read and validate one request. Errors are ready-to-send responses.
pub fn read_request(stream: &mut TcpStream, peer: SocketAddr) -> Result<Request, Response> {
    let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
    let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
    let start = Instant::now();
    let mut buf: Vec<u8> = Vec::with_capacity(1024);
    let mut chunk = [0u8; 2048];

    let head_end = loop {
        if let Some(pos) = find_head_end(&buf) {
            break pos;
        }
        if buf.len() > MAX_HEADER_BYTES {
            return Err(Response::text(431, "request head too large\n"));
        }
        if !bound_read(stream, start) {
            return Err(Response::text(408, "request too slow\n"));
        }
        match stream.read(&mut chunk) {
            Ok(0) => return Err(Response::text(400, "connection closed mid-request\n")),
            Ok(n) => buf.extend_from_slice(chunk.get(..n).unwrap_or(&[])),
            Err(e) if timed_out(&e) => return Err(Response::text(408, "request too slow\n")),
            Err(_) => return Err(Response::text(400, "read error\n")),
        }
    };
    if head_end > MAX_HEADER_BYTES {
        return Err(Response::text(431, "request head too large\n"));
    }

    let head = std::str::from_utf8(buf.get(..head_end).unwrap_or(&[]))
        .map_err(|_| Response::text(400, "request head is not UTF-8\n"))?;
    let mut lines = head.split("\r\n");
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split(' ');
    let (method, target, version) = match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some(m), Some(t), Some(v), None) if !m.is_empty() && t.starts_with('/') => (m, t, v),
        _ => return Err(Response::text(400, "malformed request line\n")),
    };
    if version != "HTTP/1.1" && version != "HTTP/1.0" {
        return Err(Response::text(505, "HTTP/1.0 or HTTP/1.1 only\n"));
    }

    let mut content_length: Option<usize> = None;
    for line in lines {
        // Only CRLF ends a line. A bare CR or LF inside a "line" is the
        // classic way to hide a header from one parser and show it to
        // another; refuse it outright.
        if line.contains('\n') || line.contains('\r') {
            return Err(Response::text(400, "bare CR or LF in request head\n"));
        }
        let Some((name, value)) = line.split_once(':') else {
            return Err(Response::text(400, "malformed header line\n"));
        };
        if name.is_empty() || name.contains(' ') {
            return Err(Response::text(400, "malformed header name\n"));
        }
        let value = value.trim();
        if name.eq_ignore_ascii_case("transfer-encoding") {
            // Chunked request bodies are a classic request-smuggling
            // vector; the protocol never needs them.
            return Err(Response::text(
                501,
                "Transfer-Encoding not supported; send Content-Length\n",
            ));
        }
        if name.eq_ignore_ascii_case("content-length") {
            if content_length.is_some() {
                return Err(Response::text(400, "duplicate Content-Length\n"));
            }
            if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
                return Err(Response::text(400, "invalid Content-Length\n"));
            }
            content_length = Some(
                value
                    .parse()
                    .map_err(|_| Response::text(400, "invalid Content-Length\n"))?,
            );
        }
    }

    let path = target.split('?').next().unwrap_or(target).to_string();
    let method = method.to_string();
    let body_len = match (method.as_str(), content_length) {
        ("POST", None) => return Err(Response::text(411, "Content-Length required\n")),
        (_, Some(n)) => n,
        (_, None) => 0,
    };
    if body_len > MAX_BODY_BYTES {
        return Err(Response::text(413, "body too large\n"));
    }

    let mut body: Vec<u8> = buf.get(head_end + 4..).unwrap_or(&[]).to_vec();
    while body.len() < body_len {
        if !bound_read(stream, start) {
            return Err(Response::text(408, "request too slow\n"));
        }
        match stream.read(&mut chunk) {
            Ok(0) => return Err(Response::text(400, "body shorter than Content-Length\n")),
            Ok(n) => body.extend_from_slice(chunk.get(..n).unwrap_or(&[])),
            Err(e) if timed_out(&e) => return Err(Response::text(408, "request too slow\n")),
            Err(_) => return Err(Response::text(400, "read error\n")),
        }
        if body.len() > MAX_BODY_BYTES {
            return Err(Response::text(413, "body too large\n"));
        }
    }
    body.truncate(body_len);
    Ok(Request {
        method,
        path,
        body,
        peer,
    })
}

pub fn write_response(stream: &mut TcpStream, resp: &Response) {
    let retry = resp
        .retry_after
        .map(|s| format!("Retry-After: {s}\r\n"))
        .unwrap_or_default();
    let head = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\n{retry}Connection: close\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\n\r\n",
        resp.status,
        reason(resp.status),
        resp.content_type,
        resp.body.len()
    );
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(&resp.body);
    let _ = stream.flush();
    let _ = stream.shutdown(std::net::Shutdown::Write);
}

struct IpGuard(Arc<Mutex<HashMap<IpAddr, usize>>>, IpAddr);
impl Drop for IpGuard {
    fn drop(&mut self) {
        let mut m = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(n) = m.get_mut(&self.1) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                m.remove(&self.1);
            }
        }
    }
}

struct ConnGuard(Arc<AtomicUsize>);
impl Drop for ConnGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Serve forever. One thread per connection, at most `max_conns` at
/// once; excess connections get an immediate 503 instead of queueing
/// unboundedly.
pub fn serve<F>(listener: TcpListener, max_conns: usize, max_per_ip: usize, handler: Arc<F>)
where
    F: Fn(&Request) -> Response + Send + Sync + 'static,
{
    let active = Arc::new(AtomicUsize::new(0));
    let per_ip: Arc<Mutex<HashMap<IpAddr, usize>>> = Arc::new(Mutex::new(HashMap::new()));
    for stream in listener.incoming() {
        let mut stream = match stream {
            Ok(s) => s,
            Err(_) => {
                // EMFILE/ENFILE and friends fail instantly and repeatedly;
                // without a pause this loop pins a CPU core.
                std::thread::sleep(Duration::from_millis(50));
                continue;
            }
        };
        let Ok(peer) = stream.peer_addr() else {
            continue;
        };
        let busy = |stream: &mut TcpStream| {
            let _ = stream.set_write_timeout(Some(Duration::from_millis(500)));
            write_response(stream, &Response::text(503, "busy, retry\n").retry_after(1));
        };
        // Per-client cap first, so one client cannot occupy every slot
        // with idle sockets (each may be held up to REQUEST_DEADLINE).
        let ip = client_key(peer.ip());
        {
            let mut m = per_ip.lock().unwrap_or_else(|e| e.into_inner());
            let n = m.entry(ip).or_insert(0);
            if *n >= max_per_ip {
                drop(m);
                busy(&mut stream);
                continue;
            }
            *n += 1;
        }
        let ip_guard = IpGuard(per_ip.clone(), ip);
        if active.fetch_add(1, Ordering::SeqCst) >= max_conns {
            active.fetch_sub(1, Ordering::SeqCst);
            drop(ip_guard);
            busy(&mut stream);
            continue;
        }
        let guard = (ConnGuard(active.clone()), ip_guard);
        let handler = handler.clone();
        let spawned = std::thread::Builder::new()
            .name("witness-conn".into())
            .spawn(move || {
                let _guard = guard;
                let resp = match read_request(&mut stream, peer) {
                    Ok(req) => handler(&req),
                    Err(resp) => resp,
                };
                write_response(&mut stream, &resp);
            });
        // If the OS refuses a thread the guard was moved into the failed
        // closure and already dropped, so the slot is released.
        if spawned.is_err() {
            continue;
        }
    }
}

// ---------------------------------------------------------------- client

#[derive(Debug, Clone)]
pub struct Url {
    pub host: String,
    pub port: u16,
    /// Path prefix without a trailing slash ("" or "/witness").
    pub base_path: String,
    /// `https://`: the request goes over TLS (the `https` feature).
    pub tls: bool,
}

pub fn parse_url(s: &str) -> Result<Url, String> {
    let (rest, tls, default_port) = if let Some(rest) = s.strip_prefix("https://") {
        if !cfg!(feature = "https") {
            return Err(format!(
                "{s}: this witness-log was built without the `https` feature, so it speaks \
                 http:// only. Rebuild with default features, or use the library from any \
                 HTTP client"
            ));
        }
        (rest, true, 443)
    } else if let Some(rest) = s.strip_prefix("http://") {
        (rest, false, 80)
    } else {
        return Err(format!("{s}: URL must start with http:// or https://"));
    };
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    };
    let (host, port) = if let Some(after) = authority.strip_prefix('[') {
        let (h, p) = after
            .split_once(']')
            .ok_or_else(|| format!("{s}: bad IPv6 literal"))?;
        let port = match p.strip_prefix(':') {
            Some(p) => p.parse().map_err(|_| format!("{s}: bad port"))?,
            None => default_port,
        };
        (h.to_string(), port)
    } else {
        match authority.rsplit_once(':') {
            Some((h, p)) => (
                h.to_string(),
                p.parse().map_err(|_| format!("{s}: bad port"))?,
            ),
            None => (authority.to_string(), default_port),
        }
    };
    if host.is_empty() {
        return Err(format!("{s}: missing host"));
    }
    Ok(Url {
        host,
        port,
        base_path: path.trim_end_matches('/').to_string(),
        tls,
    })
}

/// One request, connection closed after. Returns (status, body).
pub fn request(
    url: &Url,
    method: &str,
    path: &str,
    body: &[u8],
    timeout: Duration,
) -> Result<(u16, Vec<u8>, Option<u64>), String> {
    // A bad WITNESS_LOG_CA_FILE is a configuration error: say so before
    // any connection attempt can fail for some other reason.
    #[cfg(feature = "https")]
    if url.tls {
        tls::config()?;
    }
    let addrs: Vec<SocketAddr> = (url.host.as_str(), url.port)
        .to_socket_addrs()
        .map_err(|e| format!("resolve {}: {e}", url.host))?
        .collect();
    let mut last_err = String::from("no addresses");
    let mut stream = None;
    for a in addrs {
        match TcpStream::connect_timeout(&a, timeout) {
            Ok(s) => {
                stream = Some(s);
                break;
            }
            Err(e) => last_err = format!("connect {a}: {e}"),
        }
    }
    let stream = stream.ok_or(last_err)?;
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));
    let host_header = if url.host.contains(':') {
        format!("[{}]:{}", url.host, url.port)
    } else {
        format!("{}:{}", url.host, url.port)
    };
    let head = format!(
        "{method} {}{path} HTTP/1.1\r\nHost: {host_header}\r\nUser-Agent: witness-log/{}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        url.base_path,
        env!("CARGO_PKG_VERSION"),
        body.len()
    );
    if url.tls {
        #[cfg(feature = "https")]
        {
            let mut stream = tls::connect(&url.host, stream)?;
            return exchange(&mut stream, head.as_bytes(), body, timeout);
        }
        #[cfg(not(feature = "https"))]
        return Err("built without the `https` feature".into());
    }
    let mut stream = stream;
    exchange(&mut stream, head.as_bytes(), body, timeout)
}

/// Write one request and read the whole response, over plain TCP or TLS.
fn exchange<S: Read + Write>(
    stream: &mut S,
    head: &[u8],
    body: &[u8],
    timeout: Duration,
) -> Result<(u16, Vec<u8>, Option<u64>), String> {
    stream
        .write_all(head)
        .and_then(|_| stream.write_all(body))
        .and_then(|_| stream.flush())
        .map_err(|e| format!("send: {e}"))?;

    let start = Instant::now();
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        if start.elapsed() > timeout * 2 {
            return Err("response too slow".into());
        }
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => buf.extend_from_slice(chunk.get(..n).unwrap_or(&[])),
            Err(e) if timed_out(&e) => return Err("response timed out".into()),
            Err(e) => {
                // A reset after a complete response is fine.
                if find_head_end(&buf).is_some() {
                    break;
                }
                return Err(format!("read: {e}"));
            }
        }
        if buf.len() > MAX_HEADER_BYTES + MAX_BODY_BYTES {
            return Err("response too large".into());
        }
    }
    let head_end = find_head_end(&buf).ok_or("malformed response (no header terminator)")?;
    let head = std::str::from_utf8(buf.get(..head_end).unwrap_or(&[]))
        .map_err(|_| "response head not UTF-8")?;
    let mut lines = head.split("\r\n");
    let status: u16 = lines
        .next()
        .and_then(|l| l.split(' ').nth(1))
        .and_then(|c| c.parse().ok())
        .ok_or("malformed status line")?;
    let mut content_length = None;
    let mut chunked = false;
    let mut retry_after = None;
    for l in lines {
        if let Some((n, v)) = l.split_once(':') {
            if n.eq_ignore_ascii_case("retry-after") {
                retry_after = v.trim().parse::<u64>().ok();
            } else if n.eq_ignore_ascii_case("content-length") {
                content_length = v.trim().parse::<usize>().ok();
            } else if n.eq_ignore_ascii_case("transfer-encoding")
                && v.to_ascii_lowercase().contains("chunked")
            {
                chunked = true;
            }
        }
    }
    let raw = buf.get(head_end + 4..).unwrap_or(&[]);
    let body = if chunked {
        decode_chunked(raw)?
    } else if let Some(n) = content_length {
        raw.get(..n)
            .ok_or("response body shorter than Content-Length")?
            .to_vec()
    } else {
        raw.to_vec()
    };
    Ok((status, body, retry_after))
}

/// Whether `https://` URLs can be used, and what their certificates are
/// checked against. A `WITNESS_LOG_CA_FILE` that does not load is the
/// `Err`, as is a build without the `https` feature.
pub fn https_ready() -> Result<String, String> {
    #[cfg(feature = "https")]
    {
        tls::config()?;
        Ok(match std::env::var_os("WITNESS_LOG_CA_FILE") {
            Some(p) => format!(
                "the CA certificates in WITNESS_LOG_CA_FILE ({})",
                p.to_string_lossy()
            ),
            None => "the Mozilla root set compiled into this binary".to_string(),
        })
    }
    #[cfg(not(feature = "https"))]
    Err("this binary was built without the `https` feature".into())
}

/// TLS for the client (`https://` witnesses and directory URLs).
#[cfg(feature = "https")]
mod tls {
    use std::net::TcpStream;
    use std::sync::{Arc, OnceLock};

    pub type Stream = rustls::StreamOwned<rustls::ClientConnection, TcpStream>;

    /// Mozilla's root set compiled in, or exactly the certificates in
    /// `WITNESS_LOG_CA_FILE` (PEM) when that is set: a private CA, or a test.
    pub fn config() -> Result<Arc<rustls::ClientConfig>, String> {
        static CONFIG: OnceLock<Result<Arc<rustls::ClientConfig>, String>> = OnceLock::new();
        CONFIG
            .get_or_init(|| {
                let mut roots = rustls::RootCertStore::empty();
                match std::env::var_os("WITNESS_LOG_CA_FILE") {
                    Some(path) => {
                        use rustls::pki_types::pem::PemObject;
                        use rustls::pki_types::CertificateDer;
                        let shown = path.to_string_lossy().into_owned();
                        let certs = CertificateDer::pem_file_iter(&path)
                            .map_err(|e| format!("WITNESS_LOG_CA_FILE {shown}: {e}"))?
                            .collect::<Result<Vec<_>, _>>()
                            .map_err(|e| format!("WITNESS_LOG_CA_FILE {shown}: {e}"))?;
                        let (added, _) = roots.add_parsable_certificates(certs);
                        if added == 0 {
                            return Err(format!(
                                "WITNESS_LOG_CA_FILE {shown}: no usable certificates"
                            ));
                        }
                    }
                    None => roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned()),
                }
                let provider = Arc::new(rustls::crypto::ring::default_provider());
                let config = rustls::ClientConfig::builder_with_provider(provider)
                    .with_safe_default_protocol_versions()
                    .map_err(|e| format!("tls: {e}"))?
                    .with_root_certificates(roots)
                    .with_no_client_auth();
                Ok(Arc::new(config))
            })
            .clone()
    }

    pub fn connect(host: &str, sock: TcpStream) -> Result<Stream, String> {
        let name = rustls::pki_types::ServerName::try_from(host.to_string())
            .map_err(|_| format!("{host}: not a valid TLS server name"))?;
        let conn = rustls::ClientConnection::new(config()?, name)
            .map_err(|e| format!("tls {host}: {e}"))?;
        Ok(rustls::StreamOwned::new(conn, sock))
    }
}

/// Decode a chunked body (reverse proxies in front of witnesses use it).
fn decode_chunked(mut raw: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    loop {
        let line_end = raw
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or("bad chunk header")?;
        let size_str = std::str::from_utf8(raw.get(..line_end).unwrap_or(&[]))
            .map_err(|_| "bad chunk size")?;
        let size_str = size_str.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_str, 16).map_err(|_| "bad chunk size")?;
        raw = raw.get(line_end + 2..).ok_or("truncated chunk")?;
        if size == 0 {
            return Ok(out);
        }
        if out.len().saturating_add(size) > MAX_BODY_BYTES {
            return Err("chunked body too large".into());
        }
        out.extend_from_slice(raw.get(..size).ok_or("truncated chunk")?);
        raw = raw.get(size + 2..).ok_or("truncated chunk")?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_parsing() {
        let u = parse_url("http://127.0.0.1:7380/w").unwrap();
        assert_eq!(
            (u.host.as_str(), u.port, u.base_path.as_str()),
            ("127.0.0.1", 7380, "/w")
        );
        let u = parse_url("http://example.com").unwrap();
        assert_eq!((u.port, u.base_path.as_str()), (80, ""));
        let u = parse_url("http://[::1]:9/").unwrap();
        assert_eq!((u.host.as_str(), u.port), ("::1", 9));
        assert!(!u.tls);
        #[cfg(feature = "https")]
        {
            let u = parse_url("https://witness.example/w/").unwrap();
            assert_eq!(
                (u.host.as_str(), u.port, u.base_path.as_str(), u.tls),
                ("witness.example", 443, "/w", true)
            );
            let u = parse_url("https://[::1]:8443").unwrap();
            assert_eq!((u.host.as_str(), u.port, u.tls), ("::1", 8443, true));
        }
        #[cfg(not(feature = "https"))]
        assert!(parse_url("https://x").is_err());
        assert!(parse_url("ftp://x").is_err());
        assert!(parse_url("http://:80").is_err());
        assert!(parse_url("http://h:notaport").is_err());
    }

    #[test]
    fn ipv6_clients_are_keyed_by_slash_64() {
        let a: IpAddr = "2001:db8:1:2:aaaa::1".parse().unwrap();
        let b: IpAddr = "2001:db8:1:2:bbbb::9".parse().unwrap();
        let c: IpAddr = "2001:db8:1:3::1".parse().unwrap();
        assert_eq!(client_key(a), client_key(b));
        assert_ne!(client_key(a), client_key(c));
        let v4: IpAddr = "10.0.0.1".parse().unwrap();
        assert_eq!(client_key(v4), v4);
        let mapped: IpAddr = "::ffff:10.0.0.1".parse().unwrap();
        assert_eq!(client_key(mapped), v4);
    }

    #[test]
    fn chunk_size_overflow_is_an_error_not_a_panic() {
        assert!(decode_chunked(b"ffffffffffffffff\r\nab").is_err());
    }

    #[test]
    fn chunked_decoding() {
        assert_eq!(
            decode_chunked(b"3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n").unwrap(),
            b"abcde"
        );
        assert!(decode_chunked(b"zz\r\n").is_err());
        assert!(decode_chunked(b"5\r\nab").is_err());
    }
}
