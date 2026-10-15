//! Userspace egress proxy for `allow_hosts` (SPEC-v034 G8; design §8).
//!
//! The child runs in its own network namespace with only loopback, where
//! this proxy listens. It accepts `CONNECT host:port` and absolute-form
//! `http://host[:port]/…` requests, checks the host against the allowlist,
//! and dials upstream from the daemon's namespace. Anything else gets an
//! HTTP error and no upstream connection. No globs: an entry is a host, or
//! a host and port. An empty allowlist never reaches this proxy (it means
//! unrestricted and no namespace is made).

use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpStream, ToSocketAddrs};
use std::thread;
use std::time::Duration;

const HEAD_CAP: usize = 16 * 1024;
const DIAL_TIMEOUT: Duration = Duration::from_secs(10);

/// Parsed `allow_hosts`. Hosts compare lowercase and exactly.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AllowList(Vec<(String, Option<u16>)>);

impl AllowList {
    /// Parse `host` or `host:port` entries (`[v6]:port` for IPv6).
    #[must_use]
    pub fn parse(entries: &[String]) -> Self {
        Self(entries.iter().filter_map(|e| split_host_port(e)).collect())
    }

    /// True when `host:port` matches an entry. An entry without a port
    /// matches every port of that host.
    #[must_use]
    pub fn allows(&self, host: &str, port: u16) -> bool {
        let host = host.to_ascii_lowercase();
        self.0
            .iter()
            .any(|(h, p)| *h == host && p.is_none_or(|p| p == port))
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// `host`, `host:port`, `[v6]`, or `[v6]:port` → lowercase host and port.
fn split_host_port(s: &str) -> Option<(String, Option<u16>)> {
    let s = s.trim();
    if let Some(rest) = s.strip_prefix('[') {
        let (h, tail) = rest.split_once(']')?;
        let port = match tail.strip_prefix(':') {
            Some(p) => Some(p.parse().ok()?),
            None if tail.is_empty() => None,
            None => return None,
        };
        return Some((h.to_ascii_lowercase(), port));
    }
    match s.rsplit_once(':') {
        Some((h, p)) if !h.contains(':') => Some((h.to_ascii_lowercase(), Some(p.parse().ok()?))),
        Some(_) => None,
        None if s.is_empty() => None,
        None => Some((s.to_ascii_lowercase(), None)),
    }
}

/// Serve one client connection to completion.
///
/// # Errors
///
/// I/O errors on the client side. A refused or failed upstream is an HTTP
/// error to the client, not an `Err`.
pub fn handle_client(mut client: TcpStream, allow: &AllowList) -> io::Result<()> {
    let (head, rest) = read_head(&mut client)?;
    let line = head.split(|&b| b == b'\n').next().unwrap_or_default();
    let line = String::from_utf8_lossy(line);
    let mut parts = line.split_whitespace();
    let (method, target) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""));
    let (host, port, tunnel) = if method.eq_ignore_ascii_case("CONNECT") {
        match split_host_port(target) {
            Some((h, Some(p))) => (h, p, true),
            _ => return reply(&mut client, "400 Bad Request"),
        }
    } else if let Some(rest_uri) = target.strip_prefix("http://") {
        let authority = rest_uri.split('/').next().unwrap_or("");
        match split_host_port(authority) {
            Some((h, p)) => (h, p.unwrap_or(80), false),
            None => return reply(&mut client, "400 Bad Request"),
        }
    } else {
        return reply(&mut client, "400 Bad Request");
    };
    if !allow.allows(&host, port) {
        return reply(&mut client, "403 Forbidden");
    }
    let Some(mut upstream) = dial(&host, port) else {
        return reply(&mut client, "502 Bad Gateway");
    };
    if tunnel {
        client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")?;
    } else {
        upstream.write_all(&head)?;
    }
    upstream.write_all(&rest)?;
    pipe(client, upstream);
    Ok(())
}

fn reply(client: &mut TcpStream, status: &str) -> io::Result<()> {
    write!(
        client,
        "HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    )?;
    client.flush()
}

/// Read up to the end of the request head. Returns the head (including the
/// blank line) and any bytes read past it.
fn read_head(client: &mut TcpStream) -> io::Result<(Vec<u8>, Vec<u8>)> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 2048];
    loop {
        if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let rest = buf.split_off(end + 4);
            return Ok((buf, rest));
        }
        if buf.len() > HEAD_CAP {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "request head too large",
            ));
        }
        let n = client.read(&mut chunk)?;
        if n == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

fn dial(host: &str, port: u16) -> Option<TcpStream> {
    (host, port)
        .to_socket_addrs()
        .ok()?
        .find_map(|addr| TcpStream::connect_timeout(&addr, DIAL_TIMEOUT).ok())
}

/// Copy both directions until each side closes.
fn pipe(client: TcpStream, upstream: TcpStream) {
    let (Ok(c2), Ok(u2)) = (client.try_clone(), upstream.try_clone()) else {
        return;
    };
    let up = thread::spawn(move || copy_then_close(client, upstream));
    copy_then_close(u2, c2);
    let _ = up.join();
}

fn copy_then_close(mut from: TcpStream, mut to: TcpStream) {
    let _ = io::copy(&mut from, &mut to);
    let _ = to.shutdown(Shutdown::Write);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    /// A proxy on 127.0.0.1 serving `allow`; returns its port.
    fn proxy(allow: AllowList) -> u16 {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        thread::spawn(move || {
            for s in l.incoming().flatten() {
                let a = allow.clone();
                thread::spawn(move || handle_client(s, &a));
            }
        });
        port
    }

    /// An upstream that answers one line and counts connections.
    fn upstream() -> (u16, std::sync::mpsc::Receiver<()>) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let (tx, rx) = std::sync::mpsc::channel();
        thread::spawn(move || {
            for mut s in l.incoming().flatten() {
                let _ = tx.send(());
                let _ = s.write_all(b"hello-upstream\n");
            }
        });
        (port, rx)
    }

    fn ask(proxy_port: u16, request: &str) -> String {
        let mut s = TcpStream::connect(("127.0.0.1", proxy_port)).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        s.write_all(request.as_bytes()).unwrap();
        let mut out = Vec::new();
        let _ = s.read_to_end(&mut out);
        String::from_utf8_lossy(&out).into_owned()
    }

    #[test]
    fn connect_allowed_host_tunnels() {
        let (up, seen) = upstream();
        let p = proxy(AllowList::parse(&[format!("127.0.0.1:{up}")]));
        let r = ask(
            p,
            &format!("CONNECT 127.0.0.1:{up} HTTP/1.1\r\nHost: x\r\n\r\n"),
        );
        assert!(r.starts_with("HTTP/1.1 200"), "{r}");
        assert!(r.contains("hello-upstream"), "{r}");
        assert!(seen.recv_timeout(Duration::from_secs(2)).is_ok());
    }

    #[test]
    fn connect_denied_host_never_dials() {
        let (up, seen) = upstream();
        let (other, _) = upstream();
        let p = proxy(AllowList::parse(&[format!("127.0.0.1:{other}")]));
        let r = ask(p, &format!("CONNECT 127.0.0.1:{up} HTTP/1.1\r\n\r\n"));
        assert!(r.starts_with("HTTP/1.1 403"), "{r}");
        assert!(!r.contains("hello-upstream"));
        assert!(
            seen.recv_timeout(Duration::from_millis(300)).is_err(),
            "denied host was dialed"
        );
    }

    #[test]
    fn absolute_http_is_checked_and_forwarded() {
        let (up, _) = upstream();
        let p = proxy(AllowList::parse(&["127.0.0.1".into()]));
        let ok = ask(
            p,
            &format!("GET http://127.0.0.1:{up}/x HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"),
        );
        assert!(ok.contains("hello-upstream"), "{ok}");
        let denied = ask(p, &format!("GET http://localhost:{up}/x HTTP/1.1\r\n\r\n"));
        assert!(denied.starts_with("HTTP/1.1 403"), "{denied}");
        let bad = ask(p, "GET /relative HTTP/1.1\r\n\r\n");
        assert!(bad.starts_with("HTTP/1.1 400"), "{bad}");
    }

    #[test]
    fn allowlist_rules() {
        let a = AllowList::parse(&[
            "API.example.com".into(),
            "db.example.com:5432".into(),
            "[::1]:8443".into(),
        ]);
        assert!(a.allows("api.example.com", 443));
        assert!(a.allows("API.EXAMPLE.COM", 80));
        assert!(a.allows("db.example.com", 5432));
        assert!(!a.allows("db.example.com", 5433));
        assert!(a.allows("::1", 8443));
        assert!(!a.allows("evil.example.com", 443));
        assert!(
            !a.allows("sub.api.example.com", 443),
            "no globs, no suffix match"
        );
        assert!(AllowList::parse(&[]).is_empty());
    }
}
