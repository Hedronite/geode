//! Userspace egress proxy for `allow_hosts` (SPEC-v034 G8; design §8).
//!
//! Linux custody puts the child in its own network namespace with only
//! loopback, where this proxy listens. macOS local runs use the same proxy
//! and the same [`AllowList`] check; a seatbelt lets the child dial only
//! the proxy. The proxy accepts `CONNECT host:port` and absolute-form
//! `http://host[:port]/…` requests, checks the host with [`AllowList::allows`],
//! and dials upstream only after that check. Anything else gets an HTTP
//! error and no upstream connection. No globs: an entry is a host, or a
//! host and port.
//!
//! An empty or unusable list does not mean allow-all. [`require_secret_hosts`]
//! refuses it, and [`AllowList::admit`] refuses to dial.

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

    /// Fail closed. An empty list is [`HostGate::Required`], never allow-all.
    /// A host this list does not name is [`HostGate::Denied`]. Both mean the
    /// caller must not dial. This is the only matcher: [`gate`] and the proxy
    /// both call it, and it calls [`Self::allows`].
    pub fn admit(&self, host: &str, port: u16) -> Result<(), HostGate> {
        if self.is_empty() {
            return Err(HostGate::Required);
        }
        if self.allows(host, port) {
            Ok(())
        } else {
            Err(HostGate::Denied)
        }
    }
}

/// Why a host was not dialed. Nothing was sent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostGate {
    /// Empty or unusable `allow_hosts`. Not allow-all.
    Required,
    /// The host is not on the list.
    Denied,
}

impl HostGate {
    /// Stable error code. `host_denied` is a host that is not listed.
    /// An empty list is `policy_deny`.
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            Self::Required => "policy_deny",
            Self::Denied => "host_denied",
        }
    }
}

impl std::fmt::Display for HostGate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Required => {
                "allow_hosts is empty or unusable: refusing to inject a secret with no host allowlist"
            }
            Self::Denied => "host_denied: host is not in allow_hosts",
        })
    }
}

impl std::error::Error for HostGate {}

/// A secret binding needs a usable `allow_hosts`. Empty is a refusal, not
/// allow-all. Local `geode run` and custody both call this before spawn.
///
/// # Errors
///
/// [`HostGate::Required`] when the list is empty or every entry is unusable.
pub fn require_secret_hosts(allow_hosts: &[String]) -> Result<(), HostGate> {
    if allow_hosts.is_empty() || AllowList::parse(allow_hosts).is_empty() {
        Err(HostGate::Required)
    } else {
        Ok(())
    }
}

/// The host decision local `geode run` and custody share. It does not dial.
///
/// # Errors
///
/// [`HostGate::Required`] for an empty or unusable list.
/// [`HostGate::Denied`] when `host` is not listed (`host_denied`).
pub fn gate(allow_hosts: &[String], host: &str, port: u16) -> Result<(), HostGate> {
    if allow_hosts.is_empty() {
        return Err(HostGate::Required);
    }
    AllowList::parse(allow_hosts).admit(host, port)
}

/// Something that can open a TCP connection. Tests pass a mock; the proxy
/// passes [`TcpDial`].
pub trait HostDial {
    /// Open `host:port`. Called only after [`AllowList::admit`] returns ok.
    ///
    /// # Errors
    ///
    /// The transport's own error. A refusal never reaches this method.
    fn dial(&mut self, host: &str, port: u16) -> io::Result<TcpStream>;
}

/// The real dial the proxy uses after the allowlist check.
#[derive(Clone, Copy, Debug, Default)]
pub struct TcpDial;

impl HostDial for TcpDial {
    fn dial(&mut self, host: &str, port: u16) -> io::Result<TcpStream> {
        dial(host, port)
            .ok_or_else(|| io::Error::new(io::ErrorKind::ConnectionRefused, "upstream dial failed"))
    }
}

/// [`HostGate`] or the transport error from a dial that was allowed.
#[derive(Debug)]
pub enum ConnectError {
    /// The allowlist refused. The transport was not called.
    Gate(HostGate),
    /// The host was allowed and the dial failed.
    Io(io::Error),
}

impl std::fmt::Display for ConnectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Gate(gate) => write!(f, "{gate}"),
            Self::Io(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for ConnectError {}

/// Dial `host:port` only when [`AllowList::admit`] allows it.
///
/// # Errors
///
/// [`ConnectError::Gate`] when the list is empty or the host is not listed.
/// The `dial` is not called. [`ConnectError::Io`] when an allowed dial fails.
pub fn connect_allowed(
    allow: &AllowList,
    host: &str,
    port: u16,
    dial: &mut impl HostDial,
) -> Result<TcpStream, ConnectError> {
    allow.admit(host, port).map_err(ConnectError::Gate)?;
    dial.dial(host, port).map_err(ConnectError::Io)
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
    let mut upstream = match connect_allowed(allow, &host, port, &mut TcpDial) {
        Ok(stream) => stream,
        // Required and Denied are the same to the child: no upstream socket.
        Err(ConnectError::Gate(_)) => return reply(&mut client, "403 Forbidden"),
        Err(ConnectError::Io(_)) => return reply(&mut client, "502 Bad Gateway"),
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

    struct RecDial {
        calls: u32,
    }

    impl HostDial for RecDial {
        fn dial(&mut self, host: &str, port: u16) -> io::Result<TcpStream> {
            self.calls += 1;
            TcpStream::connect((host, port))
        }
    }

    /// Listener plus a count of accepted connections.
    fn counting_listener() -> (u16, std::sync::mpsc::Receiver<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let (tx, rx) = std::sync::mpsc::channel();
        thread::spawn(move || {
            listener.set_nonblocking(true).unwrap();
            for _ in 0..40 {
                if listener.accept().is_ok() {
                    let _ = tx.send(());
                }
                thread::sleep(Duration::from_millis(10));
            }
        });
        (port, rx)
    }

    #[test]
    fn request_to_unlisted_host_is_host_denied_and_sends_nothing() {
        let (port, seen) = counting_listener();
        let allow = AllowList::parse(&["other.example".into()]);
        let mut dial = RecDial { calls: 0 };
        let err = connect_allowed(&allow, "127.0.0.1", port, &mut dial).unwrap_err();
        let ConnectError::Gate(gate) = err else {
            panic!("dialed or lost the gate: {err}");
        };
        assert_eq!(gate.code(), "host_denied");
        assert!(gate.to_string().contains("host_denied"), "{gate}");
        assert_eq!(dial.calls, 0, "mock transport was called");
        assert!(
            seen.recv_timeout(Duration::from_millis(300)).is_err(),
            "unlisted host was dialed"
        );
    }

    #[test]
    fn request_to_an_allowed_host_dials() {
        let (port, seen) = counting_listener();
        let allow = AllowList::parse(&[format!("127.0.0.1:{port}")]);
        let mut dial = RecDial { calls: 0 };
        let stream = connect_allowed(&allow, "127.0.0.1", port, &mut dial).unwrap();
        drop(stream);
        assert_eq!(dial.calls, 1);
        assert!(
            seen.recv_timeout(Duration::from_secs(2)).is_ok(),
            "allowed host was not dialed"
        );
    }

    #[test]
    fn empty_allow_hosts_on_a_secret_binding_refuses() {
        let (port, seen) = counting_listener();
        let err = require_secret_hosts(&[]).unwrap_err();
        assert_eq!(err.code(), "policy_deny");
        assert!(err.to_string().contains("allow_hosts"), "{err}");
        assert!(err.to_string().contains("refusing"), "{err}");
        let unusable = require_secret_hosts(&[":not-a-port".into()]).unwrap_err();
        assert_eq!(unusable, HostGate::Required);
        let mut dial = RecDial { calls: 0 };
        let connect = connect_allowed(&AllowList::parse(&[]), "127.0.0.1", port, &mut dial);
        assert!(matches!(
            connect,
            Err(ConnectError::Gate(HostGate::Required))
        ));
        assert_eq!(dial.calls, 0, "empty allow_hosts dialed");
        assert!(seen.recv_timeout(Duration::from_millis(200)).is_err());
    }

    #[test]
    fn local_and_custody_host_gate_agree() {
        // One function. Local `geode run` and custody both call `gate` and
        // `require_secret_hosts`; the proxy dials only through `admit`.
        let hosts = vec!["API.example.com".into(), "db.example.com:5432".into()];
        let cases = [
            ("api.example.com", 443, true),
            ("API.EXAMPLE.COM", 80, true),
            ("db.example.com", 5432, true),
            ("db.example.com", 5433, false),
            ("evil.example", 443, false),
            ("sub.api.example.com", 443, false),
        ];
        for (host, port, allowed) in cases {
            let local = gate(&hosts, host, port);
            let custody = gate(&hosts, host, port);
            assert_eq!(local, custody, "{host}:{port}");
            assert_eq!(local.is_ok(), allowed, "{host}:{port}");
            if !allowed {
                assert_eq!(local.unwrap_err().code(), "host_denied");
            }
            let parsed = AllowList::parse(&hosts);
            assert_eq!(parsed.allows(host, port), allowed, "{host}:{port}");
        }
        let missing = gate(&[], "api.example.com", 443).unwrap_err();
        assert_eq!(missing, HostGate::Required);
        assert_eq!(require_secret_hosts(&[]), Err(HostGate::Required));
    }
}
