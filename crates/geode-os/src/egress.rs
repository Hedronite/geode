//! Userspace egress proxy for `allow_hosts` (SPEC-v034 G8; design §8).
//!
//! Linux custody puts the child in its own network namespace with only
//! loopback, where this proxy listens. macOS local runs use the same proxy
//! and the same [`AllowList`] check; a seatbelt lets the child dial only
//! the proxy. The proxy accepts `CONNECT host:port` and absolute-form
//! `http://host[:port]/…` requests, checks the host with [`AllowList::allows`],
//! and dials upstream only after that check. A per-run token, when set,
//! must be presented as `Proxy-Authorization`; a miss is 407 and no dial.
//! A name that resolves to a loopback, private, link-local, or other
//! non-global address is not dialed unless that host is an IP literal
//! already on the list. Anything else gets an HTTP error and no upstream
//! connection. No globs: an entry is a host, or a host and port.
//!
//! An empty or unusable list does not mean allow-all. [`require_secret_hosts`]
//! refuses it, and [`AllowList::admit`] refuses to dial.

use std::io::{self, Read, Write};
use std::net::{
    IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs,
};
use std::sync::{Arc, Mutex};
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

/// Hosts the proxy refused. Shared with the caller that writes the audit
/// row. The value is `host:port` only; the proxy token is never stored.
#[derive(Clone, Default)]
pub struct HostDenials {
    inner: Arc<Mutex<Vec<String>>>,
}

impl HostDenials {
    /// Record one refused `host:port`. The label is capped so a huge host
    /// cannot fill the audit row.
    pub fn record(&self, host: &str, port: u16) {
        let mut label: String = host.chars().take(180).collect();
        label.push(':');
        label.push_str(&port.to_string());
        if label.chars().count() > 200 {
            label = label.chars().take(200).collect();
        }
        let mut guard = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        guard.push(label);
    }

    /// Denials recorded so far, in order.
    #[must_use]
    pub fn snapshot(&self) -> Vec<String> {
        self.inner.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }
}

/// One proxy accept loop: the allowlist, the per-run token, and where
/// denials are recorded. `token: None` skips the check (unit tests).
#[derive(Clone)]
pub struct ProxySession {
    pub allow: AllowList,
    pub token: Option<String>,
    pub denials: HostDenials,
}

/// Why [`HostDial::dial`] did not return a stream.
#[derive(Debug)]
pub enum DialError {
    /// A resolved address is loopback, private, link-local, or another
    /// non-global range, and the request host was not an IP literal.
    Restricted,
    /// Resolve or connect failed. No restricted address was the cause.
    Io(io::Error),
}

/// Something that can open a TCP connection. Tests pass a mock; the proxy
/// passes [`TcpDial`].
pub trait HostDial {
    /// Open `host:port`. Called only after [`AllowList::admit`] returns ok.
    ///
    /// # Errors
    ///
    /// [`DialError::Restricted`] when a name resolves into a non-global
    /// range. [`DialError::Io`] for a transport failure.
    fn dial(&mut self, host: &str, port: u16) -> Result<TcpStream, DialError>;
}

/// The real dial the proxy uses after the allowlist check.
#[derive(Clone, Copy, Debug, Default)]
pub struct TcpDial;

impl HostDial for TcpDial {
    fn dial(&mut self, host: &str, port: u16) -> Result<TcpStream, DialError> {
        dial(host, port)
    }
}

/// [`HostGate`], a restricted address, or the transport error from a dial
/// that was allowed.
#[derive(Debug)]
pub enum ConnectError {
    /// The allowlist refused. The transport was not called.
    Gate(HostGate),
    /// The name resolved to a non-global address. Nothing was dialed.
    Restricted,
    /// The host was allowed and the dial failed.
    Io(io::Error),
}

impl std::fmt::Display for ConnectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Gate(gate) => write!(f, "{gate}"),
            Self::Restricted => write!(f, "host_denied: resolved address is restricted"),
            Self::Io(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for ConnectError {}

/// Dial `host:port` only when [`AllowList::admit`] allows it.
///
/// An IP literal that was admitted may be loopback or private: the operator
/// named that address. A name that resolves into a restricted range is not
/// dialed.
///
/// # Errors
///
/// [`ConnectError::Gate`] when the list is empty or the host is not listed.
/// The `dial` is not called. [`ConnectError::Restricted`] when a name
/// resolves to a restricted address. [`ConnectError::Io`] when an allowed
/// dial fails.
pub fn connect_allowed(
    allow: &AllowList,
    host: &str,
    port: u16,
    dial: &mut impl HostDial,
) -> Result<TcpStream, ConnectError> {
    allow.admit(host, port).map_err(ConnectError::Gate)?;
    dial.dial(host, port).map_err(|err| match err {
        DialError::Restricted => ConnectError::Restricted,
        DialError::Io(err) => ConnectError::Io(err),
    })
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

/// Where one proxy request wants to connect.
struct RequestTarget {
    host: String,
    port: u16,
    tunnel: bool,
}

/// Serve one client connection to completion.
///
/// A missing or wrong per-run token is 407 and no dial. An allowlist miss
/// or a restricted resolved address is 403 and no dial; both are recorded
/// on [`ProxySession::denials`]. The token header is removed before an
/// absolute-form request is forwarded.
///
/// # Errors
///
/// I/O errors on the client side. A refused or failed upstream is an HTTP
/// error to the client, not an `Err`.
pub fn handle_client(mut client: TcpStream, session: &ProxySession) -> io::Result<()> {
    let (head, rest) = read_head(&mut client)?;
    if !authorized(&head, session.token.as_deref()) {
        return reply(&mut client, "407 Proxy Authentication Required");
    }
    let Some(target) = request_target(&head) else {
        return reply(&mut client, "400 Bad Request");
    };
    let mut upstream = match open_upstream(session, &target) {
        Ok(stream) => stream,
        Err(status) => return reply(&mut client, status),
    };
    if target.tunnel {
        client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")?;
    } else {
        upstream.write_all(&without_proxy_auth(&head))?;
    }
    upstream.write_all(&rest)?;
    pipe(client, upstream);
    Ok(())
}

/// 403 when the gate or the address filter refuses. 502 when the dial fails.
fn open_upstream(
    session: &ProxySession,
    target: &RequestTarget,
) -> Result<TcpStream, &'static str> {
    match connect_allowed(&session.allow, &target.host, target.port, &mut TcpDial) {
        Ok(stream) => Ok(stream),
        Err(ConnectError::Gate(_)) | Err(ConnectError::Restricted) => {
            session.denials.record(&target.host, target.port);
            Err("403 Forbidden")
        }
        Err(ConnectError::Io(_)) => Err("502 Bad Gateway"),
    }
}

fn reply(client: &mut TcpStream, status: &str) -> io::Result<()> {
    let extra = if status.starts_with("407") {
        "Proxy-Authenticate: Basic realm=\"geode\"\r\n"
    } else {
        ""
    };
    write!(
        client,
        "HTTP/1.1 {status}\r\n{extra}Content-Length: 0\r\nConnection: close\r\n\r\n"
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

fn request_target(head: &[u8]) -> Option<RequestTarget> {
    let line = head.split(|&b| b == b'\n').next().unwrap_or_default();
    let line = String::from_utf8_lossy(line);
    let mut parts = line.split_whitespace();
    let (method, target) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""));
    if method.eq_ignore_ascii_case("CONNECT") {
        let (host, port) = split_host_port(target)?;
        return Some(RequestTarget {
            host,
            port: port?,
            tunnel: true,
        });
    }
    let rest = target.strip_prefix("http://")?;
    let authority = rest.split('/').next().unwrap_or("");
    let (host, port) = split_host_port(authority)?;
    Some(RequestTarget {
        host,
        port: port.unwrap_or(80),
        tunnel: false,
    })
}

fn authorized(head: &[u8], token: Option<&str>) -> bool {
    let Some(token) = token else {
        return true;
    };
    let Some(presented) = proxy_basic(head) else {
        return false;
    };
    let mut expect = b"geode:".to_vec();
    expect.extend_from_slice(token.as_bytes());
    ct_eq(&presented, &expect)
}

fn proxy_basic(head: &[u8]) -> Option<Vec<u8>> {
    let text = String::from_utf8_lossy(head);
    for line in text.split("\r\n") {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if !name.eq_ignore_ascii_case("proxy-authorization") {
            continue;
        }
        let value = value.trim();
        let rest = value.get(5..)?;
        if !value[..5].eq_ignore_ascii_case("basic") {
            return None;
        }
        return decode_b64(rest.trim());
    }
    None
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (left, right) in a.iter().zip(b.iter()) {
        diff |= left ^ right;
    }
    diff == 0
}

fn decode_b64(raw: &str) -> Option<Vec<u8>> {
    if raw.is_empty() || raw.bytes().any(|b| b.is_ascii_whitespace()) {
        return None;
    }
    let bytes: Vec<u8> = raw.bytes().filter(|b| *b != b'=').collect();
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    let mut i = 0;
    while i + 4 <= bytes.len() {
        let n = (u32::from(b64_val(bytes[i])?) << 18)
            | (u32::from(b64_val(bytes[i + 1])?) << 12)
            | (u32::from(b64_val(bytes[i + 2])?) << 6)
            | u32::from(b64_val(bytes[i + 3])?);
        out.push((n >> 16) as u8);
        out.push((n >> 8) as u8);
        out.push(n as u8);
        i += 4;
    }
    match bytes.len() - i {
        0 => Some(out),
        2 => {
            let n =
                (u32::from(b64_val(bytes[i])?) << 18) | (u32::from(b64_val(bytes[i + 1])?) << 12);
            out.push((n >> 16) as u8);
            Some(out)
        }
        3 => {
            let n = (u32::from(b64_val(bytes[i])?) << 18)
                | (u32::from(b64_val(bytes[i + 1])?) << 12)
                | (u32::from(b64_val(bytes[i + 2])?) << 6);
            out.push((n >> 16) as u8);
            out.push((n >> 8) as u8);
            Some(out)
        }
        _ => None,
    }
}

fn b64_val(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

fn without_proxy_auth(head: &[u8]) -> Vec<u8> {
    let text = String::from_utf8_lossy(head);
    let mut out = String::new();
    for line in text.split("\r\n") {
        if let Some((name, _)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("proxy-authorization") {
                continue;
            }
        }
        if !out.is_empty() {
            out.push_str("\r\n");
        }
        out.push_str(line);
    }
    out.into_bytes()
}

/// 16 random bytes from `/dev/urandom`, hex encoded. One token per run.
///
/// # Errors
///
/// When `/dev/urandom` cannot be read.
pub fn random_proxy_token() -> io::Result<String> {
    let mut bytes = [0u8; 16];
    let mut file = std::fs::File::open("/dev/urandom")?;
    file.read_exact(&mut bytes)?;
    let mut hex = String::with_capacity(32);
    for byte in bytes {
        hex.push_str(&format!("{byte:02x}"));
    }
    Ok(hex)
}

/// Proxy URL the child receives. The user is fixed; the password is the
/// per-run token. Hex is URL-safe, so the token is not encoded further.
#[must_use]
pub fn proxy_url(port: u16, token: &str) -> String {
    format!("http://geode:{token}@127.0.0.1:{port}")
}

/// Bind the egress proxy on both loopback stacks, same port.
///
/// The seatbelt network rule names `localhost`, which covers both. If the
/// v6 bind fails, this returns the error and drops the v4 listener: the
/// run must not start with only one stack.
///
/// # Errors
///
/// When either bind fails.
pub fn bind_proxy_loopback() -> io::Result<(TcpListener, TcpListener, u16)> {
    let v4 = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let port = v4.local_addr()?.port();
    let v6 = TcpListener::bind((Ipv6Addr::LOCALHOST, port)).map_err(|err| {
        io::Error::new(
            err.kind(),
            format!("proxy failed to bind the v6 loopback: {err}"),
        )
    })?;
    Ok((v4, v6, port))
}

fn dial(host: &str, port: u16) -> Result<TcpStream, DialError> {
    let permit_restricted = host.parse::<IpAddr>().is_ok();
    let addrs: Vec<SocketAddr> = (host, port)
        .to_socket_addrs()
        .map_err(DialError::Io)?
        .collect();
    if addrs.is_empty() {
        return Err(DialError::Io(io::Error::new(
            io::ErrorKind::NotFound,
            "upstream dial failed",
        )));
    }
    if !permit_restricted && addrs.iter().any(|addr| is_restricted_target(addr.ip())) {
        return Err(DialError::Restricted);
    }
    let mut last = None;
    for addr in &addrs {
        match TcpStream::connect_timeout(addr, DIAL_TIMEOUT) {
            Ok(stream) => return Ok(stream),
            Err(err) => last = Some(err),
        }
    }
    Err(DialError::Io(last.unwrap_or_else(|| {
        io::Error::new(io::ErrorKind::ConnectionRefused, "upstream dial failed")
    })))
}

fn is_restricted_target(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_restricted_v4(v4),
        IpAddr::V6(v6) => is_restricted_v6(v6),
    }
}

fn is_restricted_v6(ip: Ipv6Addr) -> bool {
    if let Some(v4) = ip.to_ipv4_mapped() {
        return is_restricted_v4(v4);
    }
    if ip.is_loopback() || ip.is_unspecified() || ip.is_unicast_link_local() || ip.is_multicast() {
        return true;
    }
    is_unique_local(ip)
        || is_v6_documentation(ip)
        || is_site_local(ip)
        || is_ipv4_compatible(ip)
        || is_nat64(ip)
}

fn is_restricted_v4(ip: Ipv4Addr) -> bool {
    let first = ip.octets()[0];
    // 0.0.0.0/8 ("this host") and 240.0.0.0/4 (reserved, includes broadcast).
    if first == 0 || first >= 240 {
        return true;
    }
    if ip.is_loopback() || ip.is_private() || ip.is_link_local() || ip.is_multicast() {
        return true;
    }
    ip.is_documentation() || is_cgnat(ip) || is_benchmarking(ip)
}

/// 198.18.0.0/15, the benchmarking range.
fn is_benchmarking(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    octets[0] == 198 && (octets[1] == 18 || octets[1] == 19)
}

/// fec0::/10, the deprecated site-local range.
fn is_site_local(ip: Ipv6Addr) -> bool {
    let octets = ip.octets();
    octets[0] == 0xfe && (octets[1] & 0xc0) == 0xc0
}

/// ::/96, the deprecated IPv4-compatible form. Distinct from IPv4-mapped.
fn is_ipv4_compatible(ip: Ipv6Addr) -> bool {
    ip.octets()[..12].iter().all(|byte| *byte == 0)
}

/// `64:ff9b::/96`, the well-known NAT64 prefix, and `64:ff9b:1::/48`,
/// the local-use NAT64 prefix.
fn is_nat64(ip: Ipv6Addr) -> bool {
    let octets = ip.octets();
    if octets[0] != 0x00 || octets[1] != 0x64 || octets[2] != 0xff || octets[3] != 0x9b {
        return false;
    }
    // 64:ff9b::/96: bits 32..96 are zero. The embedded IPv4 is the last 32.
    let well_known = octets[4..12].iter().all(|byte| *byte == 0);
    // 64:ff9b:1::/48: bits 32..48 are 0x0001. The rest may be anything.
    let local_use = octets[4] == 0x00 && octets[5] == 0x01;
    well_known || local_use
}

fn is_cgnat(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    octets[0] == 100 && (octets[1] & 0xc0) == 64
}

fn is_unique_local(ip: Ipv6Addr) -> bool {
    (ip.octets()[0] & 0xfe) == 0xfc
}

fn is_v6_documentation(ip: Ipv6Addr) -> bool {
    let octets = ip.octets();
    octets[0] == 0x20 && octets[1] == 0x01 && octets[2] == 0x0d && octets[3] == 0xb8
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

    /// A proxy on 127.0.0.1 serving `allow` with no token; returns its port.
    fn proxy(allow: AllowList) -> u16 {
        serve(ProxySession {
            allow,
            token: None,
            denials: HostDenials::default(),
        })
    }

    fn serve(session: ProxySession) -> u16 {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        thread::spawn(move || {
            for s in l.incoming().flatten() {
                let session = session.clone();
                thread::spawn(move || handle_client(s, &session));
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
        fn dial(&mut self, host: &str, port: u16) -> Result<TcpStream, DialError> {
            self.calls += 1;
            TcpStream::connect((host, port)).map_err(DialError::Io)
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

    #[test]
    fn restricted_address_predicate() {
        let restricted = [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.1.1",
            "100.64.0.1",
            "192.0.2.1",
            "198.51.100.1",
            "203.0.113.1",
            "0.0.0.0",
            "255.255.255.255",
            "::1",
            "::",
            "fe80::1",
            "fc00::1",
            "fd00::1",
            "2001:db8::1",
            "::ffff:10.0.0.1",
            "::ffff:127.0.0.1",
            "0.1.2.3",
            "0.255.255.255",
            "224.0.0.1",
            "239.255.255.255",
            "198.18.0.1",
            "198.19.255.1",
            "240.0.0.1",
            "255.254.0.1",
            "ff00::1",
            "ff02::1",
            "fec0::1",
            "::8.8.8.8",
            "64:ff9b::8.8.8.8",
            "64:ff9b:1::1",
            "64:ff9b:1:ffff:ffff:ffff:ffff:ffff",
        ];
        for host in restricted {
            let ip = host.parse().unwrap();
            assert!(is_restricted_target(ip), "{host}");
        }
        for host in [
            "8.8.8.8",
            "1.1.1.1",
            "223.0.0.1",
            "198.17.0.1",
            "198.20.0.1",
            "2001:4860:4860::8888",
            "64:ff9b:2::1",
            "::ffff:8.8.8.8",
        ] {
            let ip = host.parse().unwrap();
            assert!(!is_restricted_target(ip), "{host}");
        }
        assert!(!is_cgnat("100.128.0.1".parse().unwrap()));
        assert!(is_cgnat("100.127.255.255".parse().unwrap()));
    }

    #[test]
    fn name_resolving_to_loopback_is_not_dialed() {
        let (port, seen) = counting_listener();
        let denials = HostDenials::default();
        let session = ProxySession {
            allow: AllowList::parse(&["localhost".into()]),
            token: None,
            denials: denials.clone(),
        };
        let proxy_port = serve(session);
        let r = ask(
            proxy_port,
            &format!("GET http://localhost:{port}/ HTTP/1.1\r\nHost: localhost\r\n\r\n"),
        );
        assert!(r.starts_with("HTTP/1.1 403"), "{r}");
        assert!(
            seen.recv_timeout(Duration::from_millis(300)).is_err(),
            "loopback name was dialed"
        );
        assert_eq!(denials.snapshot(), vec![format!("localhost:{port}")]);
    }

    #[test]
    fn explicit_loopback_literal_still_dials() {
        let (port, seen) = counting_listener();
        let allow = AllowList::parse(&[format!("127.0.0.1:{port}")]);
        let stream = connect_allowed(&allow, "127.0.0.1", port, &mut TcpDial).unwrap();
        drop(stream);
        assert!(seen.recv_timeout(Duration::from_secs(2)).is_ok());
    }

    #[test]
    fn proxy_token_mismatch_does_not_dial() {
        let (up, seen) = upstream();
        let denials = HostDenials::default();
        let session = ProxySession {
            allow: AllowList::parse(&[format!("127.0.0.1:{up}")]),
            token: Some("aabbccdd".into()),
            denials,
        };
        let proxy_port = serve(session);
        let r = ask(
            proxy_port,
            &format!("CONNECT 127.0.0.1:{up} HTTP/1.1\r\nHost: x\r\n\r\n"),
        );
        assert!(r.starts_with("HTTP/1.1 407"), "{r}");
        assert!(r.contains("Proxy-Authenticate"), "{r}");
        assert!(
            seen.recv_timeout(Duration::from_millis(300)).is_err(),
            "unauthenticated request was dialed"
        );
    }

    #[test]
    fn proxy_token_match_strips_authorization() {
        let (up, seen) = upstream();
        let token = "aabbccdd";
        let session = ProxySession {
            allow: AllowList::parse(&[format!("127.0.0.1:{up}")]),
            token: Some(token.into()),
            denials: HostDenials::default(),
        };
        let proxy_port = serve(session);
        let basic = encode_b64(&format!("geode:{token}"));
        let r = ask(
            proxy_port,
            &format!(
                "GET http://127.0.0.1:{up}/ HTTP/1.1\r\nHost: 127.0.0.1\r\nProxy-Authorization: Basic {basic}\r\n\r\n"
            ),
        );
        assert!(r.contains("hello-upstream"), "{r}");
        assert!(seen.recv_timeout(Duration::from_secs(2)).is_ok());
        let head =
            b"GET http://h/ HTTP/1.1\r\nHost: h\r\nProxy-Authorization: Basic secret\r\n\r\n";
        let stripped = String::from_utf8(without_proxy_auth(head)).unwrap();
        assert!(!stripped
            .to_ascii_lowercase()
            .contains("proxy-authorization"));
        assert!(!stripped.contains("secret"));
        assert!(stripped.contains("GET http://h/"));
        assert!(stripped.ends_with("\r\n\r\n"));
    }

    fn encode_b64(raw: &str) -> String {
        const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let bytes = raw.as_bytes();
        let mut out = String::new();
        let mut i = 0;
        while i + 3 <= bytes.len() {
            let n = (u32::from(bytes[i]) << 16)
                | (u32::from(bytes[i + 1]) << 8)
                | u32::from(bytes[i + 2]);
            out.push(T[((n >> 18) & 63) as usize] as char);
            out.push(T[((n >> 12) & 63) as usize] as char);
            out.push(T[((n >> 6) & 63) as usize] as char);
            out.push(T[(n & 63) as usize] as char);
            i += 3;
        }
        let rem = bytes.len() - i;
        if rem == 1 {
            let n = u32::from(bytes[i]) << 16;
            out.push(T[((n >> 18) & 63) as usize] as char);
            out.push(T[((n >> 12) & 63) as usize] as char);
            out.push('=');
            out.push('=');
        } else if rem == 2 {
            let n = (u32::from(bytes[i]) << 16) | (u32::from(bytes[i + 1]) << 8);
            out.push(T[((n >> 18) & 63) as usize] as char);
            out.push(T[((n >> 12) & 63) as usize] as char);
            out.push(T[((n >> 6) & 63) as usize] as char);
            out.push('=');
        }
        out
    }

    #[test]
    fn macos_egress_proxy_binds_v4_and_v6() {
        let (v4, v6, port) = bind_proxy_loopback().expect("both loopback stacks");
        let c4 = TcpStream::connect(("127.0.0.1", port)).unwrap();
        let c6 = TcpStream::connect(("::1", port)).unwrap();
        v4.set_nonblocking(true).unwrap();
        v6.set_nonblocking(true).unwrap();
        assert!(v4.accept().is_ok(), "v4 listener did not accept");
        assert!(v6.accept().is_ok(), "v6 listener did not accept");
        drop(c4);
        drop(c6);
    }

    #[test]
    fn denied_host_is_recorded() {
        let denials = HostDenials::default();
        let session = ProxySession {
            allow: AllowList::parse(&["other.example".into()]),
            token: None,
            denials: denials.clone(),
        };
        let proxy_port = serve(session);
        let r = ask(
            proxy_port,
            "CONNECT blocked.example:80 HTTP/1.1\r\nHost: blocked.example\r\n\r\n",
        );
        assert!(r.starts_with("HTTP/1.1 403"), "{r}");
        assert_eq!(denials.snapshot(), vec!["blocked.example:80".to_string()]);
    }
}
