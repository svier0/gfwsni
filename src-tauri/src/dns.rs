use std::collections::HashMap;
use std::io::Read;
use std::net::IpAddr;
use std::sync::{Arc, OnceLock, RwLock};
use std::time::Duration;

use anyhow::{anyhow, Result};
use base64::Engine;
use log::{debug, info, warn};
use rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error, SignatureScheme};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsConnector;

const DOH_UPSTREAM: &str = "https://doh.pub/dns-query";
const DOH_LOCAL_IP: [u8; 4] = [127, 0, 0, 1];

const HOSTS_FILE: &str = "data/hosts.txt";

/// 基于 exe 所在目录解析相对路径，避免 UAC/工作目录变化导致找不到文件。
pub fn path_of(rel: &str) -> std::path::PathBuf {
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
        .unwrap_or_else(|| std::path::PathBuf::from("."));
    exe_dir.join(rel)
}

static TLS_CONNECTOR: OnceLock<TlsConnector> = OnceLock::new();
static HOSTS_URL: OnceLock<String> = OnceLock::new();
static HOSTS_MAP: OnceLock<Arc<RwLock<HashMap<String, String>>>> = OnceLock::new();
static ROOTS: OnceLock<Arc<rustls::RootCertStore>> = OnceLock::new();

pub fn init(hosts_url: String) -> Result<()> {
    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls_native_certs::load_native_certs().certs {
        let _ = roots.add(cert);
    }
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots.clone())
        .with_no_client_auth();
    TLS_CONNECTOR
        .set(TlsConnector::from(Arc::new(config)))
        .map_err(|_| anyhow!("TLS connector already set"))?;
    ROOTS.set(Arc::new(roots)).map_err(|_| anyhow!("roots already set"))?;
    HOSTS_URL
        .set(hosts_url)
        .map_err(|_| anyhow!("hosts url already set"))?;
    HOSTS_MAP
        .set(Arc::new(RwLock::new(HashMap::new())))
        .map_err(|_| anyhow!("hosts map already set"))?;
    Ok(())
}

/// Verifier that validates a server certificate against the real hostname,
/// even though the TLS connection itself is established using the peer's IP
/// (so no SNI extension is sent, bypassing SNI-based filtering).
#[derive(Debug)]
struct HostVerifier {
    inner: Arc<rustls::client::WebPkiServerVerifier>,
    real_host: ServerName<'static>,
}

impl ServerCertVerifier for HostVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        self.inner
            .verify_server_cert(end_entity, intermediates, &self.real_host, ocsp_response, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// Build a TLS client config for dialing `real_host`. The connection SNI is
/// omitted (peer IP is used); certificate validation checks `real_host`.
pub fn config_for_host(real_host: &str) -> Result<TlsConnector> {
    let real = ServerName::try_from(real_host.to_string())?;
    let inner = rustls::client::WebPkiServerVerifier::builder(ROOTS.get().unwrap().clone())
        .build()
        .map_err(|e| anyhow!("build verifier: {e}"))?;
    let verifier = HostVerifier {
        inner,
        real_host: real,
    };
    let config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();
    Ok(TlsConnector::from(Arc::new(config)))
}

fn normalize(host: &str) -> String {
    host.trim_end_matches('.').to_ascii_lowercase()
}

fn parse_hosts(body: &str) -> HashMap<String, String> {
    let mut ips: HashMap<String, String> = HashMap::new();
    let mut cnames: HashMap<String, String> = HashMap::new();
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 {
            continue;
        }
        if let Ok(ip) = parts[0].parse::<IpAddr>() {
            ips.insert(normalize(parts[1]), ip.to_string());
        } else {
            cnames.insert(normalize(parts[0]), normalize(parts[1]));
        }
    }
    let mut changed = true;
    while changed {
        changed = false;
        let mut to_add = Vec::new();
        for (alias, target) in &cnames {
            if let Some(ip) = ips.get(target) {
                to_add.push((alias.clone(), ip.clone()));
            }
        }
        for (alias, ip) in to_add {
            if ips.insert(alias, ip).is_none() {
                changed = true;
            }
        }
    }
    ips
}

async fn fetch(url: String) -> Result<String> {
    tokio::task::spawn_blocking(move || {
        let agent = ureq::AgentBuilder::new()
            .timeout(Duration::from_secs(15))
            .build();
        let resp = agent.get(&url).call()?;
        Ok::<String, anyhow::Error>(resp.into_string()?)
    })
    .await?
}

pub async fn refresh() -> Result<()> {
    let path = path_of(HOSTS_FILE);
    if path.exists() {
        info!("hosts.txt 已存在，跳过下载，绝不覆盖");
        return load_from_file();
    }
    let url = HOSTS_URL.get().unwrap().clone();
    let body = fetch(url).await?;
    std::fs::write(&path, &body)?;
    info!("已下载 hosts 文件: {}", path.display());
    load_from_file()
}

/// 强制重新下载 hosts 规则并覆盖本地文件（用于"重置规则"）。
/// 仅下载写文件，不更新内存规则，不影响正在运行的代理逻辑。
pub async fn force_download() -> Result<()> {
    let path = path_of(HOSTS_FILE);
    let url = HOSTS_URL.get().unwrap().clone();
    let body = fetch(url).await?;
    std::fs::write(&path, &body)?;
    info!("已重置 hosts 规则: {}", path.display());
    Ok(())
}

pub fn load_from_file() -> Result<()> {
    let path = path_of(HOSTS_FILE);
    let content = std::fs::read_to_string(&path)?;
    let map = parse_hosts(&content);
    let n = map.len();
    *HOSTS_MAP.get().unwrap().write().unwrap() = map;
    info!("已从 {} 加载 {} 个站点", path.display(), n);
    Ok(())
}

fn lookup_ip(host: &str) -> Option<String> {
    let hosts = HOSTS_MAP.get().unwrap().read().unwrap();
    let mut d = normalize(host);
    loop {
        if let Some(ip) = hosts.get(&d) {
            return Some(ip.clone());
        }
        match d.find('.') {
            Some(i) => d = d[i + 1..].to_string(),
            None => return None,
        }
    }
}

pub fn has(host: &str) -> bool {
    lookup_ip(host).is_some()
}

/// 返回 hosts 中所有需要代理的域名（含 CNAME 展开后的完整集合）。
pub fn domains() -> Vec<String> {
    HOSTS_MAP.get().unwrap().read().unwrap().keys().cloned().collect()
}

pub fn resolve_real_ip(host: &str) -> Vec<String> {
    match lookup_ip(host) {
        Some(ip) => vec![format!("{}:443", ip)],
        None => Vec::new(),
    }
}

/// Parse a DNS query (wire format) and return (qname, qtype, end-of-question offset).
fn parse_question(msg: &[u8]) -> Option<(String, u16, usize)> {
    if msg.len() < 12 {
        return None;
    }
    let mut off = 12usize;
    let mut name = String::new();
    let mut first = true;
    loop {
        if off >= msg.len() {
            return None;
        }
        let len = msg[off] as usize;
        if len == 0 {
            off += 1;
            break;
        }
        if len & 0xC0 != 0 {
            off += 2;
            break;
        }
        off += 1;
        if off + len > msg.len() {
            return None;
        }
        if !first {
            name.push('.');
        }
        name.push_str(&String::from_utf8_lossy(&msg[off..off + len]));
        first = false;
        off += len;
        if name.len() > 253 {
            return None;
        }
    }
    if off + 4 > msg.len() {
        return None;
    }
    let qtype = u16::from_be_bytes([msg[off], msg[off + 1]]);
    off += 4;
    Some((name, qtype, off))
}

/// Build a DNS response that points the queried name at 127.0.0.1.
fn build_local_response(req: &[u8]) -> Option<Vec<u8>> {
    let (_name, qtype, qend) = parse_question(req)?;
    let have_answer = qtype == 1 || qtype == 255; // A or ANY
    let mut resp = Vec::with_capacity(64);
    resp.extend_from_slice(&req[0..2]); // transaction id
    resp.extend_from_slice(&[0x81, 0x80]); // QR + RD + RA
    resp.extend_from_slice(&[0, 1]); // qdcount
    resp.push(0);
    resp.push(if have_answer { 1 } else { 0 }); // ancount
    resp.extend_from_slice(&[0, 0, 0, 0]); // nscount, arcount
    resp.extend_from_slice(&req[12..qend]); // question verbatim
    if have_answer {
        resp.extend_from_slice(&[0xC0, 0x0C]); // pointer to qname
        resp.extend_from_slice(&[0, 1]); // type A
        resp.extend_from_slice(&[0, 1]); // class IN
        resp.extend_from_slice(&[0, 0, 1, 44]); // ttl 300
        resp.extend_from_slice(&[0, 4]); // rdlength
        resp.extend_from_slice(&DOH_LOCAL_IP); // 127.0.0.1
    }
    Some(resp)
}

async fn forward_upstream(wire: &[u8]) -> Result<Vec<u8>> {
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(wire);
    let url = format!("{}?dns={}", DOH_UPSTREAM, b64);
    tokio::task::spawn_blocking(move || {
        let agent = ureq::AgentBuilder::new()
            .timeout(Duration::from_secs(10))
            .build();
        let resp = agent
            .get(&url)
            .set("accept", "application/dns-message")
            .call()?;
        let mut bytes = Vec::new();
        resp.into_reader().read_to_end(&mut bytes)?;
        Ok::<Vec<u8>, anyhow::Error>(bytes)
    })
    .await?
}

fn http_response(status: &str, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len() + 64);
    out.extend_from_slice(
        format!(
            "HTTP/1.1 {}\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            status,
            body.len()
        )
        .as_bytes(),
    );
    out.extend_from_slice(body);
    out
}

/// Read the HTTP request head (up to CRLFCRLF) and return its raw bytes.
pub async fn read_http_head(stream: &mut TlsStream<TcpStream>) -> Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(2048);
    let mut tmp = [0u8; 4096];
    loop {
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            return Err(anyhow!("connection closed"));
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            buf.truncate(pos + 4);
            return Ok(buf);
        }
        if buf.len() > 64 * 1024 {
            return Err(anyhow!("request header too large"));
        }
    }
}

/// Parse the request line, returning (method, target-with-query).
pub fn parse_request_line(head: &[u8]) -> (String, String) {
    let head = String::from_utf8_lossy(head);
    let mut parts = head.lines().next().unwrap_or("").split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let target = parts.next().unwrap_or("").to_string();
    (method, target)
}

/// Read the Host header value from an HTTP request head.
pub fn host_header(head: &[u8]) -> String {
    let head = String::from_utf8_lossy(head);
    for line in head.lines().skip(1) {
        if let Some((k, v)) = line.split_once(':') {
            if k.eq_ignore_ascii_case("host") {
                return v.trim().to_string();
            }
        }
    }
    String::new()
}

fn content_length_of(head: &[u8]) -> usize {
    let head = String::from_utf8_lossy(head);
    for line in head.lines().skip(1) {
        if let Some((k, v)) = line.split_once(':') {
            if k.eq_ignore_ascii_case("content-length") {
                if let Ok(n) = v.trim().parse() {
                    return n;
                }
            }
        }
    }
    0
}

/// Read the remaining POST body (per Content-Length).
pub async fn read_http_body(stream: &mut TlsStream<TcpStream>, head: &[u8]) -> Result<Vec<u8>> {
    let total = content_length_of(head);
    if total == 0 {
        return Ok(Vec::new());
    }
    let mut body = Vec::with_capacity(total);
    let mut tmp = [0u8; 4096];
    while body.len() < total {
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&tmp[..n]);
    }
    body.truncate(total);
    Ok(body)
}

/// Serve a DoH request: hosts-configured names resolve to 127.0.0.1,
/// everything else is forwarded verbatim to the upstream DoH server.
pub async fn handle_doh(stream: &mut TlsStream<TcpStream>, method: &str, target: &str, body: &[u8]) {
    let wire: Vec<u8> = if method.eq_ignore_ascii_case("GET") {
        let dns_param = target
            .split_once('?')
            .map(|(_, q)| {
                q.split('&')
                    .find_map(|kv| kv.strip_prefix("dns=").map(ToString::to_string))
                    .unwrap_or_default()
            })
            .unwrap_or_default();
        match base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(dns_param.trim()) {
            Ok(b) => b,
            Err(_) => {
                let resp = http_response("400 Bad Request", b"");
                let _ = stream.write_all(&resp).await;
                return;
            }
        }
    } else if method.eq_ignore_ascii_case("POST") {
        body.to_vec()
    } else {
        let resp = http_response("405 Method Not Allowed", b"");
        let _ = stream.write_all(&resp).await;
        return;
    };

    let name = parse_question(&wire)
        .map(|(n, _, _)| n)
        .unwrap_or_default();
    debug!("DoH 查询: {} ({} bytes)", name, wire.len());

    let resp_body = if !name.is_empty() && has(&name) {
        match build_local_response(&wire) {
            Some(r) => r,
            None => Vec::new(),
        }
    } else {
        match forward_upstream(&wire).await {
            Ok(b) => b,
            Err(e) => {
                warn!("DoH 上游转发失败 ({}): {}", name, e);
                Vec::new()
            }
        }
    };

    let resp = http_response("200 OK", &resp_body);
    let _ = stream.write_all(&resp).await;
}
