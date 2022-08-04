use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock, RwLock};

use anyhow::{Context, Result};
use log::{debug, error, warn};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::client::TlsStream;
use tokio_rustls::server::TlsStream as ServerTlsStream;

use crate::{cert, dns, DIAL_TIMEOUT};

static RESOLV_CACHE: OnceLock<Arc<RwLock<HashMap<String, String>>>> = OnceLock::new();
static RESOLV_LOCKS: OnceLock<Arc<Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>>> =
    OnceLock::new();

pub fn init() {
    RESOLV_CACHE.set(Arc::new(RwLock::new(HashMap::new()))).unwrap();
    RESOLV_LOCKS.set(Arc::new(Mutex::new(HashMap::new()))).unwrap();
}

pub fn needs_proxy(domain: &str) -> bool {
    if dns::has(domain) {
        return true;
    }
    let secondary = match cert::effective_tld_plus_one(domain) {
        Some(s) => s,
        None => {
            error!("主机名无效: {}", domain);
            return false;
        }
    };
    let mut d = domain.to_string();
    while d != secondary {
        let dot = d.find('.').unwrap_or(0);
        d = d[dot + 1..].to_string();
        if dns::has(&d) {
            return true;
        }
    }
    false
}

pub async fn resolve_real_ip(host: &str) -> Vec<String> {
    dns::resolve_real_ip(host)
}

async fn dial_target(addr: &str, host: &str) -> Result<TlsStream<TcpStream>> {
    let tcp = timeout(*DIAL_TIMEOUT.get().unwrap(), TcpStream::connect(addr)).await??;
    let ip = addr
        .rsplit_once(':')
        .map(|(ip, _)| ip)
        .unwrap_or(addr)
        .trim_start_matches('[')
        .trim_end_matches(']');
    let server_name = rustls::pki_types::ServerName::IpAddress(
        ip.parse::<std::net::IpAddr>()
            .context("invalid target ip")?
            .into(),
    );
    let connector = dns::config_for_host(host)?;
    let stream = timeout(*DIAL_TIMEOUT.get().unwrap(), connector.connect(server_name, tcp))
        .await??;
    Ok(stream)
}

pub async fn forward_tls(
    mut stream: ServerTlsStream<TcpStream>,
    host: String,
    initial: Vec<u8>,
) {
    if !needs_proxy(&host) {
        error!("{} 无需代理", host);
        return;
    }
    debug!("代理 {}", host);

    let lock = {
        let mut map = RESOLV_LOCKS.get().unwrap().lock().unwrap();
        map.entry(host.clone())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone()
    };
    let _guard = lock.lock().await;

    let cached = RESOLV_CACHE.get().unwrap().read().unwrap().get(&host).cloned();
    let mut conn = None;
    if let Some(addr) = cached {
        match dial_target(&addr, &host).await {
            Ok(c) => conn = Some(c),
            Err(e) => debug!("连接缓存地址 {} ({}) 失败: {}", host, addr, e),
        }
    }

    if conn.is_none() {
        let addrs = resolve_real_ip(&host).await;
        if addrs.is_empty() {
            warn!("{} 解析失败: hosts 中无该域名", host);
            return;
        }
        for addr in &addrs {
            match dial_target(addr, &host).await {
                Ok(c) => {
                    RESOLV_CACHE.get().unwrap().write().unwrap().insert(host.clone(), addr.clone());
                    conn = Some(c);
                    break;
                }
                Err(e) => warn!("连接目标 {} ({}) 失败: {}", host, addr, e),
            }
        }
        if conn.is_none() {
            warn!("无法访问 {} ({})", host, addrs.join(", "));
            return;
        }
    }

    drop(_guard);
    let mut conn = conn.unwrap();
    if !initial.is_empty() {
        let _ = conn.write_all(&initial).await;
    }
    let _ = tokio::io::copy_bidirectional(&mut stream, &mut conn).await;
}
