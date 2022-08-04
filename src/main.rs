mod cert;
mod dns;
mod proxy;

use std::net::IpAddr;
use std::path::Path;
use std::io::Write;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use anyhow::anyhow;
use log::{debug, error, info};
use rustls::server::Acceptor;
use rustls::ServerConfig;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::LazyConfigAcceptor;
pub static DIAL_TIMEOUT: OnceLock<Duration> = OnceLock::new();
pub static CERT_EXPIRE: OnceLock<time::Duration> = OnceLock::new();

const HOSTS_URL: &str = "https://gh-proxy.com/https://github.com/svier0/gfwsni/releases/download/0/hosts";
const ADDRESS: &str = "localhost";
const DIAL_TIMEOUT_SECS: u64 = 5;
const CERT_EXPIRE_SECS: u64 = 2000 * 3600;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    check_admin();

    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| anyhow!("failed to install default crypto provider"))?;

    init_logger();

    DIAL_TIMEOUT.set(Duration::from_secs(DIAL_TIMEOUT_SECS)).unwrap();
    CERT_EXPIRE
        .set(time::Duration::seconds(CERT_EXPIRE_SECS as i64))
        .unwrap();

    if !Path::new("ca.crt").exists() || !Path::new("ca.key").exists() {
        cert::generate_ca("ca.crt", "ca.key")?;
    } else {
        info!("使用已有的 CA 证书: ca.crt / ca.key");
    }
    install_ca("ca.crt");

    cert::init("ca.crt", "ca.key")?;
    dns::init(HOSTS_URL.to_string())?;
    proxy::init();

    if !Path::new("hosts.txt").exists() {
        info!("未找到 hosts.txt，正在从远端下载一次...");
        dns::refresh().await?;
    } else {
        info!("使用已有的 hosts.txt");
    }
    dns::load_from_file()?;

    if let Ok(ip) = ADDRESS.parse::<IpAddr>() {
        tokio::spawn(listen(ip));
    } else {
        let ips = tokio::net::lookup_host((ADDRESS, 443)).await?;
        for ip in ips {
            tokio::spawn(listen(ip.ip()));
        }
    }

    tokio::signal::ctrl_c().await?;
    info!("正在退出");
    Ok(())
}

fn init_logger() {
    env_logger::Builder::new()
        .filter_level(log::LevelFilter::Info)
        .format(|buf, record| {
            let ts = time::OffsetDateTime::now_local()
                .unwrap_or_else(|_| time::OffsetDateTime::now_utc());
            let fmt = time::format_description::parse_borrowed::<1>(
                "[year]-[month]-[day] [hour]:[minute]:[second]",
            )
            .unwrap();
            let ts = ts.format(&fmt).unwrap_or_default();
            let style = buf.default_level_style(record.level());
            write!(buf, "[{} ", ts)?;
            style.write_to(buf)?;
            write!(buf, "{}", record.level())?;
            style.write_reset_to(buf)?;
            writeln!(buf, " {}] {}", record.target(), record.args())
        })
        .init();
}

async fn listen(ip: IpAddr) {
    let bind_addr = std::net::SocketAddr::new(ip, 443);
    let listener = match TcpListener::bind(bind_addr).await {
        Ok(l) => l,
        Err(e) => {
            error!("监听 {} 失败: {}", bind_addr, e);
            return;
        }
    };
    info!("正在监听 {}:443...", ip);
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                tokio::spawn(handle_conn(stream));
            }
            Err(e) => error!("accept 错误: {}", e),
        }
    }
}

async fn handle_conn(tcp: TcpStream) {
    let acceptor = LazyConfigAcceptor::new(Acceptor::default(), tcp);
    tokio::pin!(acceptor);

    let start = match acceptor.as_mut().await {
        Ok(s) => s,
        Err(e) => {
            debug!("TLS 握手失败: {}", e);
            return;
        }
    };

    let host = {
        let hello = start.client_hello();
        hello.server_name().unwrap_or("").to_string()
    };

    // 证书仍按 SNI 签发：域名给域名证书，IP/无 SNI 给 127.0.0.1 证书。
    let config = if host.is_empty() || host.parse::<IpAddr>().is_ok() {
        match cert::doh_server_config() {
            Ok(c) => c,
            Err(e) => {
                debug!("DoH 配置失败: {}", e);
                return;
            }
        }
    } else {
        match build_server_config(&host) {
            Ok(c) => c,
            Err(e) => {
                debug!("签发证书失败 ({}): {}", host, e);
                return;
            }
        }
    };

    let mut stream = match start.into_stream(config).await {
        Ok(s) => s,
        Err(e) => {
            debug!("TLS 握手失败 ({}): {}", host, e);
            return;
        }
    };

    // 分流看 HTTP 请求：Host 是本机且 path 是 /dns-query 就是 DoH，否则代理。
    let head = match dns::read_http_head(&mut stream).await {
        Ok(h) => h,
        Err(e) => {
            debug!("读取 HTTP 请求失败: {}", e);
            return;
        }
    };
    let (method, target) = dns::parse_request_line(&head);
    let http_host = dns::host_header(&head);
    let is_doh_host = http_host.is_empty() || http_host == "127.0.0.1" || http_host == "localhost";

    if is_doh_host && target.starts_with("/dns-query") {
        let body = match dns::read_http_body(&mut stream, &head).await {
            Ok(b) => b,
            Err(e) => {
                debug!("读取 DoH body 失败: {}", e);
                return;
            }
        };
        dns::handle_doh(&mut stream, &method, &target, &body).await;
    } else {
        proxy::forward_tls(stream, host, head).await;
    }
}

fn build_server_config(host: &str) -> anyhow::Result<Arc<ServerConfig>> {
    let leaf = cert::get_certificate(host)?;
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(leaf.certs.clone(), leaf.key_der.clone_key())?;
    Ok(Arc::new(config))
}

fn check_admin() {    #[cfg(windows)]
    {
        use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
        use windows_sys::Win32::Security::{
            GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
        };
        use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

        let mut token: HANDLE = std::ptr::null_mut();
        let ok = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) };
        if ok == 0 {
            eprintln!("failed to check elevation, run as administrator");
            std::process::exit(1);
        }
        let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut size = std::mem::size_of::<TOKEN_ELEVATION>() as u32;
        let ok = unsafe {
            GetTokenInformation(
                token,
                TokenElevation,
                &mut elevation as *mut _ as *mut _,
                size,
                &mut size,
            )
        };
        unsafe { CloseHandle(token) };
        if ok == 0 || elevation.TokenIsElevated == 0 {
            eprintln!("This program must be run as administrator.");
            std::process::exit(1);
        }
    }
}

fn install_ca(cert_path: &str) {
    #[cfg(windows)]
    {
        let output = std::process::Command::new("certutil")
            .args(["-addstore", "-f", "Root", cert_path])
            .output();
        match output {
            Ok(out) if out.status.success() => {
info!("CA 已安装到系统受信任根证书存储");
        }
        Ok(out) => {
            error!(
                "CA 安装失败: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        Err(e) => error!("运行 certutil 失败: {}", e),
        }
    }
}
