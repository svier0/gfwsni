mod cert;
mod config;
mod dns;
mod hosts;
mod proxy;

use std::net::IpAddr;
use std::path::Path;
use std::io::{Seek, Write};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use anyhow::anyhow;
use log::{debug, error, info};
use rustls::server::Acceptor;
use rustls::ServerConfig;
use std::sync::atomic::{AtomicBool, Ordering};
use tauri::menu::{CheckMenuItem, MenuItem, MenuBuilder, MenuItemBuilder, PredefinedMenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{Manager, WebviewWindowBuilder};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio_rustls::LazyConfigAcceptor;
pub static DIAL_TIMEOUT: OnceLock<Duration> = OnceLock::new();
pub static CERT_EXPIRE: OnceLock<time::Duration> = OnceLock::new();

const DATA_DIR: &str = "data";
const CA_CERT_PATH: &str = "data/ca.crt";
const CA_KEY_PATH: &str = "data/ca.key";
const HOSTS_PATH: &str = "data/hosts.txt";

static QUIT_FLAG: AtomicBool = AtomicBool::new(false);
static LIGHT_MODE: AtomicBool = AtomicBool::new(false);
static LIGHT_CLOSE: AtomicBool = AtomicBool::new(false);
static LIGHT_ITEM: OnceLock<CheckMenuItem<tauri::Wry>> = OnceLock::new();
static PROXY_TOGGLE_ITEM: OnceLock<MenuItem<tauri::Wry>> = OnceLock::new();
static PROXY_RUNNING: AtomicBool = AtomicBool::new(false);
static PROXY_STOP: std::sync::Mutex<Option<watch::Sender<bool>>> = std::sync::Mutex::new(None);

#[tauri::command]
fn get_config() -> config::AppConfig {
    config::all()
}

#[tauri::command]
fn set_config(key: String, value: bool) -> Result<(), String> {
    match key.as_str() {
        "AUTOSTART" | "AUTO_RUN" | "SILENT_LAUNCH" => {
            config::set_bool(&key, value).map_err(|e| e.to_string())?;
            if key == "AUTOSTART" {
                if let Err(e) = set_autostart(value) {
                    return Err(e.to_string());
                }
            }
            Ok(())
        }
        _ => Err(format!("未知配置项: {key}")),
    }
}

#[tauri::command]
fn get_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

#[tauri::command]
fn get_logs() -> String {
    std::fs::read_to_string(dns::path_of("data/gfwsni.log")).unwrap_or_default()
}

#[tauri::command]
fn get_proxy_status() -> bool {
    PROXY_RUNNING.load(Ordering::SeqCst)
}

#[tauri::command]
fn set_proxy_status(app: tauri::AppHandle, running: bool) -> bool {
    if running {
        if !PROXY_RUNNING.load(Ordering::SeqCst) {
            start_proxy(&app);
        }
    } else {
        stop_proxy();
    }
    PROXY_RUNNING.load(Ordering::SeqCst)
}

#[tauri::command]
async fn reset_rules() -> Result<(), String> {
    dns::force_download().await.map_err(|e| e.to_string())
}

#[tauri::command]
fn reset_cert() -> Result<(), String> {
    let ca_cert = dns::path_of(CA_CERT_PATH);
    let ca_key = dns::path_of(CA_KEY_PATH);

    // 确保 data 目录存在
    if let Some(parent) = ca_cert.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("创建目录失败: {e}"))?;
    }

    // 删除旧证书文件
    let _ = std::fs::remove_file(&ca_cert);
    let _ = std::fs::remove_file(&ca_key);

    // 卸载系统旧证书（忽略错误，可能不存在）
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        let _ = std::process::Command::new("certutil")
            .creation_flags(CREATE_NO_WINDOW)
            .args(["-delstore", "Root", "gfwsni CA (auto-generated)"])
            .output();
    }

    let cert_path = ca_cert.to_str().ok_or("证书路径包含非法字符")?;
    let key_path = ca_key.to_str().ok_or("密钥路径包含非法字符")?;

    // 生成新证书文件
    cert::generate_ca(cert_path, key_path)
        .map_err(|e| {
            let msg = format!("生成 CA 证书失败: {e}");
            error!("{msg}");
            msg
        })?;

    // 安装新证书到系统信任库
    install_ca(cert_path);

    // 更新内存中的 CA
    cert::reset(cert_path, key_path)
        .map_err(|e| {
            let msg = format!("重载 CA 证书失败: {e}");
            error!("{msg}");
            msg
        })?;

    info!("CA 证书已重置");
    Ok(())
}

pub fn run() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            get_config,
            set_config,
            get_version,
            get_logs,
            get_proxy_status,
            set_proxy_status,
            reset_rules,
            reset_cert
        ])
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                if LIGHT_CLOSE.swap(false, Ordering::SeqCst) {
                    return;
                }
                api.prevent_close();
                let _ = window.hide();
            }
        })
        .setup(|app| {
            init_logger();
            check_admin();
            config::load()?;

            // 崩溃/重启系统后残留的系统 hosts 标记块，启动即清理
            hosts::cleanup_stale();

            // 开机自启：启动文件夹快捷方式（参考 FrpcTray，不碰注册表）
            if config::autostart() {
                let _ = set_autostart(true);
            }

            // 自动运行：开机自启时自动启动代理（参考 FrpcTray auto_run）
            if config::auto_run() {
                let app_handle = app.handle().clone();
                tauri::async_runtime::spawn(async move {
                    start_proxy(&app_handle);
                });
            }

            let show = MenuItemBuilder::with_id("show", "显示主界面").build(app)?;
            let toggle = MenuItemBuilder::with_id("toggle", "启动").build(app)?;
            let _ = PROXY_TOGGLE_ITEM.set(toggle.clone());
            let light = CheckMenuItem::with_id(app, "light", "轻量模式", true, false, None::<&str>)?;
            let _ = LIGHT_ITEM.set(light.clone());
            let quit = MenuItemBuilder::with_id("quit", "退出").build(app)?;

            // 静默启动：配置开启则只留托盘不建窗口（参考 FrpcTray silent_launch）
            let silent = config::silent_launch();
            LIGHT_MODE.store(silent, Ordering::SeqCst);
            if let Some(item) = LIGHT_ITEM.get() {
                let _ = item.set_checked(silent);
            }
            if !silent {
                build_main_window(app.handle())?;
            }

            let menu = MenuBuilder::new(app)
                .item(&show)
                .item(&PredefinedMenuItem::separator(app)?)
                .item(&toggle)
                .item(&PredefinedMenuItem::separator(app)?)
                .item(&light)
                .item(&PredefinedMenuItem::separator(app)?)
                .item(&quit)
                .build()?;

            let tray = TrayIconBuilder::new()
                .icon(app.default_window_icon().unwrap().clone())
                .show_menu_on_left_click(false)
                .on_tray_icon_event(|tray, event| {
                    if let TrayIconEvent::Click {
                        button: MouseButton::Left,
                        button_state: MouseButtonState::Up,
                        ..
                    } = event
                    {
                        show_or_create_window(tray.app_handle());
                    }
                })
                .menu(&menu)
                .on_menu_event(|app, event| match event.id.as_ref() {
                    "show" => show_or_create_window(app),
                    "toggle" => {
                        if PROXY_RUNNING.load(Ordering::SeqCst) {
                            stop_proxy();
                        } else {
                            start_proxy(app);
                        }
                    }
                    "light" => {
                        let is_light = !LIGHT_MODE.load(Ordering::SeqCst);
                        LIGHT_MODE.store(is_light, Ordering::SeqCst);
                        if let Some(item) = LIGHT_ITEM.get() {
                            let _ = item.set_checked(is_light);
                        }
                        if is_light {
                            if let Some(w) = app.get_webview_window("main") {
                                LIGHT_CLOSE.store(true, Ordering::SeqCst);
                                let _ = w.close();
                            }
                        } else {
                            show_or_create_window(app);
                        }
                    }
                    "quit" => {
                        QUIT_FLAG.store(true, Ordering::SeqCst);
                        if PROXY_RUNNING.load(Ordering::SeqCst) {
                            stop_proxy();
                            if let Err(e) = hosts::restore() {
                                error!("退出时恢复系统 hosts 失败: {:#}", e);
                            }
                        }
                        app.exit(0);
                    }
                    _ => {}
                })
                .build(app)?;

            // 托盘必须保持存活，否则应用会在托盘图标创建后立即退出
            app.manage(TrayState { _tray: tray });

            // 周期性刷新菜单按钮文本，保证菜单打开时反映真实运行状态
            tauri::async_runtime::spawn(async {
                loop {
                    refresh_toggle_text();
                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                }
            });

            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("error while building tauri application")
        .run(|_app_handle, event| {
            if let tauri::RunEvent::ExitRequested { api, .. } = event {
                if !QUIT_FLAG.load(Ordering::SeqCst) {
                    api.prevent_exit();
                }
            }
        });
}

/// 创建主窗口：先隐藏，等 webview 页面加载完成后（on_page_load）再显示，避免白屏闪烁。
fn build_main_window(app: &tauri::AppHandle) -> tauri::Result<()> {
    WebviewWindowBuilder::new(app, "main", tauri::WebviewUrl::App("index.html".into()))
        .title("gfwsni")
        .inner_size(800.0, 540.0)
        .center()
        .visible(false)
        .background_color(tauri::window::Color(0x22, 0x22, 0x22, 0xFF))
        .on_page_load(|webview, payload| {
            if payload.event() == tauri::webview::PageLoadEvent::Finished {
                let _ = webview.show();
                let _ = webview.set_focus();
            }
        })
        .build()?;
    Ok(())
}

fn show_or_create_window(app: &tauri::AppHandle) {
    if LIGHT_MODE.swap(false, Ordering::SeqCst) {
        if let Some(item) = LIGHT_ITEM.get() {
            let _ = item.set_checked(false);
        }
    }
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.show();
        let _ = w.set_focus();
    } else {
        let _ = build_main_window(app);
    }
}

struct TrayState {
    _tray: tauri::tray::TrayIcon<tauri::Wry>,
}

/// 依据 PROXY_RUNNING 真实状态刷新菜单按钮文本。
fn refresh_toggle_text() {
    let running = PROXY_RUNNING.load(Ordering::SeqCst);
    set_toggle_text(if running { "停止" } else { "启动" });
}

fn set_toggle_text(text: &str) {
    let text = text.to_string();
    tauri::async_runtime::spawn(async move {
        if let Some(item) = PROXY_TOGGLE_ITEM.get() {
            let _ = item.set_text(text);
        }
    });
}

fn start_proxy(app: &tauri::AppHandle) {
    if PROXY_RUNNING.swap(true, Ordering::SeqCst) {
        return;
    }
    clear_log();
    let (tx, rx) = watch::channel(false);
    *PROXY_STOP.lock().unwrap() = Some(tx);

    refresh_toggle_text();

    let handle = app.clone();
    tauri::async_runtime::spawn(async move {
        let result = async_run(rx).await;
        if let Err(e) = &result {
            error!("代理逻辑退出: {:?}", e);
            // 出错退出前也恢复系统 hosts，避免残留
            if let Err(re) = hosts::restore() {
                error!("出错退出时恢复系统 hosts 失败: {:#}", re);
            }
        }
        PROXY_RUNNING.store(false, Ordering::SeqCst);
        refresh_toggle_text();
        if result.is_err() {
            QUIT_FLAG.store(true, Ordering::SeqCst);
            handle.exit(1);
        }
    });
}

fn stop_proxy() {
    if !PROXY_RUNNING.load(Ordering::SeqCst) {
        return;
    }
    if let Some(tx) = PROXY_STOP.lock().unwrap().as_ref() {
        let _ = tx.send(true);
    }
}

async fn async_run(stop: watch::Receiver<bool>) -> anyhow::Result<()> {
    ensure_init()?;

    if !dns::path_of(HOSTS_PATH).exists() {
        info!("未找到 data/hosts.txt，正在从远端下载一次...");
        dns::refresh().await?;
    } else {
        info!("使用已有的 data/hosts.txt");
    }
    dns::load_from_file()?;
    hosts::apply()?;

    let address = config::address();
    if let Ok(ip) = address.parse::<IpAddr>() {
        tokio::spawn(listen(ip, stop.clone()));
    } else {
        let ips = tokio::net::lookup_host((address.clone(), 443)).await?;
        for ip in ips {
            tokio::spawn(listen(ip.ip(), stop.clone()));
        }
    }

    let mut stop = stop;
    loop {
        if *stop.borrow() {
            break;
        }
        let _ = stop.changed().await;
        if *stop.borrow() {
            break;
        }
    }
    info!("正在停止代理");
    hosts::restore()?;
    Ok(())
}

static INIT_DONE: OnceLock<Result<(), String>> = OnceLock::new();

fn ensure_init() -> anyhow::Result<()> {
    INIT_DONE
        .get_or_init(|| {
            (|| -> anyhow::Result<()> {
                rustls::crypto::ring::default_provider()
                    .install_default()
                    .map_err(|_| anyhow!("failed to install default crypto provider"))?;

                DIAL_TIMEOUT
                    .set(Duration::from_secs(config::dial_timeout_secs()))
                    .unwrap();
                CERT_EXPIRE
                    .set(time::Duration::seconds(config::cert_expire_secs() as i64))
                    .unwrap();

                if !Path::new(DATA_DIR).exists() {
                    std::fs::create_dir_all(dns::path_of(DATA_DIR))?;
                }

                let ca_cert = dns::path_of(CA_CERT_PATH);
                let ca_key = dns::path_of(CA_KEY_PATH);
                if !ca_cert.exists() || !ca_key.exists() {
                    cert::generate_ca(
                        ca_cert.to_str().unwrap(),
                        ca_key.to_str().unwrap(),
                    )?;
                } else {
                    info!("使用已有的 CA 证书: {}", ca_cert.display());
                }
                install_ca(ca_cert.to_str().unwrap());

                cert::init(ca_cert.to_str().unwrap(), ca_key.to_str().unwrap())?;
                dns::init(config::hosts_url())?;
                proxy::init();
                Ok(())
            })()
            .map_err(|e: anyhow::Error| format!("{e:#}"))
        })
        .clone()
        .map_err(anyhow::Error::msg)
}

struct LogFileWriter(std::sync::Arc<std::sync::Mutex<std::fs::File>>);

impl std::io::Write for LogFileWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut f = self.0.lock().unwrap();
        f.write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        let mut f = self.0.lock().unwrap();
        f.flush()
    }
}

static LOG_FILE: std::sync::OnceLock<std::sync::Arc<std::sync::Mutex<std::fs::File>>> =
    std::sync::OnceLock::new();

fn init_logger() {
    let path = dns::path_of("data/gfwsni.log");
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&path)
        .unwrap_or_else(|e| panic!("无法打开日志文件 {}: {e}", path.display()));
    let shared = std::sync::Arc::new(std::sync::Mutex::new(file));
    let _ = LOG_FILE.set(shared.clone());
    env_logger::Builder::new()
        .filter_level(log::LevelFilter::Info)
        .target(env_logger::Target::Pipe(Box::new(LogFileWriter(shared))))
        .format(|buf, record| {
            let ts = time::OffsetDateTime::now_local()
                .unwrap_or_else(|_| time::OffsetDateTime::now_utc());
            let fmt = time::format_description::parse_borrowed::<1>(
                "[year]-[month]-[day] [hour]:[minute]:[second]",
            )
            .unwrap();
            let ts = ts.format(&fmt).unwrap_or_default();
            writeln!(buf, "[{} {}] {}", ts, record.level(), record.args())
        })
        .init();
    info!("日志文件: {}", path.display());
}

/// 清空日志文件，让代理本次运行从头开始记录。
fn clear_log() {
    if let Some(shared) = LOG_FILE.get() {
        let mut f = shared.lock().unwrap();
        let _ = f.set_len(0);
        let _ = f.seek(std::io::SeekFrom::Start(0));
        let _ = f.flush();
    }
}

async fn listen(ip: IpAddr, mut stop: watch::Receiver<bool>) {
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
        tokio::select! {
            _ = stop.changed() => {
                if *stop.borrow() {
                    info!("已停止监听 {}:443", ip);
                    return;
                }
            }
            res = listener.accept() => {
                match res {
                    Ok((stream, _)) => {
                        tokio::spawn(handle_conn(stream));
                    }
                    Err(e) => error!("accept 错误: {}", e),
                }
            }
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

fn check_admin() {
    #[cfg(windows)]
    {
        use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
        use windows_sys::Win32::Security::{
            GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
        };
        use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
        use windows_sys::Win32::UI::WindowsAndMessaging::{MessageBoxW, MB_ICONWARNING, MB_OK};

        fn msg(text: &str) {
            let title: Vec<u16> = "gfwsni".encode_utf16().chain(std::iter::once(0)).collect();
            let wide: Vec<u16> = text.encode_utf16().chain(std::iter::once(0)).collect();
            unsafe {
                MessageBoxW(
                    std::ptr::null_mut(),
                    wide.as_ptr(),
                    title.as_ptr(),
                    MB_OK | MB_ICONWARNING,
                );
            }
        }

        let mut token: HANDLE = std::ptr::null_mut();
        let ok = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) };
        if ok == 0 {
            msg("无法检测管理员权限，请以管理员身份运行本程序。");
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
            msg("本程序需要管理员权限，请以管理员身份运行。");
            std::process::exit(1);
        }
    }
}

// 开机自启：启动文件夹快捷方式（参考 FrpcTray，不碰注册表）。
// 路径: %APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\gfwsni.lnk
#[cfg(windows)]
fn startup_shortcut_path() -> std::path::PathBuf {
    let appdata = std::env::var("APPDATA")
        .unwrap_or_else(|_| r"C:\Users\Default\AppData\Roaming".to_string());
    std::path::PathBuf::from(appdata)
        .join(r"Microsoft\Windows\Start Menu\Programs\Startup")
        .join("gfwsni.lnk")
}

#[cfg(not(windows))]
fn startup_shortcut_path() -> std::path::PathBuf {
    std::path::PathBuf::new()
}

/// 是否已启用开机自启（快捷方式存在即视为启用）。
pub fn is_autostart_enabled() -> bool {
    #[cfg(windows)]
    {
        startup_shortcut_path().exists()
    }
    #[cfg(not(windows))]
    {
        false
    }
}

/// 设置开机自启：创建/删除启动文件夹快捷方式。
pub fn set_autostart(enabled: bool) -> anyhow::Result<()> {
    #[cfg(windows)]
    {
        let path = startup_shortcut_path();
        if enabled {
            let exe = std::env::current_exe().map_err(|e| anyhow!("无法获取程序路径: {e}"))?;
            let ps = format!(
                "$s=(New-Object -ComObject WScript.Shell).CreateShortcut('{}');$s.TargetPath='{}';$s.Save()",
                path.display(),
                exe.display()
            );
            let mut cmd = std::process::Command::new("powershell");
            cmd.args(["-NoProfile", "-Command", &ps]);
            use std::os::windows::process::CommandExt;
            cmd.creation_flags(0x08000000); // CREATE_NO_WINDOW
            let out = cmd.output().map_err(|e| anyhow!("创建快捷方式失败: {e}"))?;
            if !out.status.success() {
                return Err(anyhow!(
                    "创建快捷方式失败: {}",
                    String::from_utf8_lossy(&out.stderr)
                ));
            }
            info!("已创建开机自启快捷方式: {}", path.display());
        } else if path.exists() {
            std::fs::remove_file(&path).map_err(|e| anyhow!("删除快捷方式失败: {e}"))?;
            info!("已删除开机自启快捷方式");
        }
        Ok(())
    }
    #[cfg(not(windows))]
    {
        let _ = enabled;
        Err(anyhow!("当前平台不支持开机自启"))
    }
}

fn install_ca(cert_path: &str) {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        // 先按 CN 删除旧的自动生成 CA，避免每次重新生成后系统信任库累积无用证书
        let _ = std::process::Command::new("certutil")
            .creation_flags(CREATE_NO_WINDOW)
            .args(["-delstore", "Root", "gfwsni CA (auto-generated)"])
            .output();
        let output = std::process::Command::new("certutil")
            .creation_flags(CREATE_NO_WINDOW)
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
