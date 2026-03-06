use std::path::PathBuf;

use anyhow::{Context, Result};
use dotenvy::from_path;
use log::{info, warn};

use crate::dns;

/// 配置文件路径（exe 所在目录下 data/app.conf，绝对路径）。
pub const CONFIG_FILE: &str = "data/app.conf";

/// 默认配置模板。文件不存在时生成此内容（纯 ASCII，避免解析问题）。
const DEFAULT_CONFIG: &str = "\
# gfwsni config (UTF-8, ASCII only). Put this file at: <exe dir>/data/app.conf

# hosts download URL
HOSTS_URL=https://gh-proxy.com/https://github.com/svier0/gfwsni/releases/download/0/hosts

# listen address (localhost or concrete IP)
ADDRESS=localhost

# target connection timeout (seconds)
DIAL_TIMEOUT_SECS=5

# certificate validity (seconds)
CERT_EXPIRE_SECS=7200000

# autostart via startup-folder shortcut (no registry writes)
AUTOSTART=false

# auto-run the proxy when the app starts
AUTO_RUN=false

# silent launch: do not create the main window, tray only (default false)
SILENT_LAUNCH=false
";

/// 加载配置。文件不存在时生成默认配置文件；存在但解析失败则报错。
pub fn load() -> Result<()> {
    let path = config_path();
    if !path.exists() {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("创建配置目录 {} 失败", parent.display()))?;
        }
        std::fs::write(&path, DEFAULT_CONFIG)
            .with_context(|| format!("生成配置文件 {} 失败", path.display()))?;
        info!("配置文件不存在，已生成默认配置 {}", path.display());
        return Ok(());
    }
    from_path(&path)
        .with_context(|| format!("解析配置文件 {} 失败", path.display()))?;
    info!("已加载配置文件 {}", path.display());
    Ok(())
}

pub fn config_path() -> PathBuf {
    dns::path_of(CONFIG_FILE)
}

fn get_str(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

fn get_bool(key: &str, default: bool) -> bool {
    match std::env::var(key) {
        Ok(v) => match v.trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => true,
            "0" | "false" | "no" | "off" => false,
            _ => {
                warn!("配置项 {} 取值非法（{}），使用默认 {}", key, v, default);
                default
            }
        },
        Err(_) => default,
    }
}

fn get_u64(key: &str, default: u64) -> u64 {
    match std::env::var(key) {
        Ok(v) => v.trim().parse().unwrap_or_else(|_| {
            warn!("配置项 {} 取值非法（{}），使用默认 {}", key, v, default);
            default
        }),
        Err(_) => default,
    }
}

pub fn hosts_url() -> String {
    get_str(
        "HOSTS_URL",
        "https://gh-proxy.com/https://github.com/svier0/gfwsni/releases/download/0/hosts",
    )
}

pub fn address() -> String {
    get_str("ADDRESS", "localhost")
}

pub fn dial_timeout_secs() -> u64 {
    get_u64("DIAL_TIMEOUT_SECS", 5)
}

pub fn cert_expire_secs() -> u64 {
    get_u64("CERT_EXPIRE_SECS", 2000 * 3600)
}

/// 开机自动运行代理。
pub fn auto_run() -> bool {
    get_bool("AUTO_RUN", false)
}

/// 静默启动：开机自启时不显示主窗口。
pub fn silent_launch() -> bool {
    get_bool("SILENT_LAUNCH", false)
}

/// 开机自启（启动文件夹快捷方式）。
pub fn autostart() -> bool {
    get_bool("AUTOSTART", false)
}

/// 前端展示的完整配置。
#[derive(serde::Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub struct AppConfig {
    pub autostart: bool,
    pub auto_run: bool,
    pub silent_launch: bool,
}

pub fn all() -> AppConfig {
    AppConfig {
        autostart: autostart(),
        auto_run: auto_run(),
        silent_launch: silent_launch(),
    }
}

/// 将布尔配置写回配置文件（仅改对应行，保留其余内容和注释）。
pub fn set_bool(key: &str, value: bool) -> Result<()> {
    let path = config_path();
    let content = std::fs::read_to_string(&path)
        .with_context(|| format!("读取配置文件 {} 失败", path.display()))?;
    let value_str = if value { "true" } else { "false" };
    let mut found = false;
    let mut lines: Vec<String> = content.lines().map(|s| s.to_string()).collect();
    for line in lines.iter_mut() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') {
            continue;
        }
        if let Some(eq) = trimmed.find('=') {
            if trimmed[..eq].trim() == key {
                *line = format!("{key}={value_str}");
                found = true;
                break;
            }
        }
    }
    if !found {
        lines.push(format!("{key}={value_str}"));
    }
    let mut out = lines.join("\n");
    out.push('\n');
    std::fs::write(&path, out)
        .with_context(|| format!("写入配置文件 {} 失败", path.display()))?;
    std::env::set_var(key, value_str);
    info!("已更新配置 {key}={value_str}");
    Ok(())
}
