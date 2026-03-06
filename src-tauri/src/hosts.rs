use std::path::PathBuf;

use anyhow::{Context, Result};
use log::{error, info};

use crate::dns;

const SYS_HOSTS: &str = r"C:\Windows\System32\drivers\etc\hosts";
const BEGIN_MARK: &str = "# === gfwsni begin ===";
const END_MARK: &str = "# === gfwsni end ===";

fn sys_hosts_path() -> PathBuf {
    match std::env::var("SystemRoot") {
        Ok(root) => PathBuf::from(root).join("System32\\drivers\\etc\\hosts"),
        Err(_) => PathBuf::from(SYS_HOSTS),
    }
}

/// 将 hosts 中所有需要代理的域名追加到系统 hosts（指向 127.0.0.1），
/// 用标记块包裹，便于停止时精确恢复。
pub fn apply() -> Result<()> {
    let domains = dns::domains();
    if domains.is_empty() {
        info!("hosts 为空，不修改系统 hosts");
        return Ok(());
    }
    let path = sys_hosts_path();
    let content = std::fs::read_to_string(&path)
        .with_context(|| format!("读取系统 hosts {} 失败", path.display()))?;

    let base = strip_block(&content);

    let mut block = String::new();
    block.push_str(BEGIN_MARK);
    block.push('\n');
    for d in &domains {
        block.push_str("127.0.0.1 ");
        block.push_str(&d);
        block.push('\n');
    }
    block.push_str(END_MARK);
    block.push('\n');

    let new_content = if base.trim().is_empty() {
        block
    } else {
        format!("{}\n{}\n{}", base.trim_end(), block.trim_end(), "")
    };
    std::fs::write(&path, new_content)
        .with_context(|| format!("写入系统 hosts {} 失败", path.display()))?;
    info!("已写入 {} 个域名到系统 hosts {}", domains.len(), path.display());
    Ok(())
}

/// 移除程序写入的标记块，恢复系统 hosts 原样。
pub fn restore() -> Result<()> {
    let path = sys_hosts_path();
    let content = std::fs::read_to_string(&path)
        .with_context(|| format!("读取系统 hosts {} 失败", path.display()))?;
    let cleaned = strip_block(&content);
    if cleaned != content {
        std::fs::write(&path, cleaned)
            .with_context(|| format!("写回系统 hosts {} 失败", path.display()))?;
        info!("已恢复系统 hosts {}", path.display());
    } else {
        info!("系统 hosts 无需恢复 {}", path.display());
    }
    Ok(())
}

/// 删除标记块内的所有行，保留块外内容。
fn strip_block(content: &str) -> String {
    let mut out = String::new();
    let mut in_block = false;
    for line in content.lines() {
        let t = line.trim();
        if t == BEGIN_MARK {
            in_block = true;
            continue;
        }
        if t == END_MARK {
            in_block = false;
            continue;
        }
        if !in_block {
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}

/// 崩溃兜底：启动时清理上次残留的标记块（幂等，restore 同逻辑）。
pub fn cleanup_stale() {
    if let Err(e) = restore() {
        error!("清理系统 hosts 失败: {:#}", e);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_removes_block_only() {
        let content = "127.0.0.1 localhost\n# === gfwsni begin ===\n127.0.0.1 example.com\n# === gfwsni end ===\n127.0.0.1 other.local\n";
        let cleaned = strip_block(content);
        assert!(!cleaned.contains("example.com"));
        assert!(!cleaned.contains("gfwsni"));
        assert!(cleaned.contains("127.0.0.1 localhost"));
        assert!(cleaned.contains("127.0.0.1 other.local"));
    }

    #[test]
    fn strip_without_block_is_unchanged() {
        let content = "127.0.0.1 localhost\n";
        assert_eq!(strip_block(content), content);
    }

    #[test]
    fn apply_restore_roundtrip() {
        let mut base = String::from("127.0.0.1 localhost\n");
        let mut block = String::new();
        block.push_str(BEGIN_MARK);
        block.push('\n');
        block.push_str("127.0.0.1 example.com\n127.0.0.1 foo.org\n");
        block.push_str(END_MARK);
        block.push('\n');
        base.push_str(&block);
        let restored = strip_block(&base);
        assert_eq!(restored, "127.0.0.1 localhost\n");
    }

    /// 真实系统 hosts 写/恢复（需管理员）。运行: cargo test --lib -- --ignored system_hosts_roundtrip
    #[test]
    #[ignore]
    fn system_hosts_roundtrip() {
        use crate::dns;
        let url = String::new();
        dns::init(url).unwrap();
        let _ = dns::load_from_file();
        let applied = apply();
        if let Err(e) = &applied {
            eprintln!("apply error: {:#}", e);
        }
        applied.unwrap();
        let content = std::fs::read_to_string(sys_hosts_path()).unwrap();
        eprintln!("system hosts after apply:\n{}", content);
        assert!(content.contains(BEGIN_MARK), "缺少 begin 标记");
        assert!(
            content.contains("127.0.0.1 steamcommunity.com"),
            "缺少代理域名"
        );
        restore().unwrap();
        let content2 = std::fs::read_to_string(sys_hosts_path()).unwrap();
        assert!(!content2.contains(BEGIN_MARK));
        assert!(!content2.contains("127.0.0.1 steamcommunity.com"));
    }
}
