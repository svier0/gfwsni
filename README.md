# gfwsni

本地 443 端口 MITM 中间人代理，通过改写 SNI / hosts 绕过基于 SNI 的域名封锁，实现对 **github、pixiv** 等「被墙但未被封 IP」网站的直接访问。

不需要额外设置浏览器/系统代理，启动后即接管相关域名的 443 流量，对应用完全透明。

## 系统要求

- Windows 10 / 11（64 位）
- 管理员权限（首次运行会触发 UAC 提权提示）

## 安装

### 方式一：Release 二进制安装包

从 [GitHub Releases](https://github.com/svier0/gfwsni/releases) 下载最新版安装包：

- `gfwsni_<版本>_x64-setup.exe` — NSIS 安装程序，双击安装即可

### 方式二：Scoop 安装

```powershell
scoop bucket add svier0 https://gh-proxy/https://github.com/svier0/scoopbucket
scoop install GFWSNI
```

> 如果本机尚未安装 Scoop，先执行：
> ```powershell
> Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
> irm https://ghfast.top/https://raw.githubusercontent.com/svier0/scoop-ghproxy/master/fastinstall.ps1 | iex
> ```

## 使用

1. **启动程序**：以管理员身份运行 gfwsni（托盘图标出现即代表已启动）
2. **运行代理服务**：主界面「常规设置」→ 打开「运行服务」开关，或托盘菜单点「启动」
3. **访问被墙网站**：直接访问 github.com、pixiv.net 等即可，无需配置任何代理

## 常见问题

**访问网站提示证书不受信任？**
进入主界面「常规设置」→「重置证书」重新安装 CA 证书，或在「运行日志」页查看错误详情。

**打开程序提示需要管理员权限？**
程序必须管理员运行。请右键 exe →「以管理员身份运行」；安装包自带 UAC 清单，正常安装后双击即可。

**如何完全卸载？**
1. 托盘菜单「退出」，确认系统 hosts 已恢复
2. 删除安装目录（含 `data/` 文件夹）
3. （可选）`certutil -delstore Root "gfwsni CA (auto-generated)"` 删除已安装的 CA 证书

## 工作原理

1. 将目标域名解析记录写入系统 hosts，指向 `127.0.0.1`
2. 程序在 `127.0.0.1:443` 监听 TLS 连接，按客户端发来的 SNI 动态签发对应域名证书
3. 与真实服务器建立连接时**不发送 SNI 扩展**，从而绕过 SNI 过滤；同时按真实主机名校验服务器证书，保证安全
4. 访问结束后自动恢复系统 hosts 原样，不留残留

> 注意：因为涉及修改系统 hosts、安装根证书、监听 443 端口，**必须使用管理员权限运行**。

## 免责声明

本项目仅用于学习与科研用途，请遵守所在地区的法律法规，勿用于非法用途。
