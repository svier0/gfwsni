const invoke = window.__TAURI__.core.invoke;

const pages = {
  general: "page-general",
  logs: "page-logs",
  about: "page-about",
};

const menuItems = document.querySelectorAll(".menu-item");

menuItems.forEach((item) => {
  item.addEventListener("click", () => {
    const page = item.dataset.page;
    if (!pages[page]) return;

    menuItems.forEach((i) => i.classList.remove("active"));
    item.classList.add("active");

    Object.entries(pages).forEach(([key, id]) => {
      document.getElementById(id).hidden = key !== page;
    });
  });
});

const switchMap = [
  { id: "switch-autostart", key: "AUTOSTART" },
  { id: "switch-auto-run", key: "AUTO_RUN" },
  { id: "switch-silent-launch", key: "SILENT_LAUNCH" },
];

async function loadConfig() {
  try {
    const cfg = await invoke("get_config");
    switchMap.forEach(({ id, key }) => {
      const el = document.getElementById(id);
      if (el) el.checked = !!cfg[key];
    });
  } catch (e) {
    console.error("读取配置失败:", e);
  }
}

async function loadVersion() {
  try {
    const version = await invoke("get_version");
    const el = document.querySelector(".about-version");
    if (el) el.textContent = "v" + version;
  } catch (e) {
    console.error("读取版本失败:", e);
  }
}

switchMap.forEach(({ id, key }) => {
  const el = document.getElementById(id);
  if (!el) return;
  el.addEventListener("change", async () => {
    try {
      await invoke("set_config", { key, value: el.checked });
    } catch (e) {
      console.error(`写入配置 ${key} 失败:`, e);
      el.checked = !el.checked;
    }
  });
});

loadConfig();
loadVersion();

const proxySwitch = document.getElementById("switch-proxy");

async function refreshProxyStatus() {
  try {
    const running = await invoke("get_proxy_status");
    if (proxySwitch) proxySwitch.checked = running;
  } catch (e) {
    console.error("读取代理状态失败:", e);
  }
}

if (proxySwitch) {
  let proxyLocked = false;
  proxySwitch.addEventListener("change", async () => {
    if (proxyLocked) {
      proxySwitch.checked = !proxySwitch.checked;
      return;
    }
    proxyLocked = true;
    proxySwitch.disabled = true;
    try {
      await invoke("set_proxy_status", { running: proxySwitch.checked });
    } catch (e) {
      console.error("切换代理状态失败:", e);
      refreshProxyStatus();
    } finally {
      setTimeout(() => {
        proxyLocked = false;
        proxySwitch.disabled = false;
      }, 1000);
    }
  });
}

refreshProxyStatus();
setInterval(refreshProxyStatus, 1000);

const resetBtn = document.getElementById("btn-reset-rules");

if (resetBtn) {
  resetBtn.addEventListener("click", async () => {
    if (resetBtn.disabled) return;
    resetBtn.disabled = true;
    resetBtn.textContent = "下载中...";
    try {
      await invoke("reset_rules");
      resetBtn.textContent = "完成";
    } catch (e) {
      console.error("下载规则失败:", e);
      resetBtn.textContent = "失败";
    } finally {
      setTimeout(() => {
        resetBtn.disabled = false;
        resetBtn.textContent = "立即下载";
      }, 1500);
    }
  });
}

const resetCertBtn = document.getElementById("btn-reset-cert");

if (resetCertBtn) {
  resetCertBtn.addEventListener("click", async () => {
    if (resetCertBtn.disabled) return;
    resetCertBtn.disabled = true;
    resetCertBtn.textContent = "重装中...";
    try {
      await invoke("reset_cert");
      resetCertBtn.textContent = "完成";
    } catch (e) {
      console.error("重装证书失败:", e);
      resetCertBtn.textContent = "失败";
    } finally {
      setTimeout(() => {
        resetCertBtn.disabled = false;
        resetCertBtn.textContent = "重装证书";
      }, 1500);
    }
  });
}

const logsContent = document.getElementById("logs-content");

async function refreshLogs() {
  try {
    const logs = await invoke("get_logs");
    if (logsContent) {
      logsContent.textContent = logs || "暂无日志";
      logsContent.scrollTop = logsContent.scrollHeight;
    }
  } catch (e) {
    console.error("读取日志失败:", e);
  }
}

document.querySelector('.menu-item[data-page="logs"]').addEventListener("click", () => {
  refreshLogs();
});
