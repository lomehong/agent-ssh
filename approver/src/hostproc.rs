//! Host 守护子进程托管（T-20：Host 桌面化）。
//!
//! 桌面应用是 Host 的宿主外壳：启动即拉起 `host serve` 子进程（部署描述
//! desktop.json），就绪探测通过后其余面（RPC/审批）才启动；崩溃按退避自动
//! 重启；应用退出随行停掉子进程树。Host 代码零改动——被托管的仍是
//! `node <build>/index.js host serve --port=<port>`。
//!
//! desktop.json（%APPDATA%\ssh-mcp\desktop.json，0600）是本机部署的单一
//! 事实源：nodePath / hostEntry / configPath / port / token。start-host.cmd
//! 与本模块同源读取，令牌不再多手抄。

use std::path::PathBuf;
use std::process::Stdio;
use tokio::io::AsyncBufReadExt;
use tokio::process::{Child, Command};
use tokio::sync::mpsc;

#[derive(Clone, Debug)]
pub struct HostDeployment {
    pub node_path: String,
    pub host_entry: String,
    pub config_path: String,
    pub port: u16,
    pub token: String,
}

impl HostDeployment {
    /// 读部署描述；缺省值即本机默认部署（%APPDATA%\ssh-mcp）。
    pub fn load() -> Result<Self, String> {
        let base = dirs_appdata().join("ssh-mcp");
        let path = base.join("desktop.json");
        let raw = std::fs::read_to_string(&path)
            .map_err(|e| format!("desktop.json unreadable ({}): {}", path.display(), e))?;
        let v: serde_json::Value = serde_json::from_str(&raw)
            .map_err(|e| format!("desktop.json parse: {}", e))?;
        let get = |k: &str| -> Result<String, String> {
            v.get(k)
                .and_then(|x| x.as_str())
                .map(|s| s.to_string())
                .ok_or_else(|| format!("desktop.json missing key: {}", k))
        };
        // port 兼容数字与字符串两种 JSON 形态（本机部署文件为数字——
        // 曾因只按字符串取而静默回退 env-only 模式，T-20 实测修正）。
        let port = match v.get("port") {
            Some(serde_json::Value::Number(n)) => n.as_u64().ok_or("desktop.json port out of range")? as u16,
            other => other
                .and_then(|x| x.as_str())
                .map(|s| s.to_string())
                .ok_or_else(|| "desktop.json missing key: port".to_string())?
                .parse()
                .map_err(|_| "desktop.json port invalid")?,
        };
        Ok(Self {
            node_path: get("nodePath")?,
            host_entry: get("hostEntry")?,
            config_path: get("configPath")?,
            port,
            token: get("token")?,
        })
    }

    pub fn addr(&self) -> String {
        format!("127.0.0.1:{}", self.port)
    }
}

fn dirs_appdata() -> PathBuf {
    appdata_ssh_mcp_base()
}

/// %APPDATA%（与 TS 侧 loader 的 win32 分支同语义）——main.rs 日志路径复用。
pub fn appdata_ssh_mcp_base() -> PathBuf {
    std::env::var_os("APPDATA")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("USERPROFILE").map(|h| PathBuf::from(h).join("AppData").join("Roaming")))
        .unwrap_or_else(|| PathBuf::from("."))
}

pub enum HostEvent {
    /// stderr 行（原样，供日志窗口/诊断）。
    Log(String),
    /// host-rpc-ready 解析到（就绪）。
    Ready(u16),
    /// 子进程退出（码）。
    Exited(Option<i32>),
}

/// 拉起 Host 子进程；stderr 行经 channel 回传（调用方决定落盘/转发）。
pub async fn spawn_host(dep: &HostDeployment) -> Result<Child, String> {
    Command::new(&dep.node_path)
        .args([
            &dep.host_entry,
            "host",
            "serve",
            &format!("--port={}", dep.port),
            &format!("--config={}", dep.config_path),
        ])
        .env("AGENT_SSH_TOKEN", &dep.token)
        // windows_hide 防控制台窗闪烁；stdin 关（守护语义：EOF 不退出）。
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .creation_flags(0x0800_0000) // CREATE_NO_WINDOW
        .spawn()
        .map_err(|e| format!("spawn host failed: {}", e))
}

/// 泵 stderr 流（调用方先 `child.stderr.take()`）：ready 行发 Ready 事件
/// （调用方据此落日志），其余原样发 Log。
pub async fn pump_stderr(
    stderr: impl tokio::io::AsyncRead + Unpin,
    tx: mpsc::UnboundedSender<HostEvent>,
) {
    let mut lines = tokio::io::BufReader::new(stderr).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        let event = if let Some(port) = parse_ready(&line) {
            HostEvent::Ready(port)
        } else {
            HostEvent::Log(line.clone())
        };
        if tx.send(event).is_err() {
            break;
        }
    }
}

fn parse_ready(line: &str) -> Option<u16> {
    line.split_whitespace()
        .find_map(|t| t.strip_prefix("port="))
        .and_then(|p| p.parse().ok())
}

/// TCP 探活（就绪/重启后的确认面；单次，调用方控制节奏）。
pub async fn probe(addr: &str) -> bool {
    tokio::net::TcpStream::connect(addr).await.is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ready_extracts_port() {
        assert_eq!(
            parse_ready("host-rpc-ready port=7788 (pidfile C:/x/host.pid)"),
            Some(7788)
        );
        assert_eq!(parse_ready("no port here"), None);
        assert_eq!(parse_ready("port=abc"), None);
    }

    #[test]
    fn deployment_addr_formats() {
        let d = HostDeployment {
            node_path: "node".into(),
            host_entry: "index.js".into(),
            config_path: "c.toml".into(),
            port: 7788,
            token: "t".into(),
        };
        assert_eq!(d.addr(), "127.0.0.1:7788");
    }
}

#[cfg(test)]
mod load_tests {
    use super::*;

    #[test]
    fn loads_real_desktop_json() {
        // 本机部署文件（存在时）必须可加载——port 数字形态回归（T-20 实测）。
        let path = appdata_ssh_mcp_base().join("ssh-mcp").join("desktop.json");
        if !path.exists() { return; }
        let dep = HostDeployment::load().expect("desktop.json should load");
        assert_eq!(dep.port, 7788);
        assert!(dep.token.len() >= 32);
    }
}
