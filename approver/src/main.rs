#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

//! agent-ssh 桌面审批端（T-17.5c）：Tauri 2 窗口 + RPC 桥 + 托盘 + 自启。
//!
//! 架构：RPC 客户端跑在 tauri async_runtime；Host 推送（approval.pending/
//! settled）经 AppHandle.emit 转发窗口；窗口决定经 invoke('decide') 回桥。
//! operator 会话：UI 口令表单 → invoke('unlock') → 内部 start 换会话令牌
//! （内存态，K8-⑦ Zeroizing）；agent 令牌连接仅用于只读面（ping/manifest）。

use approver::hostproc::{self, HostDeployment, HostEvent};
use approver::rpc::RpcClient;
use serde_json::Value;
use std::sync::Arc;
#[cfg(windows)]
use std::os::windows::process::CommandExt;
use tauri::{AppHandle, Emitter, Manager, State};
use tauri_plugin_notification::NotificationExt;
use tokio::sync::Mutex;

/// 待决审批数（T-17.5d 验收 1）：pending +1／settled 或本地 decide −1；
/// 托盘 tooltip 同步「N 条待审」。
#[derive(Default)]
struct PendingCounter(Mutex<usize>);

/// Host 守护子进程 pid（T-20）：Some=本应用托管中；None=未托管（外部起）。
struct HostProc(Mutex<Option<u32>>);

/// Host 状态文案（supervisor 写，托盘/推送回调读）。
struct HostStatusText(Mutex<String>);

/// Host 日志文件路径（stderr 行追加；「打开日志」菜单目标）。
fn host_log_path() -> std::path::PathBuf {
    hostproc::appdata_ssh_mcp_base().join("ssh-mcp").join("host-daemon.log")
}

async fn append_host_log(line: &str) {
    use std::io::Write;
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(host_log_path())
    {
        let _ = writeln!(f, "{}", line);
    }
}

/// 托盘 tooltip 承载 Host 状态 + 待审数（T-20）。
async fn refresh_tray(app: &AppHandle) {
    let status = app.state::<HostStatusText>().0.lock().await.clone();
    let n = *app.state::<PendingCounter>().0.lock().await;
    let pending = if n == 0 { "无待审".to_string() } else { format!("{n} 条待审") };
    let label = format!("agent-ssh（Host {status} · {pending}）");
    if let Some(tray) = app.tray_by_id("main-tray") {
        let _ = tray.set_tooltip(Some(label));
    }
}

/// Host 状态写入 + 托盘刷新（单入口，避免文案漂移）。
async fn set_host_status(app: &AppHandle, status: &str) {
    *app.state::<HostStatusText>().0.lock().await = status.to_string();
    refresh_tray(app).await;
}

struct HostState {
    addr: String,
    /// agent 只读连接（ping/manifest）。
    agent_client: Mutex<Option<Arc<RpcClient>>>,
    /// operator 会话连接（解锁后建立，订阅+decide）。
    operator_client: Mutex<Option<Arc<RpcClient>>>,
    token: Arc<String>,
    pin: Option<String>,
}

fn err_str(e: impl std::fmt::Display) -> String {
    e.to_string()
}

#[tauri::command]
async fn ping(state: State<'_, HostState>) -> Result<Value, String> {
    let guard = state.agent_client.lock().await;
    let client = guard.as_ref().ok_or_else(|| err_str("not connected"))?;
    client.ping().await.map_err(err_str)
}

/// 口令→会话（operator 引导）：skipHello 连接 start → 会话令牌建正式连接并订阅。
#[tauri::command]
async fn unlock(
    app: AppHandle,
    state: State<'_, HostState>,
    password: String,
) -> Result<Value, String> {
    let pre = RpcClient::connect_no_hello(&state.addr).await;
    let started = pre
        .call(
            "auth.session.start",
            serde_json::json!({ "password": password }),
        )
        .await
        .map_err(err_str)?;
    pre.close().await;
    let session_token = started
        .get("sessionToken")
        .and_then(|v| v.as_str())
        .ok_or_else(|| err_str("auth.session.start: missing sessionToken"))?
        .to_string();

    let operator = Arc::new(RpcClient::connect(&state.addr, &session_token).await);
    // 订阅并把推送转发到窗口（K8-③：数据经 event 进 UI，秘密不落 JS 全局）。
    // T-17.5d：pending/settled 同步托盘未决数+原生 toast（验收 1/2）。
    let emitter = app.clone();
    let operator_for_push = operator.clone();
    operator
        .set_notification_handler(Arc::new(move |frame: Value| {
            if let Some(method) = frame.get("method").and_then(|v| v.as_str()) {
                // Tauri 事件名不允许点号（listen 会被拒）——映射为连字符形态。
                let is_pending = method == "approval.pending";
                let event_name = match method {
                    "approval.pending" => "approval-pending",
                    "approval.settled" => "approval-settled",
                    _ => return,
                };
                let payload = frame.get("params").cloned().unwrap_or(Value::Null);
                // 未决数与托盘/通知：pending +1 + toast；settled −1。
                let app2 = emitter.clone();
                tauri::async_runtime::spawn(async move {
                    {
                        let counter = app2.state::<PendingCounter>();
                        let mut n = counter.0.lock().await;
                        if is_pending { *n += 1; } else { *n = n.saturating_sub(1); }
                    }
                    refresh_tray(&app2).await;
                    if is_pending {
                        let _ = app2.notification().builder()
                            .title("agent-ssh 审批请求")
                            .body("有新的命令等待人工审批，请打开审批窗。")
                            .show();
                    }
                });
                let _ = emitter.emit(event_name, payload);
            }
        }))
        .await;
    operator.subscribe_approvals().await.map_err(err_str)?;
    *state.operator_client.lock().await = Some(operator.clone());

    Ok(json_ok(true))
}

fn json_ok(v: bool) -> Value {
    serde_json::json!({ "ok": v })
}

#[tauri::command]
async fn decide(
    app: AppHandle,
    state: State<'_, HostState>,
    id: String,
    decision: String,
    face: String,
    challenge: Option<String>,
) -> Result<Value, String> {
    let guard = state.operator_client.lock().await;
    let client = guard.as_ref().ok_or_else(|| err_str("not unlocked"))?;
    let by = format!("desktop:{}", std::env::var("USERNAME").unwrap_or_default());
    match client
        .decide_approval(&id, &decision, &by, challenge.as_deref())
        .await
    {
        Ok(v) => {
            // 本地决定成功：未决数 −1 并刷新托盘（settled 推送也会到达，双路径幂等）。
            {
                let counter = app.state::<PendingCounter>();
                let mut n = counter.0.lock().await;
                *n = n.saturating_sub(1);
            }
            refresh_tray(&app).await;
            Ok(v)
        }
        Err(e) => {
            let msg = err_str(&e);
            // 锁屏回锁（T-17.5d 验收 3）：会话过期/失效（-32001）→ 清内存会话
            // → 窗口回解锁态（locked 事件，UI 显示口令表单）。
            if msg.contains("-32001") || msg.to_lowercase().contains("session") {
                drop(guard);
                *state.operator_client.lock().await = None;
                let _ = app.emit("locked", serde_json::json!({ "reason": "session expired" }));
                return Err("locked: session expired — unlock again".to_string());
            }
            Err(msg)
        }
    }
}

/// 历史审批（T-21b）：经 operator 会话转发 Host approval.history（分页）。
#[tauri::command]
async fn history(
    state: State<'_, HostState>,
    offset: Option<i64>,
    limit: Option<i64>,
) -> Result<Value, String> {
    let guard = state.operator_client.lock().await;
    let client = guard.as_ref().ok_or_else(|| err_str("not unlocked"))?;
    let params = serde_json::json!({
        "offset": offset.unwrap_or(0),
        "limit": limit.unwrap_or(50),
    });
    client.call("approval.history", params).await.map_err(err_str)
}

/// 审计查询/统计/连接/配额（T-21c/d）：operator 会话转发 Host 运维 RPC。
#[tauri::command]
async fn audit_query(
    state: State<'_, HostState>,
    offset_tail: Option<i64>,
    limit: Option<i64>,
    profile: Option<String>,
    command_class: Option<String>,
    decision: Option<String>,
    rule_id: Option<String>,
    keyword: Option<String>,
) -> Result<Value, String> {
    let guard = state.operator_client.lock().await;
    let client = guard.as_ref().ok_or_else(|| err_str("not unlocked"))?;
    let filter = serde_json::json!({
        "profile": profile, "commandClass": command_class,
        "decision": decision, "ruleId": rule_id, "keyword": keyword,
    });
    let params = serde_json::json!({
        "offsetTail": offset_tail.unwrap_or(0), "limit": limit.unwrap_or(50), "filter": filter,
    });
    client.call("audit.query", params).await.map_err(err_str)
}

#[tauri::command]
async fn audit_stats(state: State<'_, HostState>) -> Result<Value, String> {
    let guard = state.operator_client.lock().await;
    let client = guard.as_ref().ok_or_else(|| err_str("not unlocked"))?;
    client.call("audit.stats", Value::Null).await.map_err(err_str)
}

#[tauri::command]
async fn connections(state: State<'_, HostState>) -> Result<Value, String> {
    let guard = state.operator_client.lock().await;
    let client = guard.as_ref().ok_or_else(|| err_str("not unlocked"))?;
    client.call("host.connections", Value::Null).await.map_err(err_str)
}

#[tauri::command]
async fn quota_snapshot(state: State<'_, HostState>) -> Result<Value, String> {
    let guard = state.operator_client.lock().await;
    let client = guard.as_ref().ok_or_else(|| err_str("not unlocked"))?;
    client.call("quota.snapshot", Value::Null).await.map_err(err_str)
}

/// 开机自启状态（T-21e 设置页）。
#[tauri::command]
async fn autostart_status(app: AppHandle) -> Result<Value, String> {
    use tauri_plugin_autostart::ManagerExt;
    let enabled = app.autolaunch().is_enabled().map_err(err_str)?;
    Ok(serde_json::json!({ "enabled": enabled }))
}

/// 开关开机自启（T-21e 设置页 toggle）。
#[tauri::command]
async fn autostart_set(app: AppHandle, enable: bool) -> Result<Value, String> {
    use tauri_plugin_autostart::ManagerExt;
    let launcher = app.autolaunch();
    if enable {
        launcher.enable().map_err(err_str)?;
    } else {
        launcher.disable().map_err(err_str)?;
    }
    let enabled = launcher.is_enabled().map_err(err_str)?;
    Ok(serde_json::json!({ "enabled": enabled }))
}

/// Host 重启（设置页按钮）：杀托管子进程，supervisor 退避链自动拉新。
#[tauri::command]
async fn restart_host(app: AppHandle) -> Result<Value, String> {
    let pid = *app.state::<HostProc>().0.lock().await;
    if let Some(pid) = pid {
        let _ = std::process::Command::new("taskkill")
            .args(["/PID", &pid.to_string(), "/T", "/F"])
            .creation_flags(0x0800_0000)
            .output();
        return Ok(serde_json::json!({ "restarting": true, "pid": pid }));
    }
    Ok(serde_json::json!({ "restarting": false, "reason": "not managed by this app" }))
}

/// 打开 Host 日志（设置页按钮）。
#[tauri::command]
async fn open_host_log() -> Result<Value, String> {
    std::process::Command::new("notepad.exe")
        .arg(host_log_path())
        .creation_flags(0x0800_0000)
        .spawn()
        .map_err(err_str)?;
    Ok(serde_json::json!({ "ok": true }))
}

/// 更换 operator 口令（T-21e）：转发 Host host.admin.changePassword。
#[tauri::command]
async fn change_password(
    state: State<'_, HostState>,
    old_password: String,
    new_password: String,
) -> Result<Value, String> {
    let guard = state.operator_client.lock().await;
    let client = guard.as_ref().ok_or_else(|| err_str("not unlocked"))?;
    client
        .call("host.admin.changePassword", serde_json::json!({ "oldPassword": old_password, "newPassword": new_password }))
        .await
        .map_err(err_str)
}

/// 审批面状态/版本聚合（T-21e 设置页）：operator 会话转发 host.status。
#[tauri::command]
async fn host_status(state: State<'_, HostState>) -> Result<Value, String> {
    let guard = state.operator_client.lock().await;
    let client = guard.as_ref().ok_or_else(|| err_str("not unlocked"))?;
    client.call("host.status", Value::Null).await.map_err(err_str)
}

/// 本机宿主识别（T-21g 设置页）：operator 会话转发 agents.scan。
#[tauri::command]
async fn agents_scan(state: State<'_, HostState>) -> Result<Value, String> {
    let guard = state.operator_client.lock().await;
    let client = guard.as_ref().ok_or_else(|| err_str("not unlocked"))?;
    client.call("agents.scan", Value::Null).await.map_err(err_str)
}

/// 宿主接入写入（T-21g）：operator 会话转发 agents.configure。
#[tauri::command]
async fn agents_configure(state: State<'_, HostState>, id: String) -> Result<Value, String> {
    let guard = state.operator_client.lock().await;
    let client = guard.as_ref().ok_or_else(|| err_str("not unlocked"))?;
    client
        .call("agents.configure", serde_json::json!({ "id": id }))
        .await
        .map_err(err_str)
}

/// 宿主条目移除（T-21g）：operator 会话转发 agents.remove。
#[tauri::command]
async fn agents_remove(state: State<'_, HostState>, id: String) -> Result<Value, String> {
    let guard = state.operator_client.lock().await;
    let client = guard.as_ref().ok_or_else(|| err_str("not unlocked"))?;
    client
        .call("agents.remove", serde_json::json!({ "id": id }))
        .await
        .map_err(err_str)
}

/// 主机清单（T-22 主机管理）：operator 会话转发 host.profiles.list。
#[tauri::command]
async fn profiles_list(state: State<'_, HostState>) -> Result<Value, String> {
    let guard = state.operator_client.lock().await;
    let client = guard.as_ref().ok_or_else(|| err_str("not unlocked"))?;
    client.call("host.profiles.list", Value::Null).await.map_err(err_str)
}

/// 主机新增/编辑（T-22）：转发 host.profiles.upsert（密码经 Host 写凭据管理器）。
#[tauri::command]
async fn profiles_upsert(
    state: State<'_, HostState>,
    profile: Value,
) -> Result<Value, String> {
    let guard = state.operator_client.lock().await;
    let client = guard.as_ref().ok_or_else(|| err_str("not unlocked"))?;
    client.call("host.profiles.upsert", profile).await.map_err(err_str)
}

/// 主机删除（T-22）：转发 host.profiles.remove。
#[tauri::command]
async fn profiles_remove(state: State<'_, HostState>, name: String) -> Result<Value, String> {
    let guard = state.operator_client.lock().await;
    let client = guard.as_ref().ok_or_else(|| err_str("not unlocked"))?;
    client
        .call("host.profiles.remove", serde_json::json!({ "name": name }))
        .await
        .map_err(err_str)
}

#[tauri::command]
async fn list_pending(state: State<'_, HostState>) -> Result<Value, String> {
    let guard = state.operator_client.lock().await;
    let client = guard.as_ref().ok_or_else(|| err_str("not unlocked"))?;
    client.call("approval.list", Value::Null).await.map_err(err_str)
}

/// 托盘 tooltip 承载 Host 状态 + 待审数（T-20）。
async fn refresh_tray_status(app: &AppHandle, host_status: &str) {
    *app.state::<HostStatusText>().0.lock().await = host_status.to_string();
    refresh_tray(app).await;
}

/// Host 托管监督循环（T-20）：拉起→探活→等待退出→退避重启，直至 stop 信号。
/// pid 记入 HostProc 供 quit 停机链使用。
async fn run_host_supervisor(app: AppHandle, dep: HostDeployment, stop: Arc<std::sync::atomic::AtomicBool>) {
    use std::sync::atomic::Ordering;
    let backoff = [3u64, 6, 12, 24, 30];
    let mut attempt = 0usize;
    loop {
        if stop.load(Ordering::SeqCst) { return; }
        refresh_tray_status(&app, "启动中…").await;
        let mut child = match hostproc::spawn_host(&dep).await {
            Ok(c) => c,
            Err(e) => {
                refresh_tray_status(&app, "拉起失败").await;
                append_host_log(&format!("[supervisor] spawn failed: {e}")).await;
                tokio::time::sleep(std::time::Duration::from_secs(backoff[attempt.min(4)])).await;
                attempt += 1;
                continue;
            }
        };
        *app.state::<HostProc>().0.lock().await = child.id();
        if let Some(stderr) = child.stderr.take() {
            let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
            tauri::async_runtime::spawn(hostproc::pump_stderr(stderr, tx));
            let log_app = app.clone();
            tauri::async_runtime::spawn(async move {
                while let Some(ev) = rx.recv().await {
                    if let HostEvent::Log(line) = ev { append_host_log(&line).await; }
                    let _ = log_app; // 日志面只需落盘
                }
            });
        }
        // 就绪探测：TCP 最多 20s（就绪行解析留作 hostproc 单测口径）。
        let mut ready = false;
        for _ in 0..40 {
            if hostproc::probe(&dep.addr()).await { ready = true; break; }
            if stop.load(Ordering::SeqCst) { break; }
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }
        if ready {
            attempt = 0;
            refresh_tray_status(&app, &format!("运行中 :{}", dep.port)).await;
        }
        let outcome = child.wait().await;
        *app.state::<HostProc>().0.lock().await = None;
        append_host_log(&format!("[supervisor] host exited: {:?}", outcome.map(|s| s.code()))).await;
        if stop.load(Ordering::SeqCst) { return; }
        refresh_tray_status(&app, if ready { "已停止（重启中）" } else { "无响应（重启中）" }).await;
        tokio::time::sleep(std::time::Duration::from_secs(backoff[attempt.min(4)])).await;
        if ready { attempt += 1; }
    }
}

fn main() {
    // 部署描述优先（desktop.json）；解析失败落日志再回退 env-only 模式
    //（仅连接、不托管）——静默回退曾让"为什么没托管"无从诊断（T-20 实测）。
    let deployment = match HostDeployment::load() {
        Ok(d) => Some(d),
        Err(e) => {
            let line = format!("[desktop] deployment load failed, env-only fallback: {e}");
            eprintln!("{line}");
            let _ = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(host_log_path())
                .and_then(|mut f| {
                    use std::io::Write;
                    writeln!(f, "{line}")
                });
            None
        }
    };
    let (host_addr, token) = match &deployment {
        Some(d) => (d.addr(), d.token.clone()),
        None => (
            std::env::var("AGENT_SSH_HOST_ADDR").unwrap_or_else(|_| "127.0.0.1:9443".to_string()),
            std::env::var("AGENT_SSH_TOKEN").unwrap_or_default(),
        ),
    };
    let pin = std::env::var("AGENT_SSH_HOST_PIN").ok().filter(|s| !s.is_empty());
    let stop_flag = Arc::new(std::sync::atomic::AtomicBool::new(false));

    tauri::Builder::default()
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_autostart::init(
            tauri_plugin_autostart::MacosLauncher::LaunchAgent,
            None,
        ))
        .manage(PendingCounter::default())
        .manage(HostProc(Mutex::new(None)))
        .manage(HostStatusText(Mutex::new("未托管".to_string())))
        .manage(HostState {
            addr: host_addr.clone(),
            agent_client: Mutex::new(None),
            operator_client: Mutex::new(None),
            token: Arc::new(token.clone()),
            pin: pin.clone(),
        })
.setup(move |app| {
    use tauri::menu::{Menu, MenuItem};
    use tauri::tray::TrayIconBuilder;
    // 托盘（T-17.5c 验收 1 + T-20 控制台化）：审批窗/重启 Host/打开日志/退出。
    let show = MenuItem::with_id(app, "show", "显示审批窗", true, None::<&str>)?;
    let restart = MenuItem::with_id(app, "restart-host", "重启 Host", true, None::<&str>)?;
    let open_log = MenuItem::with_id(app, "open-log", "打开 Host 日志", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "退出（停 Host）", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&show, &restart, &open_log, &quit])?;
    TrayIconBuilder::with_id("main-tray")
        .icon(app.default_window_icon().unwrap().clone())
        .menu(&menu)
        .on_menu_event(|app, event| {
            let id = event.id.as_ref();
            if id == "quit" {
                // 停机链（T-20）：置 stop → 杀子进程树 → supervisor 归位 → 退出。
                let app = app.clone();
                tauri::async_runtime::spawn(async move {
                    let pid = *app.state::<HostProc>().0.lock().await;
                    if let Some(pid) = pid {
                        let _ = std::process::Command::new("taskkill")
                            .args(["/PID", &pid.to_string(), "/T", "/F"])
                            .creation_flags(0x0800_0000)
                            .output();
                    }
                    app.exit(0);
                });
            } else if id == "show" {
                if let Some(win) = app.get_webview_window("main") {
                    let _ = win.show();
                    let _ = win.set_focus();
                }
            } else if id == "open-log" {
                let _ = std::process::Command::new("notepad.exe")
                    .arg(host_log_path())
                    .creation_flags(0x0800_0000)
                    .spawn();
            } else if id == "restart-host" {
                // 直接杀：supervisor 探到退出后按既定链重启（attempt 归零于就绪）。
                let app = app.clone();
                tauri::async_runtime::spawn(async move {
                    let pid = *app.state::<HostProc>().0.lock().await;
                    if let Some(pid) = pid {
                        let _ = std::process::Command::new("taskkill")
                            .args(["/PID", &pid.to_string(), "/T", "/F"])
                            .creation_flags(0x0800_0000)
                            .output();
                    }
                });
            }
        })
        .build(app)?;
    // 自启（验收 2）：插件默认关，运维经设置开关。
    let _ = tauri_plugin_autostart::ManagerExt::autolaunch(app).disable();
    let handle = app.handle().clone();
    let addr = host_addr.clone();
    let rpc_token = token.clone();
    // T-20：部署描述在场即托管拉起 Host（H6 结构性关闭——应用自启即 Host 在）。
    if let Some(dep) = deployment.clone() {
        let sup_app = handle.clone();
        let sup_stop = stop_flag.clone();
        tauri::async_runtime::spawn(async move {
            run_host_supervisor(sup_app, dep, sup_stop).await;
        });
    } else {
        let nh = handle.clone();
        tauri::async_runtime::spawn(async move {
            set_host_status(&nh, "未托管（desktop.json 缺席）").await;
        });
    }
    tauri::async_runtime::spawn(async move {
        // agent 只读连接：断线 3s 重试（常驻语义）。Host 未就绪时 connect
        // 失败由循环自然重试——日志噪音可接受（诊断面即托盘状态）。
        loop {
            let c = RpcClient::connect(&addr, &rpc_token).await;
            *handle.state::<HostState>().agent_client.lock().await = Some(Arc::new(c));
            tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        }
    });
    Ok(())
    })
    .invoke_handler(tauri::generate_handler![ping, unlock, decide, list_pending, history, audit_query, audit_stats, connections, quota_snapshot, autostart_status, autostart_set, restart_host, open_host_log, change_password, host_status, agents_scan, agents_configure, agents_remove, profiles_list, profiles_upsert, profiles_remove])
    .run(tauri::generate_context!())
    .expect("error while running tauri application");
}