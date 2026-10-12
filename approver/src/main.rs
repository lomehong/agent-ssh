#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

//! agent-ssh 桌面审批端（T-17.5c）：Tauri 2 窗口 + RPC 桥 + 托盘 + 自启。
//!
//! 架构：RPC 客户端跑在 tauri async_runtime；Host 推送（approval.pending/
//! settled）经 AppHandle.emit 转发窗口；窗口决定经 invoke('decide') 回桥。
//! operator 会话：UI 口令表单 → invoke('unlock') → 内部 start 换会话令牌
//! （内存态，K8-⑦ Zeroizing）；agent 令牌连接仅用于只读面（ping/manifest）。

use approver::rpc::RpcClient;
use serde_json::Value;
use std::sync::Arc;
use tauri::{AppHandle, Emitter, Manager, State};
use tauri_plugin_notification::NotificationExt;
use tokio::sync::Mutex;

/// 待决审批数（T-17.5d 验收 1）：pending +1／settled 或本地 decide −1；
/// 托盘 tooltip 同步「N 条待审」。
#[derive(Default)]
struct PendingCounter(Mutex<usize>);

struct HostState {
    addr: String,
    /// agent 只读连接（ping/manifest）。
    agent_client: Mutex<Option<Arc<RpcClient>>>,
    /// operator 会话连接（解锁后建立，订阅+decide）。
    operator_client: Mutex<Option<Arc<RpcClient>>>,
    token: Arc<String>,
    pin: Option<String>,
}

async fn refresh_tray(app: &AppHandle) {
    let state = app.state::<PendingCounter>();
    let n = *state.0.lock().await;
    let label = if n == 0 { "agent-ssh 审批（无待审）".to_string() } else { format!("agent-ssh 审批（{n} 条待审）") };
    if let Some(tray) = app.tray_by_id("main-tray") {
        let _ = tray.set_tooltip(Some(label));
    }
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
                let event_name = match method {
                    "approval.pending" => "approval.pending",
                    "approval.settled" => "approval.settled",
                    _ => return,
                };
                let payload = frame.get("params").cloned().unwrap_or(Value::Null);
                // 未决数与托盘/通知：pending +1 + toast；settled −1。
                let app2 = emitter.clone();
                tauri::async_runtime::spawn(async move {
                    {
                        let counter = app2.state::<PendingCounter>();
                        let mut n = counter.0.lock().await;
                        if event_name == "approval.pending" { *n += 1; } else { *n = n.saturating_sub(1); }
                    }
                    refresh_tray(&app2).await;
                    if event_name == "approval.pending" {
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

#[tauri::command]
async fn list_pending(state: State<'_, HostState>) -> Result<Value, String> {
    let guard = state.operator_client.lock().await;
    let client = guard.as_ref().ok_or_else(|| err_str("not unlocked"))?;
    client.call("approval.list", Value::Null).await.map_err(err_str)
}

fn main() {
    let host_addr =
        std::env::var("AGENT_SSH_HOST_ADDR").unwrap_or_else(|_| "127.0.0.1:9443".to_string());
    let token = std::env::var("AGENT_SSH_TOKEN").unwrap_or_default();
    let pin = std::env::var("AGENT_SSH_HOST_PIN").ok().filter(|s| !s.is_empty());

    tauri::Builder::default()
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_autostart::init(
            tauri_plugin_autostart::MacosLauncher::LaunchAgent,
            None,
        ))
        .manage(PendingCounter::default())
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
    // 托盘（T-17.5c 验收 1）：常驻图标+菜单。未决数/IM 面离线随 T-17.6 接线。
    let show = MenuItem::with_id(app, "show", "显示审批窗", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "退出", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&show, &quit])?;
    TrayIconBuilder::with_id("main-tray")
        .icon(app.default_window_icon().unwrap().clone())
        .menu(&menu)
        .on_menu_event(|app, event| {
            if event.id.as_ref() == "quit" {
                app.exit(0);
            } else if event.id.as_ref() == "show" {
                if let Some(win) = app.get_webview_window("main") {
                    let _ = win.show();
                    let _ = win.set_focus();
                }
            }
        })
        .build(app)?;
    // 自启（验收 2）：插件默认关，运维经设置开关。
    let _ = tauri_plugin_autostart::ManagerExt::autolaunch(app).disable();
    let handle = app.handle().clone();
    let addr = host_addr.clone();
    let token = approver::rpc::fresh_agent_token();
    tauri::async_runtime::spawn(async move {
        // agent 只读连接：断线 3s 重试（常驻语义）。
        loop {
            let c = RpcClient::connect(&addr, &token).await;
            *handle.state::<HostState>().agent_client.lock().await = Some(Arc::new(c));
            tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        }
    });
    Ok(())
    })
    .invoke_handler(tauri::generate_handler![ping, unlock, decide, list_pending])
    .run(tauri::generate_context!())
    .expect("error while running tauri application");
}