//! T-17.5b 协议闭环：mock Host（手写 JSON-RPC 应答器）+ approver 客户端
//! 全流程——无凭据引导（skipHello）→口令换会话→会话重连（hello）→订阅→
//! 收携码 pending→错码 decide 被拒→对码 decide 生效。
//!
//! mock Host 校验语义与 host/main.ts 的 decide 桥一致（D10/K8-②）。

use approver::rpc::{RpcClient, RpcError};
use serde_json::{json, Value};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

const CHALLENGE: &str = "4321";

async fn read_frame(reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>) -> Option<Value> {
    let mut line = String::new();
    loop {
        let chunk = reader.fill_buf().await.ok()?;
        if chunk.is_empty() {
            return None;
        }
        if let Some(pos) = chunk.iter().position(|&b| b == b'\n') {
            let tail = &chunk[..pos];
            line.push_str(&String::from_utf8_lossy(tail));
            reader.consume(pos + 1);
            return serde_json::from_str(line.trim_end_matches('\r')).ok();
        }
        line.push_str(&String::from_utf8_lossy(chunk));
        let len = chunk.len();
        reader.consume(len);
    }
}

async fn write_frame(writer: &mut tokio::net::tcp::OwnedWriteHalf, value: &Value) {
    let text = serde_json::to_string(value).unwrap();
    writer.write_all((text + "\n").as_bytes()).await.unwrap();
    writer.flush().await.unwrap();
}

/// mock Host 单连接处理：hello→start→subscribe→decide（携码语义）。
/// push 槽位：subscribe 应答后取走并下发一条携码 pending（每连接至多一次）。
async fn handle_conn(stream: TcpStream, push_slot: Arc<Mutex<Option<Value>>>) {
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);
    let mut subscribed = false;
    while let Some(req) = read_frame(&mut reader).await {
        let method = req.get("method").and_then(|v| v.as_str()).unwrap_or("");
        let id = req.get("id").cloned().unwrap_or(Value::Null);
        let response = match method {
            "host.hello" => json!({
                "jsonrpc": "2.0", "id": id,
                "result": { "protocolVersion": "0.2.0" },
            }),
            "auth.session.start" => json!({
                "jsonrpc": "2.0", "id": id,
                "result": { "sessionToken": "session-from-mock" },
            }),
            "approval.subscribe" => {
                subscribed = true;
                json!({ "jsonrpc": "2.0", "id": id, "result": { "subscribed": true } })
            }
            "approval.decide" => {
                let presented = req
                    .get("params")
                    .and_then(|p| p.get("challenge"))
                    .and_then(|c| c.as_str());
                if presented == Some(CHALLENGE) {
                    json!({
                        "jsonrpc": "2.0", "id": id,
                        "result": { "decided": true, "message": "approved: via mock" },
                    })
                } else {
                    json!({
                        "jsonrpc": "2.0", "id": id,
                        "error": { "code": -32603,
                            "message": "CHALLENGE_REJECTED: challenge mismatch" },
                    })
                }
            }
            _ => json!({
                "jsonrpc": "2.0", "id": id,
                "error": { "code": -32601, "message": "method not found" },
            }),
        };
        write_frame(&mut write_half, &response).await;

        if subscribed {
            let mut slot = push_slot.lock().await;
            if let Some(pending_frame) = slot.take() {
                write_frame(&mut write_half, &pending_frame).await;
            }
        }
    }
}

async fn start_mock_host() -> (String, Arc<Mutex<Option<Value>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().unwrap().to_string();
    let push: Arc<Mutex<Option<Value>>> = Arc::new(Mutex::new(Some(
        json!({
            "jsonrpc": "2.0", "method": "approval.pending",
            "params": { "id": "ap-mock-1", "profile": "admin",
                "command": "rm -rf /tmp/build", "commandClass": "destructive",
                "challenge": CHALLENGE },
        }),
    )));
    let push_for_accept = push.clone();
    tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(v) => v,
                Err(_) => break,
            };
            let push = push_for_accept.clone();
            tokio::spawn(handle_conn(stream, push));
        }
    });
    (addr, push)
}

#[tokio::test]
async fn approval_flow_session_subscribe_challenge_decide() {
    let (addr, _push_slot) = start_mock_host().await;

    // ① 无凭据引导（skipHello）→ 口令换会话。
    let bootstrap = RpcClient::connect_skip_hello(&addr).await;
    let started = bootstrap
        .call("auth.session.start", json!({ "password": "op-pass" }))
        .await
        .expect("start must succeed");
    let session_token = started
        .get("sessionToken")
        .and_then(|v| v.as_str())
        .expect("sessionToken")
        .to_string();
    bootstrap.close().await;

    // ② 会话客户端（走 hello）→ 先注册通知回调再订阅（mock 在订阅应答后立即推 pending）。
    let operator = RpcClient::connect(&addr, &session_token).await;
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Value>();
    let tx_clone = tx.clone();
    operator
        .set_notification_handler(Arc::new(move |frame: Value| {
            let _ = tx_clone.send(frame);
        }))
        .await;
    operator.subscribe_approvals().await.expect("subscribe");

    let pending = rx.recv().await.expect("pending push must arrive");
    assert_eq!(pending.get("method").and_then(|v| v.as_str()), Some("approval.pending"));
    let challenge = pending.pointer("/params/challenge").and_then(|v| v.as_str()).expect("challenge").to_string();
    // ④ 错码 decide → 结构化拒绝。
    let wrong = operator
        .decide_approval("ap-mock-1", "approved", "desktop:tester", Some("0000"))
        .await;
    match wrong {
        Err(RpcError::ServerError { message, .. }) => {
            assert!(message.contains("CHALLENGE_REJECTED"), "{message}");
        }
        other => panic!("wrong challenge must be rejected, got {other:?}"),
    }

    // ⑤ 对码 decide → 生效。
    let outcome = operator
        .decide_approval("ap-mock-1", "approved", "desktop:tester", Some(&challenge))
        .await
        .expect("correct challenge must decide");
    assert_eq!(outcome.get("decided").and_then(|v| v.as_bool()), Some(true));
    operator.close().await;
}
