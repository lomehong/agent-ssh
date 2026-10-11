//! RPC 客户端（T-17.5a 骨架）：\n 分帧 + hello 握手 + id 关联 + ping。
//!
//! 与 TS 侧对齐的常量：帧上限 4MB（D12，进出同值）、协议版本 0.2.0。
//! 契约样本消费见 tests/golden.rs（K6：TS 生成、Rust 消费）。
//! 断线即 ConnectionClosed——重连由调用方按指数退避驱动（骨架阶段不做
//! 内部自动重连；自动重连在 T-17.5b 与 UI/托盘一起落地）。

use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tokio::sync::{oneshot, Mutex};

/// 单帧上限：4MB，进出同值（D12）。与 TS 侧 RPC_FRAME_LIMIT_BYTES 一致。
pub const RPC_FRAME_LIMIT_BYTES: usize = 4 * 1024 * 1024;

/// 协议版本（与 TS 侧 RPC_PROTOCOL_VERSION 一致）。
pub const RPC_PROTOCOL_VERSION: &str = "0.2.0";

#[derive(Debug, Clone)]
pub enum RpcError {
    /// 帧超限（对端发来 >4MB 的行）——必须断连。
    FrameTooLarge(usize),
    /// 对端发来的行不是合法 JSON。
    ParseError,
    /// 对端以 JSON-RPC error 应答。
    ServerError { code: i64, message: String },
    /// 连接已关闭。
    ConnectionClosed,
    /// io 错误透传。
    Io(String),
}

impl std::fmt::Display for RpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RpcError::FrameTooLarge(n) => {
                write!(f, "frame of {n} bytes exceeds the {RPC_FRAME_LIMIT_BYTES}-byte frame limit")
            }
            RpcError::ParseError => write!(f, "parse error: frame is not valid JSON"),
            RpcError::ServerError { code, message } => write!(f, "RPC error {code}: {message}"),
            RpcError::ConnectionClosed => write!(f, "RPC connection closed"),
            RpcError::Io(e) => write!(f, "io error: {e}"),
        }
    }
}

impl std::error::Error for RpcError {}

/// 编码一帧（`\n` 结尾）。序列化后超限返回 None（调用方视为不可投递）。
pub fn encode_frame(value: &Value) -> Option<String> {
    let text = serde_json::to_string(value).ok()?;
    if text.len() > RPC_FRAME_LIMIT_BYTES {
        return None;
    }
    Some(text + "\n")
}

/// 读一行帧（上限 4MB，按字节计）。返回 (JSON 值, 字节数)。
async fn read_frame_line(reader: &mut BufReader<OwnedReadHalf>) -> Result<(Value, usize), RpcError> {
    let mut line = String::new();
    let mut bytes = 0usize;
    loop {
        let chunk = reader.fill_buf().await.map_err(|e| RpcError::Io(e.to_string()))?;
        if chunk.is_empty() {
            return Err(RpcError::ConnectionClosed);
        }
        if let Some(pos) = chunk.iter().position(|&b| b == b'\n') {
            let tail = &chunk[..pos];
            bytes += tail.len();
            line.push_str(&String::from_utf8_lossy(tail));
            reader.consume(pos + 1);
            if bytes > RPC_FRAME_LIMIT_BYTES {
                return Err(RpcError::FrameTooLarge(bytes));
            }
            let value: Value =
                serde_json::from_str(line.trim_end_matches('\r')).map_err(|_| RpcError::ParseError)?;
            return Ok((value, bytes));
        }
        bytes += chunk.len();
        line.push_str(&String::from_utf8_lossy(chunk));
        let len = chunk.len();
        reader.consume(len);
        if bytes > RPC_FRAME_LIMIT_BYTES {
            return Err(RpcError::FrameTooLarge(bytes));
        }
    }
}

type PendingMap = Arc<Mutex<HashMap<i64, oneshot::Sender<Result<Value, RpcError>>>>>;

/// RPC 客户端：连接→hello→按 id 关联的请求/应答。
/// 断线即 ConnectionClosed（重连由调用方按指数退避驱动；骨架阶段不做
/// 内部自动重连）。
pub struct RpcClient {
    agent_token: Option<String>,
    pending: PendingMap,
    writer: Mutex<OwnedWriteHalf>,
    next_id: Mutex<i64>,
    read_task: tokio::task::JoinHandle<()>,
}

impl RpcClient {
    pub async fn connect(addr: &str, token: &str) -> RpcClient {
        Self::connect_with_version(addr, token, RPC_PROTOCOL_VERSION).await
    }

    pub async fn connect_with_version(addr: &str, token: &str, protocol_version: &str) -> RpcClient {
        let stream = TcpStream::connect(addr)
            .await
            .unwrap_or_else(|e| panic!("tcp connect {addr}: {e}"));
        let (read_half, write_half) = stream.into_split();
        let pending: PendingMap = Arc::new(Mutex::new(HashMap::new()));

        // 读循环：帧→JSON；response（有 id 且带 result/error）→ 唤醒 pending；
        // 通知（无 id）在 T-17.5b 审批推送接线；致命错误→drain pending 并终止
        // 读循环（断线由调用方按退避重连）。
        let pending_for_reader = pending.clone();
        let read_task = tokio::spawn(async move {
            let mut reader = BufReader::new(read_half);
            loop {
                match read_frame_line(&mut reader).await {
                    Ok((value, _bytes)) => {
                        let id = value.get("id").and_then(|v| v.as_i64());
                        let is_response =
                            id.is_some() && (value.get("result").is_some() || value.get("error").is_some());
                        if let (Some(id), true) = (id, is_response) {
                            if let Some(pending_value) = {
                                let mut map = pending_for_reader.lock().await;
                                map.remove(&id)
                            } {
                                if let Some(e) = value.get("error") {
                                    let code = e.get("code").and_then(|v| v.as_i64()).unwrap_or(-32603);
                                    let message = e
                                        .get("message")
                                        .and_then(|v| v.as_str())
                                        .unwrap_or("unknown")
                                        .to_string();
                                    let _ = pending_value
                                        .send(Err(RpcError::ServerError { code, message }));
                                } else {
                                    let _ = pending_value
                                        .send(Ok(value.get("result").cloned().unwrap_or(Value::Null)));
                                }
                            }
                            continue;
                        }
                        // 通知（无 id）：T-17.5b 审批推送接线。
                    }
                    Err(err) => {
                        let mut map = pending_for_reader.lock().await;
                        for (_, pending_value) in map.drain() {
                            let _ = pending_value.send(Err(err.clone()));
                        }
                        break;
                    }
                }
            }
        });

        let client = RpcClient {
            agent_token: Some(token.to_string()),
            pending,
            writer: Mutex::new(write_half),
            next_id: Mutex::new(1),
            read_task,
        };

        // hello 握手：版本不匹配即 panic（骨架语义；正式错误通道在 5b）。
        let result = client
            .call(
                "host.hello",
                serde_json::json!({ "protocolVersion": protocol_version }),
            )
            .await;
        match result {
            Ok(_) => client,
            Err(err) => {
                client.close().await;
                panic!("hello failed: {err}");
            }
        }
    }

    async fn next_request_id(&self) -> i64 {
        let mut id = self.next_id.lock().await;
        let value = *id;
        *id += 1;
        value
    }

    async fn raw_call(&self, method: &str, params: Value) -> Result<Value, RpcError> {
        let id = self.next_request_id().await;
        let mut envelope = serde_json::json!({ "jsonrpc": "2.0", "id": id, "method": method });
        if !params.is_null() {
            envelope["params"] = params;
        }
        if let Some(token) = &self.agent_token {
            envelope["auth"] = Value::String(token.clone());
        }

        let (tx, rx) = oneshot::channel();
        {
            let mut map = self.pending.lock().await;
            map.insert(id, tx);
        }
        let frame = encode_frame(&envelope)
            .ok_or_else(|| RpcError::FrameTooLarge(RPC_FRAME_LIMIT_BYTES + 1))?;
        {
            let mut writer = self.writer.lock().await;
            writer
                .write_all(frame.as_bytes())
                .await
                .map_err(|e| RpcError::Io(e.to_string()))?;
            writer.flush().await.map_err(|e| RpcError::Io(e.to_string()))?;
        }
        rx.await.map_err(|_| RpcError::ConnectionClosed)?
    }

    pub async fn call(&self, method: &str, params: Value) -> Result<Value, RpcError> {
        self.raw_call(method, params).await
    }

    pub async fn ping(&self) -> Result<Value, RpcError> {
        self.call("host.ping", Value::Null).await
    }

    pub async fn close(&self) {
        self.read_task.abort();
    }
}
