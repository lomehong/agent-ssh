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

/// 审批推送回调：收到的通知帧（approval.pending/settled 完整信封）。
pub type NotificationHandler = Arc<dyn Fn(Value) + Send + Sync>;

/// RPC 客户端：连接→hello→按 id 关联的请求/应答。
/// 断线即 ConnectionClosed（重连由调用方按指数退避驱动；骨架阶段不做
/// 内部自动重连）。
pub struct RpcClient {
    /// K8-⑦：Zeroizing 包裹——drop 时清零内存；clone 共享堆仍由最后持有者清零。
    agent_token: Option<zeroize::Zeroizing<String>>,
    pending: PendingMap,
    writer: Mutex<OwnedWriteHalf>,
    next_id: Mutex<i64>,
    read_task: tokio::task::JoinHandle<()>,
    notification_handler: Arc<Mutex<Option<NotificationHandler>>>,
}

impl RpcClient {
    pub async fn connect(addr: &str, token: &str) -> RpcClient {
        Self::connect_with_version(addr, token, RPC_PROTOCOL_VERSION).await
    }

    /// 指数退避重连（1s 起步逐次翻倍，封顶 30s）：Host 暂不可达时按
    /// §3.5 退避重试，max_attempts 次全败后返回最后一次错误。
    pub async fn connect_with_retry(
        addr: &str,
        token: &str,
        max_attempts: u32,
    ) -> Result<RpcClient, RpcError> {
        let mut attempt = 0u32;
        loop {
            // 直接调用底层拨号+握手：握手 panic 语义在此路径外不适用，
            // 拨号失败退避重试，握手失败（版本不匹配）立即返回。
            match tokio::net::TcpStream::connect(addr).await {
                Ok(stream) => {
                    return Ok(Self::from_stream_and_handshake(stream, token, RPC_PROTOCOL_VERSION).await);
                }
                Err(e) => {
                    attempt += 1;
                    if attempt >= max_attempts {
                        return Err(RpcError::Io(e.to_string()));
                    }
                    let delay = std::cmp::min(1_000u64 << (attempt - 1).min(16), 30_000);
                    tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
                }
            }
        }
    }

    pub async fn connect_with_version(addr: &str, token: &str, protocol_version: &str) -> RpcClient {
        let stream = TcpStream::connect(addr)
            .await
            .unwrap_or_else(|e| panic!("tcp connect {addr}: {e}"));
        Self::from_stream_and_handshake(stream, token, protocol_version).await
    }

    /// operator 引导变体：跳过 hello（无凭据面先 auth.session.start 换会话——
    /// hello 需有效凭据，start 是 pre-auth 方法）。
    pub async fn connect_skip_hello(addr: &str) -> RpcClient {
        let stream = TcpStream::connect(addr)
            .await
            .unwrap_or_else(|e| panic!("tcp connect {addr}: {e}"));
        Self::from_stream_and_handshake_no_hello(stream).await
    }

    async fn from_stream_and_handshake(
        stream: TcpStream,
        token: &str,
        protocol_version: &str,
    ) -> RpcClient {
        let (read_half, write_half) = stream.into_split();
        let pending: PendingMap = Arc::new(Mutex::new(HashMap::new()));
        let notification_handler: Arc<Mutex<Option<NotificationHandler>>> = Arc::new(Mutex::new(None));

        // 读循环：帧→JSON；response（有 id 且带 result/error）→ 唤醒 pending；
        // 通知（无 id）→ 审批推送回调；致命错误→drain pending 并终止
        // 读循环（断线由调用方按退避重连）。
        let pending_for_reader = pending.clone();
        let notification_for_reader = notification_handler.clone();
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
                        // 通知（无 id）：审批推送（approval.pending/settled）。
                        if let Some(method) = value.get("method").and_then(|v| v.as_str()) {
                            if method == "approval.pending" || method == "approval.settled" {
                                let handler = notification_for_reader.lock().await.clone();
                                if let Some(handler) = handler {
                                    handler(value.clone());
                                }
                            }
                            continue;
                        }
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
            agent_token: Some(zeroize::Zeroizing::new(token.to_string())),
            pending,
            writer: Mutex::new(write_half),
            next_id: Mutex::new(1),
            read_task,
            notification_handler,
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

    /// 无凭据引导构造：跳过 hello（start 为 pre-auth），令牌缺省 None。
    async fn from_stream_and_handshake_no_hello(stream: TcpStream) -> RpcClient {
        let (read_half, write_half) = stream.into_split();
        let pending: PendingMap = Arc::new(Mutex::new(HashMap::new()));
        let notification_handler: Arc<Mutex<Option<NotificationHandler>>> = Arc::new(Mutex::new(None));

        let pending_for_reader = pending.clone();
        let notification_for_reader = notification_handler.clone();
        let read_task = tokio::spawn(async move {
            let mut reader = BufReader::new(read_half);
            loop {
                match read_frame_line(&mut reader).await {
                    Ok((value, _bytes)) => {
                        let is_response = value.get("id").is_some()
                            && (value.get("result").is_some() || value.get("error").is_some());
                        if is_response {
                            let numeric_id = value.get("id").and_then(|v| v.as_i64()).unwrap_or(-1);
                            if let Some(pending_value) = {
                                let mut map = pending_for_reader.lock().await;
                                map.remove(&numeric_id)
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
                        // 通知（无 id）：与 hello 版读循环同分发（skipHello 引导
                        // 连接也可能在 start 前收到订阅推送——5c 收拢双循环）。
                        if let Some(method) = value.get("method").and_then(|v| v.as_str()) {
                            if method == "approval.pending" || method == "approval.settled" {
                                let handler = notification_for_reader.lock().await.clone();
                                if let Some(handler) = handler {
                                    handler(value.clone());
                                }
                            }
                            continue;
                        }
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

        RpcClient {
            agent_token: None,
            pending,
            writer: Mutex::new(write_half),
            next_id: Mutex::new(1),
            read_task,
            notification_handler,
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
            envelope["auth"] = Value::String(token.to_string());
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

    /// 注册审批推送回调（approval.pending/settled 通知帧）。重复注册替换。
    pub async fn set_notification_handler(&self, handler: NotificationHandler) {
        *self.notification_handler.lock().await = Some(handler);
    }

    /// approval.subscribe：向 Host 订阅审批推送。
    pub async fn subscribe_approvals(&self) -> Result<Value, RpcError> {
        self.call("approval.subscribe", Value::Null).await
    }

    /// approval.decide：携可选校验码提交决定（D10/K8-②）。
    pub async fn decide_approval(
        &self,
        id: &str,
        decision: &str,
        by: &str,
        challenge: Option<&str>,
    ) -> Result<Value, RpcError> {
        let mut params = serde_json::json!({ "id": id, "decision": decision, "by": by });
        if let Some(code) = challenge {
            params["challenge"] = Value::String(code.to_string());
        }
        self.call("approval.decide", params).await
    }

    pub async fn close(&self) {
        self.read_task.abort();
    }
}
