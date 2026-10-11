//! connect_with_retry 的退避语义：不可达地址在有限次尝试后返回最后错误。

use approver::rpc::RpcClient;

#[tokio::test]
async fn unreachable_host_exhausts_attempts_and_returns_error() {
    // 127.0.0.1:1 保留端口，几乎必然 ECONNREFUSED。
    let started = std::time::Instant::now();
    let result = RpcClient::connect_with_retry("127.0.0.1:1", "tok", 3).await;
    let elapsed = started.elapsed();
    assert!(result.is_err(), "unreachable host must not connect");
    // 三次尝试=两次退避等待（1s+2s），至少 3s——证明真的退避而非空转。
    assert!(elapsed.as_millis() >= 2_800, "expected backoff waits, got {elapsed:?}");
}
