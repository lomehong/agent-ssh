//! approver 进程入口（T-17.5a 骨架）：smoke 用——连 Host、hello、ping。
//! UI 与常驻逻辑在 T-17.5b/c 落地。

use approver::rpc::RpcClient;

#[tokio::main]
async fn main() {
    let addr = std::env::var("AGENT_SSH_HOST_ADDR").unwrap_or_else(|_| "127.0.0.1:9443".to_string());
    let token = std::env::var("AGENT_SSH_TOKEN").unwrap_or_default();
    let mut client = RpcClient::connect(&addr, &token).await;
    let pong = client.ping().await;
    println!("host.ping → {:?}", pong);
    client.close().await;
}
