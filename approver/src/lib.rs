//! agent-ssh 桌面审批端骨架（T-17.5a）：RPC 客户端 + 契约对拍，无 UI。
//!
//! 模块：`rpc`——\n 分帧（4MB 上限进出同值，D12）、hello 握手、
//! 请求 id 关联、指数退避重连。契约单一事实源在 TS 侧
//! （test/fixtures/rpc/protocol-golden.json），本工程只消费（K6）。

pub mod rpc;
