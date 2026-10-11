/**
 * 审批推送分发（T-14，方案 §3.3 approval.subscribe + §2.2 双推送 D11）。
 *
 * 每连接可多路订阅（多窗/多面）；断连时服务层调 dropAll 清理。
 * 扇出顺序即订阅序，不做跨连接排序承诺；payload 原样透传（序列化
 * 由帧层在各自连接上完成——大响应与推送交织的隔离由 T-18b 用例钉）。
 */

export type ApprovalChannel = 'approval.pending' | 'approval.settled';

export interface PushEvent {
  channel: ApprovalChannel;
  payload: unknown;
}

export class PushHub {
  private readonly subs = new Map<string, Set<(event: PushEvent) => void>>();

  /** 订阅；返回退订函数（幂等）。 */
  subscribe(connId: string, send: (event: PushEvent) => void): () => void {
    let set = this.subs.get(connId);
    if (set === undefined) {
      set = new Set();
      this.subs.set(connId, set);
    }
    set.add(send);
    return () => {
      set.delete(send);
    };
  }

  /** 扇出；返回实际投递数（无订阅者即 0，审批不静默丢失由队列兜底语义保证）。 */
  publish(channel: ApprovalChannel, payload: unknown): number {
    let delivered = 0;
    for (const set of this.subs.values()) {
      for (const send of set) {
        send({ channel, payload });
        delivered++;
      }
    }
    return delivered;
  }

  /** 连接断开：清理该连接全部订阅。 */
  dropAll(connId: string): void {
    this.subs.delete(connId);
  }
}
