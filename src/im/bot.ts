/**
 * 飞书审批 bot 编排（T-17.6，方案 §4.2）。
 *
 * 职责链：入队 → notifyPending（发卡，签发单次决策令牌）→ 人点按钮 →
 * onCardAction（绑定校验 + 令牌消费 + face='im' 携码 decide）→ settled
 * （任意面决定后 patch 卡片，D11 跨面仲裁可见）。启动后 listPending 补偿
 * ——重启窗口期的未决请求不静默丢失（K5）。
 *
 * 独立 error domain（K5）：port 回调与发送异常全部就地吞掉并审计
 * im.unreachable，绝不冒泡进 Host 事件循环；WS 启动失败同样降级——
 * 审批等待与 CLI 队列兜底不受影响。
 */
import type { PendingApproval } from '../guard/approval-queue.js';
import { buildPendingCard, buildSettledCard, type PendingCardInput } from './cards.js';
import { DecisionTokenStore } from './decision-tokens.js';
import type { LarkPort } from './port.js';

export interface ImBotConfig {
  appId: string;
  appSecret: string;
  /** open_id 绑定表：卡片点击者必须在内（群聊转发场景的硬门，K8-⑤）。 */
  allowedUsers: string[];
  /** 推送目标；缺省私聊 allowedUsers[0]。 */
  chatId?: string;
  /** full=命令全文（默认）；truncated=截断+redactor 脱敏。 */
  commandDetail?: 'full' | 'truncated';
}

export interface ImBotDeps {
  port: LarkPort;
  /** Host 进程内 decide 核心（face 固定 'im'，破坏性类强制校验码）。 */
  decide(input: { id: string; decision: 'approved' | 'rejected'; by: string; face: 'im'; challenge?: string }): Promise<{ decided: boolean; message: string }>;
  listPending(): Promise<PendingApproval[]>;
  /** K5 失效语义：审计 im.unreachable。 */
  auditUnreachable(context: string, err: unknown): void;
  log(line: string): void;
}

export class ImBot {
  private readonly tokens = new DecisionTokenStore();
  /** approvalId → 已发卡片（messageId + 构建输入），settled 时 patch 用。 */
  private readonly cards = new Map<string, { messageId: string; input: PendingCardInput }>();
  private readonly announced = new Set<string>();
  private started = false;

  constructor(private readonly cfg: ImBotConfig, private readonly deps: ImBotDeps) {
    if (cfg.allowedUsers.length === 0) throw new Error('ImBot requires at least one allowedUsers open_id');
  }

  /** 异步非阻塞启动：WS 失败降级（审计+日志），随后补偿推送存量未决。 */
  async start(): Promise<void> {
    try {
      await this.deps.port.start(
        (ev) => this.onCardAction(ev),
        (ev) => {
          // 主人给 bot 发消息 → 打出 open_id（填 allowedUsers 的引导路径）。
          if (ev.senderOpenId) this.deps.log(`im.message from open_id=${ev.senderOpenId}${ev.chatId ? ` chat_id=${ev.chatId}` : ''}`);
        },
      );
      this.started = true;
      this.deps.log('im bot connected (long-connection outbound)');
    } catch (err) {
      this.deps.auditUnreachable('ws-start', err);
      this.deps.log(`im.unreachable ws-start: ${err instanceof Error ? err.message : String(err)}`);
    }
    // 补偿（K5）：重启窗口期的未决请求补发卡片（发送失败逐条降级，不中断）。
    try {
      for (const p of await this.deps.listPending()) {
        await this.notifyPending(p, undefined);
      }
    } catch (err) {
      this.deps.auditUnreachable('compensate', err);
    }
  }

  /** 入队推送（main.onApprovalQueued 直调；challenge 由 Host 生成随 payload）。 */
  async notifyPending(
    payload: { id: string; profile: string; command: string; commandClass: string; expiresAt: string },
    challenge?: string,
  ): Promise<void> {
    if (this.announced.has(payload.id)) return;
    const input: PendingCardInput = {
      id: payload.id,
      profile: payload.profile,
      command: payload.command,
      commandClass: payload.commandClass,
      expiresAt: payload.expiresAt,
      decisionToken: this.tokens.issue(payload.id),
      ...(challenge !== undefined ? { challenge } : {}),
      ...(this.cfg.commandDetail !== undefined ? { commandDetail: this.cfg.commandDetail } : {}),
    };
    try {
      const receiveIdType: 'open_id' | 'chat_id' = this.cfg.chatId !== undefined ? 'chat_id' : 'open_id';
      const receiveId = this.cfg.chatId ?? this.cfg.allowedUsers[0];
      const messageId = await this.deps.port.sendCard(receiveIdType, receiveId, buildPendingCard(input));
      this.cards.set(payload.id, { messageId, input });
      this.announced.add(payload.id);
    } catch (err) {
      this.deps.auditUnreachable(`push ${payload.id}`, err);
      this.deps.log(`im.unreachable push ${payload.id}: ${err instanceof Error ? err.message : String(err)}`);
      this.tokens.revokeFor(payload.id);
    }
  }

  /** 任意面决定后的卡片收尾（D11：「已在桌面端/CLI 批准」）。 */
  async settled(id: string, decision: 'approved' | 'rejected', by: string): Promise<void> {
    this.tokens.revokeFor(id);
    const entry = this.cards.get(id);
    if (entry === undefined) return;
    this.cards.delete(id);
    try {
      await this.deps.port.patchCard(entry.messageId, buildSettledCard(entry.input, { decision, by }));
    } catch (err) {
      this.deps.auditUnreachable(`settled ${id}`, err);
    }
  }

  private onCardAction(ev: { operatorOpenId?: string; value?: Record<string, unknown> }): void {
    // error domain：回调内一切异常就地消化，不冒泡进 SDK/Host。
    void (async () => {
      try {
        const v = ev.value ?? {};
        if (v.k !== 'decide' || typeof v.id !== 'string' || typeof v.t !== 'string' || (v.d !== 'approved' && v.d !== 'rejected')) {
          this.deps.log('im card action ignored: malformed value');
          return;
        }
        // 绑定校验（K8-⑤）：群聊/转发场景，非绑定用户点击一律拒绝并留痕。
        const openId = ev.operatorOpenId ?? '';
        if (!this.cfg.allowedUsers.includes(openId)) {
          this.deps.auditUnreachable(`forbidden-clicker ${v.id} open_id=${openId.slice(0, 12)}…`, new Error('card action from non-bound user'));
          this.deps.log(`im card action rejected: open_id not in allowedUsers (request ${v.id})`);
          return;
        }
        // 单次决策令牌（A8）：消费制，跨请求/重放必拒。
        if (!this.tokens.consume(v.t, v.id)) {
          this.deps.log(`im card action rejected: decision token invalid or already used (request ${v.id})`);
          return;
        }
        const challenge = typeof v.challenge === 'string' ? v.challenge : undefined;
        const outcome = await this.deps.decide({
          id: v.id,
          decision: v.d,
          by: `im:${openId}`,
          face: 'im',
          ...(challenge !== undefined ? { challenge } : {}),
        });
        this.deps.log(`im decide ${v.id} → ${v.d}: ${outcome.message}`);
      } catch (err) {
        this.deps.auditUnreachable('card-action', err);
        this.deps.log(`im card action error: ${err instanceof Error ? err.message : String(err)}`);
      }
    })();
  }

  get connected(): boolean {
    return this.started;
  }
}
