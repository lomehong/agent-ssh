import { describe, it, expect } from 'vitest';
import { ImBot, type ImBotConfig, type ImBotDeps } from '../../../src/im/bot.js';
import type { CardActionEvent, LarkPort } from '../../../src/im/port.js';
import type { PendingApproval } from '../../../src/guard/approval-queue.js';

// bot 编排（T-17.6）：推送/绑定校验/单次令牌/face='im' 携码 decide/
// settled patch/启动降级/error domain。SDK 以 FakePort 注入——零网络。

class FakePort implements LarkPort {
  sent: { type: string; id: string; card: Record<string, unknown> }[] = [];
  patched: { messageId: string; card: Record<string, unknown> }[] = [];
  cardHandler: ((ev: CardActionEvent) => void) | undefined;
  failStart = false;
  failSend = false;

  async start(onCardAction: (ev: CardActionEvent) => void): Promise<void> {
    if (this.failStart) throw new Error('ws down');
    this.cardHandler = onCardAction;
  }
  async sendCard(type: string, id: string, card: Record<string, unknown>): Promise<string> {
    if (this.failSend) throw new Error('send failed');
    const messageId = `msg-${this.sent.length}`;
    this.sent.push({ type, id, card });
    return messageId;
  }
  async patchCard(messageId: string, card: Record<string, unknown>): Promise<void> {
    this.patched.push({ messageId, card });
  }
}

interface Harness {
  port: FakePort;
  bot: ImBot;
  decides: { id: string; decision: string; by: string; face: string; challenge?: string }[];
  audits: string[];
  logs: string[];
  decideResult: { decided: boolean; message: string };
  decideThrows?: Error;
}

function harness(over: Partial<ImBotConfig> = {}, pendings: PendingApproval[] = []): Harness {
  const port = new FakePort();
  const h: Harness = {
    port,
    bot: undefined!,
    decides: [],
    audits: [],
    logs: [],
    decideResult: { decided: true, message: 'approved' },
  };
  const deps: ImBotDeps = {
    port,
    decide: async (input) => {
      if (h.decideThrows) throw h.decideThrows;
      h.decides.push(input);
      return h.decideResult;
    },
    listPending: async () => pendings,
    auditUnreachable: (ctx) => h.audits.push(ctx),
    log: (line) => h.logs.push(line),
  };
  h.bot = new ImBot(
    { appId: 'cli_x', appSecret: 's', allowedUsers: ['ou_me'], ...over },
    deps,
  );
  return h;
}

const payload = { id: 'req-1', profile: 'prod', command: 'rm -rf /tmp/x', commandClass: 'safe', expiresAt: '2026-10-17T12:00:00Z' };
const pendingOf = (p: typeof payload): PendingApproval => ({
  id: p.id, createdAt: '', expiresAt: p.expiresAt, profile: p.profile,
  command: p.command, commandClass: p.commandClass, binary: 'rm', fingerprint: '', status: 'pending',
});

async function flush(ms = 20): Promise<void> {
  await new Promise((r) => setTimeout(r, ms));
}

describe('im bot 编排', () => {
  it('notifyPending：发卡到私聊 allowedUsers[0]，同请求去重', async () => {
    const h = harness();
    await h.bot.notifyPending(payload);
    await h.bot.notifyPending(payload);
    expect(h.port.sent).toHaveLength(1);
    expect(h.port.sent[0].type).toBe('open_id');
    expect(h.port.sent[0].id).toBe('ou_me');
  });

  it('chatId 配置：发到群', async () => {
    const h = harness({ chatId: 'oc_group' });
    await h.bot.notifyPending(payload);
    expect(h.port.sent[0].type).toBe('chat_id');
    expect(h.port.sent[0].id).toBe('oc_group');
  });

  it('卡片点击（绑定用户+有效令牌）→ face=im decide；令牌单次', async () => {
    const h = harness();
    await h.bot.start();
    await h.bot.notifyPending(payload);
    const value = extractTokenValue(h, 0, 'approved');
    h.port.cardHandler!({ operatorOpenId: 'ou_me', value });
    await flush();
    expect(h.decides).toHaveLength(1);
    expect(h.decides[0]).toMatchObject({ id: 'req-1', decision: 'approved', by: 'im:ou_me', face: 'im' });
    // 重复点击（令牌已消费）：拒绝
    h.port.cardHandler!({ operatorOpenId: 'ou_me', value });
    await flush();
    expect(h.decides).toHaveLength(1);
  });

  it('非绑定用户点击：拒绝且留痕（K8-⑤）', async () => {
    const h = harness();
    await h.bot.start();
    await h.bot.notifyPending(payload);
    const value = extractTokenValue(h, 0, 'rejected');
    h.port.cardHandler!({ operatorOpenId: 'ou_stranger', value });
    await flush();
    expect(h.decides).toHaveLength(0);
    expect(h.audits.some((a) => a.includes('forbidden-clicker'))).toBe(true);
  });

  it('破坏性类：回调携带输入的校验码透传 decide（Host 侧校验）', async () => {
    const h = harness();
    await h.bot.start();
    await h.bot.notifyPending({ ...payload, commandClass: 'destructive' }, '4321');
    const value = { ...extractTokenValue(h, 0, 'approved'), challenge: '4321' };
    h.port.cardHandler!({ operatorOpenId: 'ou_me', value });
    await flush();
    expect(h.decides[0].challenge).toBe('4321');
    expect(h.decides[0].face).toBe('im');
  });

  it('settled：patch 卡片为已决态（他面决定同样触发）', async () => {
    const h = harness();
    await h.bot.notifyPending(payload);
    await h.bot.settled('req-1', 'approved', 'desktop:lome');
    expect(h.port.patched).toHaveLength(1);
    expect(JSON.stringify(h.port.patched[0].card)).toContain('desktop:lome');
    expect(JSON.stringify(h.port.patched[0].card)).toContain('已批准');
  });

  it('启动失败降级：审计 ws-start，不抛出（K5）', async () => {
    const h = harness();
    h.port.failStart = true;
    await h.bot.start(); // 不应 reject
    expect(h.audits.some((a) => a === 'ws-start')).toBe(true);
  });

  it('启动补偿：存量 pending 补发卡片（K5）', async () => {
    const h = harness({}, [pendingOf(payload)]);
    await h.bot.start();
    expect(h.port.sent.length).toBeGreaterThanOrEqual(1);
    expect(h.port.sent[0].card && JSON.stringify(h.port.sent[0].card)).toContain('req-1');
  });

  it('error domain：decide 抛错被就地消化，审计 card-action', async () => {
    const h = harness();
    await h.bot.start();
    h.decideThrows = new Error('queue gone');
    await h.bot.notifyPending(payload);
    h.port.cardHandler!({ operatorOpenId: 'ou_me', value: extractTokenValue(h, 0, 'approved') });
    await flush();
    expect(h.audits.some((a) => a === 'card-action')).toBe(true);
  });

  it('发送失败：审计 im.unreachable + 令牌收回', async () => {
    const h = harness();
    h.port.failSend = true;
    await h.bot.notifyPending(payload);
    expect(h.audits.some((a) => a.includes('push req-1'))).toBe(true);
    // 令牌已收回：即使后续卡到达也无法消费
    expect(h.port.sent).toHaveLength(0);
  });

  it('allowedUsers 为空：构造即拒（配置面兜底）', () => {
    expect(() => harness({ allowedUsers: [] })).toThrow(/allowedUsers/);
  });
});

function extractTokenValue(h: Harness, index: number, decision: 'approved' | 'rejected'): Record<string, unknown> {
  const card = h.port.sent[index].card as { elements: unknown[] };
  const json = JSON.stringify(card);
  const token = /"t":"([^"]+)"/.exec(json)?.[1] ?? '';
  const id = /"id":"(req-[^"]+)"/.exec(json)?.[1] ?? '';
  return { k: 'decide', id, t: token, d: decision };
}
